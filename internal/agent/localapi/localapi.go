// Package localapi is the agent's API for workload runtimes on its host,
// served over a unix socket: attach a workload, detach it, list what the
// agent holds.
package localapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"sdn.sh/internal/agent/daemon"
	"sdn.sh/internal/api"
	"sdn.sh/internal/model"
)

// Agent is what the API serves.
type Agent interface {
	Attach(context.Context, api.LocalAttach) (api.LocalInterface, error)
	Detach(context.Context, model.InterfaceID) (api.LocalInterface, error)
	Interfaces(context.Context) ([]api.LocalInterface, error)
	Status(context.Context) (daemon.Status, error)
}

// Handler serves the API.
func Handler(a Agent) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/attach", func(w http.ResponseWriter, r *http.Request) {
		var req api.LocalAttach
		if !decode(w, r, &req) {
			return
		}
		out, err := a.Attach(r.Context(), req)
		respond(w, out, err)
	})
	mux.HandleFunc("POST /v1/detach", func(w http.ResponseWriter, r *http.Request) {
		var req api.LocalDetach
		if !decode(w, r, &req) {
			return
		}
		out, err := a.Detach(r.Context(), req.Interface)
		respond(w, out, err)
	})
	mux.HandleFunc("GET /v1/interfaces", func(w http.ResponseWriter, r *http.Request) {
		out, err := a.Interfaces(r.Context())
		respond(w, out, err)
	})
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, r *http.Request) {
		out, err := a.Status(r.Context())
		respond(w, out, err)
	})
	return mux
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		respond(w, nil, &api.Error{Code: api.CodeInvalid, Message: "body: " + err.Error()})
		return false
	}
	return true
}

func respond(w http.ResponseWriter, out any, err error) {
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		var ae *api.Error
		if !errors.As(err, &ae) {
			ae = &api.Error{Code: "failed", Message: err.Error()}
		}
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ae)
		return
	}
	json.NewEncoder(w).Encode(out)
}

// Serve listens on a unix socket, replacing a stale one, and serves until
// ctx ends. Only root and the socket's group may connect.
func Serve(ctx context.Context, path string, a Agent) error {
	os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	if err := os.Chmod(path, 0o660); err != nil {
		ln.Close()
		return err
	}
	srv := &http.Server{Handler: Handler(a), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		srv.Close()
	}()
	if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// Client calls an agent's local API.
type Client struct {
	http *http.Client
}

// NewClient returns a client for the agent listening on path.
func NewClient(path string) *Client {
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", path)
	}}
	return &Client{http: &http.Client{Transport: tr}}
}

func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://agent"+path, body)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		var ae api.Error
		if json.Unmarshal(b, &ae) == nil && ae.Code != "" {
			return &ae
		}
		return fmt.Errorf("%s %s: %s", method, path, resp.Status)
	}
	return json.Unmarshal(b, out)
}

// Attach asks the agent for an interface.
func (c *Client) Attach(ctx context.Context, req api.LocalAttach) (api.LocalInterface, error) {
	var out api.LocalInterface
	err := c.do(ctx, "POST", "/v1/attach", req, &out)
	return out, err
}

// Detach tears an interface down.
func (c *Client) Detach(ctx context.Context, id model.InterfaceID) (api.LocalInterface, error) {
	var out api.LocalInterface
	err := c.do(ctx, "POST", "/v1/detach", api.LocalDetach{Interface: id}, &out)
	return out, err
}

// Interfaces lists what the agent holds.
func (c *Client) Interfaces(ctx context.Context) ([]api.LocalInterface, error) {
	var out []api.LocalInterface
	err := c.do(ctx, "GET", "/v1/interfaces", nil, &out)
	return out, err
}

// Status reports the agent's state.
func (c *Client) Status(ctx context.Context) (daemon.Status, error) {
	var out daemon.Status
	err := c.do(ctx, "GET", "/v1/status", nil, &out)
	return out, err
}
