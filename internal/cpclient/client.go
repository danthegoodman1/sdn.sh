// Package cpclient calls the control plane's HTTP API: the operator's
// resources, an agent's attach, release, renew and long poll, and a relay's
// long poll.
package cpclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"sdn.sh/internal/api"
	"sdn.sh/internal/model"
)

// Client is one principal's connection to the control plane.
type Client struct {
	base    string
	token   string
	http    *http.Client
	timeout time.Duration
}

// Options configure a client.
type Options struct {
	// CAFile, when set, is the only authority the client trusts.
	CAFile string
	// Timeout bounds a call that is not a long poll.
	Timeout time.Duration
}

// New returns a client for the control plane at base, authenticating with
// token.
func New(base, token string, opts Options) (*Client, error) {
	if _, err := url.Parse(base); err != nil {
		return nil, err
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.MaxIdleConnsPerHost = 16
	if opts.CAFile != "" {
		pem, err := os.ReadFile(opts.CAFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%s holds no certificate", opts.CAFile)
		}
		tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	if opts.Timeout == 0 {
		opts.Timeout = 10 * time.Second
	}
	return &Client{base: strings.TrimRight(base, "/"), token: token, http: &http.Client{Transport: tr}, timeout: opts.Timeout}, nil
}

// ErrUnavailable wraps a failure to reach the control plane at all, as
// against an answer refusing the call.
var ErrUnavailable = errors.New("control plane unavailable")

func (c *Client) do(ctx context.Context, method, path string, in, out any, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %s %s: %v", ErrUnavailable, method, path, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return fmt.Errorf("%w: %s %s: %v", ErrUnavailable, method, path, err)
	}
	if resp.StatusCode != http.StatusOK {
		var ae api.Error
		if json.Unmarshal(b, &ae) != nil || ae.Code == "" {
			ae = api.Error{Code: "http", Message: fmt.Sprintf("%s %s: %s", method, path, resp.Status)}
		}
		// A failure on the server's side is worth retrying; the agent
		// tells retryable answers by their code.
		if ae.Code == api.CodeUnavailable || resp.StatusCode >= 500 {
			return fmt.Errorf("%w: %w", ErrUnavailable, &api.Error{Code: api.CodeUnavailable, Message: ae.Message})
		}
		return &ae
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(b, out); err != nil {
		return fmt.Errorf("%s %s: decoding answer: %w", method, path, err)
	}
	return nil
}

func call[T any](c *Client, ctx context.Context, method, path string, in any) (T, error) {
	var out T
	err := c.do(ctx, method, path, in, &out, c.timeout)
	return out, err
}

func esc(s string) string { return url.PathEscape(s) }

// The operator's API.

func (c *Client) CreateNetwork(ctx context.Context, req api.CreateNetwork) (api.Network, error) {
	return call[api.Network](c, ctx, "POST", "/v1/networks", req)
}

func (c *Client) Networks(ctx context.Context) ([]api.Network, error) {
	return call[[]api.Network](c, ctx, "GET", "/v1/networks", nil)
}

func (c *Client) Network(ctx context.Context, ref string) (api.Network, error) {
	return call[api.Network](c, ctx, "GET", "/v1/networks/"+esc(ref), nil)
}

func (c *Client) DeleteNetwork(ctx context.Context, ref string) error {
	return c.do(ctx, "DELETE", "/v1/networks/"+esc(ref), nil, nil, c.timeout)
}

func (c *Client) CreateService(ctx context.Context, net string, req api.CreateService) (api.ServiceInfo, error) {
	return call[api.ServiceInfo](c, ctx, "POST", "/v1/networks/"+esc(net)+"/services", req)
}

func (c *Client) Services(ctx context.Context, net string) ([]api.ServiceInfo, error) {
	return call[[]api.ServiceInfo](c, ctx, "GET", "/v1/networks/"+esc(net)+"/services", nil)
}

func (c *Client) DeleteService(ctx context.Context, net, svc string) error {
	return c.do(ctx, "DELETE", "/v1/networks/"+esc(net)+"/services/"+esc(svc), nil, nil, c.timeout)
}

func (c *Client) CreateRule(ctx context.Context, net string, req api.CreateRule) (api.Rule, error) {
	return call[api.Rule](c, ctx, "POST", "/v1/networks/"+esc(net)+"/rules", req)
}

func (c *Client) Rules(ctx context.Context, net string) ([]api.Rule, error) {
	return call[[]api.Rule](c, ctx, "GET", "/v1/networks/"+esc(net)+"/rules", nil)
}

func (c *Client) DeleteRule(ctx context.Context, net string, id model.RuleID) error {
	return c.do(ctx, "DELETE", "/v1/networks/"+esc(net)+"/rules/"+esc(string(id)), nil, nil, c.timeout)
}

func (c *Client) Interfaces(ctx context.Context, net string) ([]api.InterfaceInfo, error) {
	return call[[]api.InterfaceInfo](c, ctx, "GET", "/v1/networks/"+esc(net)+"/interfaces", nil)
}

// CreateDevice registers a development machine behind a gateway; the
// caller keeps the private key.
func (c *Client) CreateDevice(ctx context.Context, net string, req api.CreateDevice) (api.DeviceConfig, error) {
	return call[api.DeviceConfig](c, ctx, "POST", "/v1/networks/"+esc(net)+"/devices", req)
}

func (c *Client) Revoke(ctx context.Context, id model.InterfaceID) error {
	return c.do(ctx, "POST", "/v1/interfaces/"+esc(string(id))+"/revoke", nil, nil, c.timeout)
}

func (c *Client) CreateHost(ctx context.Context, req api.CreateHost) (api.Credentials, error) {
	return call[api.Credentials](c, ctx, "POST", "/v1/hosts", req)
}

// DeleteHost revokes a host's interfaces and deletes the host, by name or
// identifier.
func (c *Client) DeleteHost(ctx context.Context, ref string) error {
	return c.do(ctx, "DELETE", "/v1/hosts/"+esc(ref), nil, nil, c.timeout)
}

func (c *Client) CreateRelay(ctx context.Context, req api.CreateRelay) (api.Credentials, error) {
	return call[api.Credentials](c, ctx, "POST", "/v1/relays", req)
}

func (c *Client) Relays(ctx context.Context) ([]api.RelayInfo, error) {
	return call[[]api.RelayInfo](c, ctx, "GET", "/v1/relays", nil)
}

// DeleteRelay deletes a relay no network names, by name or identifier.
func (c *Client) DeleteRelay(ctx context.Context, ref string) error {
	return c.do(ctx, "DELETE", "/v1/relays/"+esc(ref), nil, nil, c.timeout)
}

// An agent's API.

func (c *Client) Attach(ctx context.Context, req api.AttachRequest) (*api.AttachResponse, error) {
	resp, err := call[api.AttachResponse](c, ctx, "POST", "/v1/agent/attach", req)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) Release(ctx context.Context, ids []model.InterfaceID) error {
	return c.do(ctx, "POST", "/v1/agent/release", api.ReleaseRequest{Interfaces: ids}, nil, c.timeout)
}

func (c *Client) Renew(ctx context.Context, ids []model.InterfaceID) (api.RenewResponse, error) {
	return call[api.RenewResponse](c, ctx, "POST", "/v1/agent/renew", api.RenewRequest{Interfaces: ids})
}

// HostState long-polls for desired state newer than since. wait bounds the
// whole call and should exceed the server's poll timeout.
func (c *Client) HostState(ctx context.Context, since uint64, wait time.Duration) (api.StateUpdate, error) {
	var u api.StateUpdate
	err := c.do(ctx, "GET", "/v1/agent/state?since="+strconv.FormatUint(since, 10), nil, &u, wait)
	return u, err
}

// A relay's API.

// RelayState long-polls for a port table newer than since.
func (c *Client) RelayState(ctx context.Context, since uint64, wait time.Duration) (api.RelayState, error) {
	var st api.RelayState
	err := c.do(ctx, "GET", "/v1/relay/state?since="+strconv.FormatUint(since, 10), nil, &st, wait)
	return st, err
}
