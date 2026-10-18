// Command sdn-lab runs named benchmark plans against a fleet and writes a
// report per plan, ready to copy into SPEC.md.
//
//	sdn-lab plans
//	sdn-lab run --env local --plan paths --duration 3s         (as root)
//	sdn-lab run --env aws --tf-output fleet.json --ssh-key KEY --plan all
//	sdn-lab deploy --tf-output fleet.json --ssh-key KEY [--dry-run]
//	sdn-lab purge --tf-output fleet.json --ssh-key KEY
//	sdn-lab monitoring --tf-output fleet.json --out DIR
//
// The local environment builds the fleet as namespaces on this machine
// with internal/lab and the real daemons. The aws environment reads
// `terraform output -json` from deploy/aws/terraform and drives the
// instances over ssh; --dry-run prints every remote command instead of
// running it. Each plan starts from a fresh fleet and purges it after.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

func main() {
	if err := cli(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "sdn-lab:", err)
		os.Exit(1)
	}
}

func usage() error {
	return errors.New("usage: sdn-lab plans | run | deploy | purge | monitoring; see the package documentation")
}

// envFlags are the flags every command that reaches a fleet takes.
type envFlags struct {
	env, bin, tfOutput, sshKey, store string
	logLevel, keep                    string
	hosts                             int
	dryRun                            bool
}

func (f *envFlags) register(fs *flag.FlagSet) {
	self, _ := os.Executable()
	fs.StringVar(&f.env, "env", "local", "local or aws")
	fs.StringVar(&f.bin, "bin", filepath.Dir(self), "directory holding sdn-cp, sdn-agent, sdn-relay, sdnctl, sdn-bench and hostbench (linux/amd64 for aws)")
	fs.StringVar(&f.tfOutput, "tf-output", "", "aws: a file holding `terraform output -json` from deploy/aws/terraform")
	fs.StringVar(&f.sshKey, "ssh-key", "", "aws: the private key for the fleet's key pair; ssh's default when empty")
	fs.StringVar(&f.store, "store", "memory", `local: the control plane's store, "memory" or a postgres:// URL (each run gets a fresh schema)`)
	fs.IntVar(&f.hosts, "hosts", 3, "local: agent hosts")
	fs.StringVar(&f.logLevel, "log-level", "info", "local: the daemons' log level")
	fs.StringVar(&f.keep, "keep-logs", "", "local: copy the daemons' logs into this directory after each plan")
	fs.BoolVar(&f.dryRun, "dry-run", false, "aws: print every remote command instead of running it")
}

func (f *envFlags) open() (Env, error) {
	switch f.env {
	case "local":
		if f.dryRun {
			return nil, errors.New("--dry-run is for the aws environment")
		}
		bin, err := filepath.Abs(f.bin)
		if err != nil {
			return nil, err
		}
		return newLocalEnv(localOptions{bin: bin, store: f.store, hosts: f.hosts, logLevel: f.logLevel, keep: f.keep, log: os.Stderr})
	case "aws":
		return f.openAWS()
	}
	return nil, fmt.Errorf("--env must be local or aws, not %q", f.env)
}

func (f *envFlags) openAWS() (*awsEnv, error) {
	if f.tfOutput == "" {
		return nil, errors.New("--tf-output is required: terraform -chdir=deploy/aws/terraform output -json > fleet.json")
	}
	fleet, err := readFleet(f.tfOutput)
	if err != nil {
		return nil, err
	}
	return newAWSEnv(fleet, f.sshKey, f.bin, f.dryRun, os.Stdout)
}

func cli(args []string) error {
	if len(args) == 0 {
		return usage()
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	fs := flag.NewFlagSet("sdn-lab "+args[0], flag.ContinueOnError)
	var ef envFlags
	switch args[0] {
	case "plans":
		for _, p := range plans {
			fmt.Printf("%-10s %s\n", p.name, p.about)
		}
		return nil
	case "run":
		return runCmd(ctx, fs, &ef, args[1:])
	case "deploy", "purge":
		ef.register(fs)
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		e, err := ef.openAWS()
		if err != nil {
			return err
		}
		defer e.Close()
		if args[0] == "deploy" {
			return e.Deploy(ctx)
		}
		return e.Purge(ctx)
	case "monitoring":
		tf := fs.String("tf-output", "", "a file holding `terraform output -json`")
		out := fs.String("out", "", "directory for the file_sd target files")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *tf == "" || *out == "" {
			return errors.New("monitoring: --tf-output and --out are required")
		}
		fleet, err := readFleet(*tf)
		if err != nil {
			return err
		}
		files, err := targets(fleet)
		if err != nil {
			return err
		}
		for _, name := range sortedKeys(files) {
			if err := writeFileUnderSudo(filepath.Join(*out, name), files[name]); err != nil {
				return err
			}
		}
		return nil
	}
	return usage()
}

func runCmd(ctx context.Context, fs *flag.FlagSet, ef *envFlags, args []string) error {
	ef.register(fs)
	planSpec := fs.String("plan", "", "a plan, a comma-separated list, or all")
	reports := fs.String("reports", "reports", "directory reports land in")
	deployFirst := fs.Bool("deploy", false, "aws: deploy binaries and run host preparation first")
	var o Options
	fs.DurationVar(&o.Duration, "duration", 10*time.Second, "throughput, round-trip and churn windows")
	fs.IntVar(&o.Streams, "streams", 8, "parallel streams for the many-stream runs")
	fs.IntVar(&o.RRSize, "rr-size", 1, "bytes per request and per response")
	fs.IntVar(&o.Degree, "degree", 20, "attach: the new interface's policy degree")
	fs.IntVar(&o.ChurnDegree, "churn-degree", 4, "churn: each churned interface's policy degree")
	fs.IntVar(&o.Rounds, "rounds", 10, "attach: rounds; failover: rounds, at most 3")
	fs.IntVar(&o.Clients, "clients", 30, "converge: client interfaces, spread over the hosts")
	fs.IntVar(&o.Concurrency, "concurrency", 4, "churn: workers per host")
	fs.IntVar(&o.MaxIfaces, "max-interfaces", 1000, "density: the cap")
	fs.IntVar(&o.Edges, "edges", 12, "spread: edges streaming at once")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *planSpec == "" {
		return errors.New("run: --plan is required; sdn-lab plans lists them")
	}
	ps, err := findPlans(*planSpec)
	if err != nil {
		return err
	}
	env, err := ef.open()
	if err != nil {
		return err
	}
	if c, ok := env.(io.Closer); ok {
		defer c.Close()
	}
	if *deployFirst {
		a, ok := env.(*awsEnv)
		if !ok {
			return errors.New("--deploy is for the aws environment")
		}
		if err := a.Deploy(ctx); err != nil {
			return fmt.Errorf("deploy: %w", err)
		}
	}
	var errs []error
	for _, p := range ps {
		if err := runPlan(ctx, env, p, o, *reports, os.Stderr); err != nil {
			errs = append(errs, err)
		}
		if ctx.Err() != nil {
			break
		}
	}
	return errors.Join(errs...)
}
