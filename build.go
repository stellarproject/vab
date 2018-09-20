// stole from buildkit, tonis said it was ok
package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/containerd/console"
	"github.com/moby/buildkit/client"
	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/session"
	"github.com/moby/buildkit/session/auth/authprovider"
	"github.com/moby/buildkit/util/progress/progressui"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	"golang.org/x/sync/errgroup"
)

var buildCommand = cli.Command{
	Name:        "build",
	Description: "build an image using buildkit",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "ref,r",
			Usage: "ref of the image",
		},
		cli.BoolFlag{
			Name:  "push,p",
			Usage: "push the final image",
		},
		cli.StringFlag{
			Name:  "dockerfile,d",
			Usage: "set the path to a Dockerfile",
			Value: ".",
		},
		cli.StringFlag{
			Name:  "context,c",
			Usage: "set the context path",
			Value: ".",
		},
		cli.BoolFlag{
			Name:   "dry",
			Usage:  "test run the build without any exports",
			Hidden: true,
		},
		cli.BoolFlag{
			Name:  "local",
			Usage: "export the build results to the local directory",
		},
		cli.StringSliceFlag{
			Name:  "arg,a",
			Usage: "set build arguments",
			Value: &cli.StringSlice{},
		},
	},
	Action: func(clix *cli.Context) error {
		if err := build(clix); err != nil {
			return err
		}
		if clix.Bool("push") {
			panic("push not supported")
		}
		return nil
	},
}

func read(r io.Reader, clicontext *cli.Context) (*llb.Definition, error) {
	def, err := llb.ReadFrom(r)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse input")
	}
	return def, nil
}

func build(clicontext *cli.Context) error {
	c, err := resolveClient(clicontext)
	if err != nil {
		return err
	}
	ch := make(chan *client.SolveStatus)
	eg, ctx := errgroup.WithContext(commandContext(clicontext))

	atters := make(map[string]string)
	for _, a := range clicontext.StringSlice("arg") {
		kv := strings.SplitN(a, "=", 2)
		if len(kv) != 2 {
			return errors.Errorf("invalid build-arg value %s", a)
		}
		atters["build-arg:"+kv[0]] = kv[1]
	}
	solveOpt := client.SolveOpt{
		Exporter:      "image",
		ExporterAttrs: make(map[string]string),
		Frontend:      "dockerfile.v0",
		FrontendAttrs: atters,
		Session:       []session.Attachable{authprovider.NewDockerAuthProvider()},
	}
	switch {
	case clicontext.Bool("dry"):
		solveOpt.Exporter = ""
	case clicontext.Bool("local"):
		solveOpt.Exporter = "local"
		solveOpt.ExporterAttrs["output"] = "."
	default:
		ref := clicontext.String("ref")
		if ref == "" {
			return errors.New("ref is required when exporting image")
		}
		solveOpt.ExporterAttrs["name"] = ref
	}
	solveOpt.ExporterOutput, solveOpt.ExporterOutputDir, err = resolveExporterOutput(solveOpt.Exporter, solveOpt.ExporterAttrs["output"])
	if err != nil {
		return errors.Wrap(err, "invalid exporter-opt: output")
	}
	if solveOpt.ExporterOutput != nil || solveOpt.ExporterOutputDir != "" {
		delete(solveOpt.ExporterAttrs, "output")
	}
	solveOpt.ExportCacheAttrs = map[string]string{"mode": "min"}
	solveOpt.LocalDirs, err = attrMap(
		fmt.Sprintf("context=%s", clicontext.String("context")),
		fmt.Sprintf("dockerfile=%s", clicontext.String("dockerfile")),
	)
	if err != nil {
		return errors.Wrap(err, "invalid local")
	}
	var def *llb.Definition
	eg.Go(func() error {
		resp, err := c.Solve(ctx, def, solveOpt, ch)
		if err != nil {
			return err
		}
		for k, v := range resp.ExporterResponse {
			logrus.Debugf("solve response: %s=%s", k, v)
		}
		return err
	})

	displayCh := ch

	eg.Go(func() error {
		var c console.Console
		if cf, err := console.ConsoleFromFile(os.Stderr); err == nil {
			c = cf
		}
		// not using shared context to not disrupt display but let is finish reporting errors
		return progressui.DisplaySolveStatus(context.TODO(), "", c, os.Stdout, displayCh)
	})

	return eg.Wait()
}

func attrMap(sl ...string) (map[string]string, error) {
	m := map[string]string{}
	for _, v := range sl {
		parts := strings.SplitN(v, "=", 2)
		if len(parts) != 2 {
			return nil, errors.Errorf("invalid value %s", v)
		}
		m[parts[0]] = parts[1]
	}
	return m, nil
}

// resolveExporterOutput returns at most either one of io.WriteCloser (single file) or a string (directory path).
func resolveExporterOutput(exporter, output string) (io.WriteCloser, string, error) {
	switch exporter {
	case client.ExporterLocal:
		if output == "" {
			return nil, "", errors.New("output directory is required for local exporter")
		}
		return nil, output, nil
	case client.ExporterOCI, client.ExporterDocker:
		if output != "" {
			fi, err := os.Stat(output)
			if err != nil && !os.IsNotExist(err) {
				return nil, "", errors.Wrapf(err, "invalid destination file: %s", output)
			}
			if err == nil && fi.IsDir() {
				return nil, "", errors.Errorf("destination file is a directory")
			}
			w, err := os.Create(output)
			return w, "", err
		}
		// if no output file is specified, use stdout
		if _, err := console.ConsoleFromFile(os.Stdout); err == nil {
			return nil, "", errors.Errorf("output file is required for %s exporter. refusing to write to console", exporter)
		}
		return os.Stdout, "", nil
	default: // e.g. client.ExporterImage
		if output != "" {
			return nil, "", errors.Errorf("output %s is not supported by %s exporter", output, exporter)
		}
		return nil, "", nil
	}
}

func commandContext(c *cli.Context) context.Context {
	return context.Background()
}

func resolveClient(c *cli.Context) (*client.Client, error) {
	opts := []client.ClientOpt{client.WithBlock()}
	ctx := commandContext(c)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return client.New(ctx, buildkitProto(c.String("address")), opts...)
}

func buildkitProto(s string) string {
	if strings.HasPrefix(s, "unix://") || strings.HasPrefix(s, "tcp://") {
		return s
	}
	if _, _, err := net.SplitHostPort(s); err == nil {
		return fmt.Sprintf("tcp://%s", s)
	}
	return fmt.Sprintf("unix://%s", s)
}
