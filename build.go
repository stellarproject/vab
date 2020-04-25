// stole from buildkit, tonis said it was ok
package main

import (
	"context"
	"encoding/csv"
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
	Usage:       "build an image or export its contents",
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
			Name:  "dry",
			Usage: "test run the build without any exports",
		},
		cli.BoolFlag{
			Name:  "local",
			Usage: "export the build results to the local directory",
		},
		cli.BoolFlag{
			Name:  "oci",
			Usage: "export the build results as an OCI image",
		},
		cli.StringFlag{
			Name:  "output",
			Usage: "output directory or file location (used with --local|--oci",
			Value: ".",
		},
		cli.StringFlag{
			Name: "target",
			Usage: "set target stage to build",
		},
		cli.StringSliceFlag{
			Name:  "arg,a",
			Usage: "set build arguments",
			Value: &cli.StringSlice{},
		},
		cli.BoolFlag{
			Name:  "http,i",
			Usage: "push over http",
		},
		cli.BoolFlag{
			Name:  "detail",
			Usage: "detailed build output",
		},
		cli.StringSliceFlag{
			Name:  "cache-from",
			Usage: "external cache source (eg. user/app:cache, type=local,dest=path/to/dir)",
		},
		cli.StringSliceFlag{
			Name:  "cache-to",
			Usage: "export cache location (eg. user/app:cache, type=local,dest=path/to/dir)",
		},
		cli.BoolFlag{
			Name:  "no-cache",
			Usage: "do not use the cache",
		},
	},
	Action: func(clix *cli.Context) error {
		return build(clix)
	},
}

func build(clix *cli.Context) error {
	c, err := resolveClient(clix)
	if err != nil {
		return err
	}
	defer c.Close()
	ch := make(chan *client.SolveStatus)
	eg, ctx := errgroup.WithContext(commandContext(clix))

	atters := make(map[string]string)
	for _, a := range clix.StringSlice("arg") {
		kv := strings.SplitN(a, "=", 2)
		if len(kv) != 2 {
			return errors.Errorf("invalid build-arg value %s", a)
		}
		atters["build-arg:"+kv[0]] = kv[1]
	}
	if clix.Bool("no-cache") {
		atters["no-cache"] = ""
	}
	if v := clix.String("target"); v != "" {
		atters["target"] = v
	}
	solveOpt := client.SolveOpt{
		Frontend:      "dockerfile.v0",
		FrontendAttrs: atters,
		Session:       []session.Attachable{authprovider.NewDockerAuthProvider(os.Stderr)},
	}
	cacheImports, err := parseCacheEntry(clix.StringSlice("cache-from"))
	if err != nil {
		return err
	}
	cacheExports, err := parseCacheEntry(clix.StringSlice("cache-to"))
	if err != nil {
		return err
	}
	solveOpt.CacheImports = cacheImports
	solveOpt.CacheExports = cacheExports

	exportEntry := client.ExportEntry{
		Type:  "image",
		Attrs: map[string]string{},
	}
	switch {
	case clix.Bool("dry"):
	case clix.Bool("local"):
		exportEntry.Type = "local"
		exportEntry.Attrs["output"] = clix.String("output")
	case clix.Bool("oci"):
		exportEntry.Type = "oci"
		exportEntry.Attrs["output"] = clix.String("output")
	default:
		ref := clix.String("ref")
		if ref == "" {
			return errors.New("ref is required when exporting image")
		}
		exportEntry.Attrs["name"] = ref
		if clix.Bool("push") {
			exportEntry.Attrs["push"] = "true"
			if clix.Bool("http") || strings.Contains(ref, "127.0.0.1") {
				exportEntry.Attrs["registry.insecure"] = "true"
			}
		}
	}
	wc, dir, err := resolveExporterOutput(exportEntry.Type, exportEntry.Attrs["output"])
	if err != nil {
		return errors.Wrap(err, "invalid exporter-opt: output")
	}
	if wc != nil {
		exportEntry.Output = func(attrs map[string]string) (io.WriteCloser, error) {
			return wc, nil
		}
	}
	if dir != "" {
		exportEntry.OutputDir = dir
	}
	if exportEntry.Output != nil || exportEntry.OutputDir != "" {
		delete(exportEntry.Attrs, "output")
	}
	solveOpt.Exports = []client.ExportEntry{exportEntry}
	solveOpt.LocalDirs, err = attrMap(
		fmt.Sprintf("context=%s", clix.String("context")),
		fmt.Sprintf("dockerfile=%s", clix.String("dockerfile")),
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
		if !clix.Bool("detail") {
			if cf, err := console.ConsoleFromFile(os.Stderr); err == nil {
				c = cf
			}
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
	opts := []client.ClientOpt{}
	ctx := commandContext(c)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return client.New(ctx, buildkitProto(c.GlobalString("buildkit")), opts...)
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

// vendored from https://github.com/docker/buildx/blob/master/build/cache.go
func parseCacheEntry(in []string) ([]client.CacheOptionsEntry, error) {
	imports := make([]client.CacheOptionsEntry, 0, len(in))
	for _, in := range in {
		csvReader := csv.NewReader(strings.NewReader(in))
		fields, err := csvReader.Read()
		if err != nil {
			return nil, err
		}
		if isRefOnlyFormat(fields) {
			for _, field := range fields {
				imports = append(imports, client.CacheOptionsEntry{
					Type:  "registry",
					Attrs: map[string]string{"ref": field},
				})
			}
			continue
		}
		im := client.CacheOptionsEntry{
			Attrs: map[string]string{},
		}
		for _, field := range fields {
			parts := strings.SplitN(field, "=", 2)
			if len(parts) != 2 {
				return nil, errors.Errorf("invalid value %s", field)
			}
			key := strings.ToLower(parts[0])
			value := parts[1]
			switch key {
			case "type":
				im.Type = value
			default:
				im.Attrs[key] = value
			}
		}
		if im.Type == "" {
			return nil, errors.Errorf("type required form> %q", in)
		}
		imports = append(imports, im)
	}
	return imports, nil
}

func isRefOnlyFormat(in []string) bool {
	for _, v := range in {
		if strings.Contains(v, "=") {
			return false
		}
	}
	return true
}
