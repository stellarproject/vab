package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/Sirupsen/logrus"
	"github.com/containerd/containerd/archive"
	"github.com/containerd/containerd/archive/compression"
	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/content/local"
	"github.com/containerd/containerd/images"
	"github.com/containerd/containerd/remotes"
	"github.com/containerd/containerd/remotes/docker"
	"github.com/containerd/containerd/rootfs"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"github.com/urfave/cli"
)

const postInstallFile = "post-install"

var applyCommand = cli.Command{
	Name:  "apply",
	Usage: "apply and image to a destination",
	Action: func(clix *cli.Context) error {
		var (
			image       = clix.Args().First()
			destination = clix.Args().Get(1)
		)
		if image == "" {
			return errors.New("no image specified")
		}
		if destination == "" {
			return errors.New("no destination specified")
		}
		if err := applyImage(image, destination); err != nil {
			return err
		}
		return postInstall(destination)
	},
}

func postInstall(dest string) error {
	path := filepath.Join(dest, postInstallFile)
	if _, err := os.Stat(path); err != nil {
		// return nil when no post install file exists
		return nil
	}
	cmd := exec.Command(path)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func applyImage(imageName, dest string) error {
	if _, err := os.Stat(dest); err != nil {
		if !os.IsNotExist(err) {
			return err
		}

		if err := os.MkdirAll(dest, 0755); err != nil {
			return err
		}
	}
	tmpContent, err := ioutil.TempDir("", "vab-content-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpContent)

	cs, err := local.NewStore(tmpContent)
	if err != nil {
		return err
	}

	authorizer := docker.NewAuthorizer(nil, getDockerCredentials)
	resolver := docker.NewResolver(docker.ResolverOptions{
		PlainHTTP:  true,
		Authorizer: authorizer,
	})
	ctx := context.Background()

	name, desc, err := resolver.Resolve(ctx, imageName)
	if err != nil {
		return err
	}
	fetcher, err := resolver.Fetcher(ctx, name)
	if err != nil {
		return err
	}

	childrenHandler := images.ChildrenHandler(cs)
	h := images.Handlers(remotes.FetchHandler(cs, fetcher), childrenHandler)
	if err := images.Dispatch(ctx, h, nil, desc); err != nil {
		return err
	}

	layers, err := getLayers(ctx, cs, desc)
	if err != nil {
		return err
	}
	for _, layer := range layers {
		ra, err := cs.ReaderAt(ctx, layer.Blob)
		if err != nil {
			return err
		}
		cr := content.NewReader(ra)
		r, err := compression.DecompressStream(cr)
		if err != nil {
			return err
		}
		defer r.Close()
		if r.(compression.DecompressReadCloser).GetCompression() == compression.Uncompressed {
			continue
		}
		if _, err := archive.Apply(ctx, dest, r); err != nil {
			return err
		}
	}
	return nil
}

// RegistryAuth is the base64 encoded credentials for the registry credentials
type RegistryAuth struct {
	Auth string `json:"auth,omitempty"`
}

// DockerConfig is the docker config struct
type DockerConfig struct {
	Auths map[string]RegistryAuth `json:"auths"`
}

func getDockerCredentials(host string) (string, string, error) {
	logrus.WithField("host", host).Debug("checking for registry auth config")
	home := os.Getenv("HOME")
	credentialConfig := filepath.Join(home, ".docker", "config.json")
	f, err := os.Open(credentialConfig)
	if err != nil {
		if os.IsNotExist(err) {
			return "", "", nil
		}
		return "", "", err
	}
	defer f.Close()

	var cfg DockerConfig
	if err := json.NewDecoder(f).Decode(&cfg); err != nil {
		return "", "", err
	}

	for h, r := range cfg.Auths {
		if h == host {
			creds, err := base64.StdEncoding.DecodeString(r.Auth)
			if err != nil {
				return "", "", err
			}
			parts := strings.SplitN(string(creds), ":", 2)
			logrus.Debugf("using auth for registry %s: user=%s", host, parts[0])
			return parts[0], parts[1], nil
		}
	}

	return "", "", nil
}

func getLayers(ctx context.Context, cs content.Store, desc v1.Descriptor) ([]rootfs.Layer, error) {
	manifest, err := images.Manifest(ctx, cs, desc, nil)
	if err != nil {
		return nil, err
	}
	diffIDs, err := images.RootFS(ctx, cs, manifest.Config)
	if err != nil {
		return nil, errors.Wrap(err, "failed to resolve rootfs")
	}
	if len(diffIDs) != len(manifest.Layers) {
		return nil, errors.Errorf("mismatched image rootfs and manifest layers")
	}
	layers := make([]rootfs.Layer, len(diffIDs))
	for i := range diffIDs {
		layers[i].Diff = v1.Descriptor{
			// TODO: derive media type from compressed type
			MediaType: v1.MediaTypeImageLayer,
			Digest:    diffIDs[i],
		}
		layers[i].Blob = manifest.Layers[i]
	}
	return layers, nil
}
