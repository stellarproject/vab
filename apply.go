package main

import (
	"archive/tar"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

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
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

var applyCommand = cli.Command{
	Name:  "apply",
	Usage: "apply and image to a destination",
	Flags: []cli.Flag{
		cli.BoolFlag{
			Name:  "no-post",
			Usage: "don't run post install",
		},
		cli.BoolFlag{
			Name:  "http,i",
			Usage: "pull over http",
		},
		cli.StringFlag{
			Name:  "device",
			Usage: "unpack to the device",
		},
		cli.BoolFlag{
			Name:  "boot",
			Usage: "install the kernel and initrd from the image",
		},
	},
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
		device := clix.String("device")
		if device != "" {
			tmpMount, err := ioutil.TempDir("", "vab-device-")
			if err != nil {
				return err
			}
			defer os.RemoveAll(tmpMount)
			if err := syscall.Mount(device, tmpMount, "ext4", 0, ""); err != nil {
				return err
			}
			defer syscall.Unmount(tmpMount, 0)
			destination = filepath.Join(tmpMount, destination)
		}
		return applyImage(clix, image, destination)
	},
}

func postInstall(i *Image, dest string) error {
	logrus.Info("running post install commands")
	for _, arg := range i.Config.OnBuild {
		logrus.WithField("command", arg).Info("executing command")
		cmd := exec.Command("bash", "-c", arg)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return errors.Wrapf(err, "executing %q", arg)
		}
	}
	return nil
}

func applyImage(clix *cli.Context, imageName, dest string) error {
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
	defer func() {
		if err := os.RemoveAll(tmpContent); err != nil {
			logrus.WithError(err).Errorf("removing content store at %s", tmpContent)
			return
		}
		logrus.Infof("removing content store at %s", tmpContent)
	}()

	logrus.Infof("created content store at %s", tmpContent)
	cs, err := local.NewStore(tmpContent)
	if err != nil {
		return err
	}

	authorizer := docker.NewAuthorizer(nil, getDockerCredentials)
	resolver := docker.NewResolver(docker.ResolverOptions{
		PlainHTTP:  clix.Bool("http"),
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
	logrus.Info("fetching system image")
	childrenHandler := images.ChildrenHandler(cs)
	h := images.Handlers(remotes.FetchHandler(cs, fetcher), childrenHandler)
	if err := images.Dispatch(ctx, h, nil, desc); err != nil {
		return err
	}
	config, layers, err := getLayers(ctx, cs, desc)
	if err != nil {
		return err
	}
	logrus.Infof("unpacking image to %q", dest)
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
		logrus.WithField("layer", layer.Blob.Digest).Info("apply layer")
		if _, err := archive.Apply(ctx, dest, r, archive.WithFilter(HostFilter)); err != nil {
			return err
		}
	}
	if clix.Bool("boot") {
		config.Config.OnBuild = append([]string{
			fmt.Sprintf("cp %s/* /boot/", filepath.Join(dest, "boot")),
			fmt.Sprintf("cp %s /etc/default/", filepath.Join(dest, "etc/default/grub")),
		},
			config.Config.OnBuild...,
		)
	}
	if clix.Bool("no-post") {
		return nil
	}
	return postInstall(config, dest)
}

const excludedModes = os.ModeDevice | os.ModeCharDevice | os.ModeSocket | os.ModeNamedPipe

func HostFilter(h *tar.Header) (bool, error) {
	// exclude devices
	if h.FileInfo().Mode()&excludedModes != 0 {
		return false, nil
	}
	// exclude /run
	parts := strings.Split(h.Name, "/")
	if len(parts) > 0 && parts[0] == "/run" {
		return false, nil
	}
	return true, nil
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

func getConfig(ctx context.Context, provider content.Provider, desc v1.Descriptor) (*Image, error) {
	p, err := content.ReadBlob(ctx, provider, desc)
	if err != nil {
		return nil, err
	}
	var config Image
	if err := json.Unmarshal(p, &config); err != nil {
		return nil, err
	}
	return &config, nil
}

func getLayers(ctx context.Context, cs content.Store, desc v1.Descriptor) (*Image, []rootfs.Layer, error) {
	manifest, err := images.Manifest(ctx, cs, desc, nil)
	if err != nil {
		return nil, nil, err
	}
	config, err := getConfig(ctx, cs, manifest.Config)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to resolve config")
	}
	diffIDs := config.RootFS.DiffIDs
	if len(diffIDs) != len(manifest.Layers) {
		return nil, nil, errors.Errorf("mismatched image rootfs and manifest layers")
	}
	var (
		layers       []rootfs.Layer
		historyIndex int
	)
	for i := range diffIDs {
		if config.History[historyIndex].EmptyLayer {
			historyIndex++
		}
		// TODO: find a better way to remove the base image data
		if config.History[historyIndex].Comment != "buildkit.dockerfile.v0" {
			historyIndex++
			continue
		}
		var l rootfs.Layer
		l.Diff = v1.Descriptor{
			// TODO: derive media type from compressed type
			MediaType: v1.MediaTypeImageLayer,
			Digest:    diffIDs[i],
		}
		l.Blob = manifest.Layers[i]
		layers = append(layers, l)
		historyIndex++
	}
	return config, layers, nil
}
