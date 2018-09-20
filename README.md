# vab

A simple build tool on top of buildkit for building images in a different way.

```
NAME:
   vab - container assembly builder

USAGE:
   vab [global options] command [command options] [arguments...]

VERSION:
   1

DESCRIPTION:

        _..-.._
     .'  _   _  `.
    /_) (_) (_) (_\
   /               \
   |'''''''''''''''|
  /                 \
 |                   |
 |-------------------|
 |                   |
 |                   |
 |'''''''''''''''''''|
 |             .--.  |
 |            //  \\=|
 |            ||- || |
 |            \\__//=|
 |             '--'  |
 |...................|
 |___________________|
 |___________________|
 |___________________|
 |___________________|
   /_______________\

container assembly builder

COMMANDS:
     build    build an image or export its contents
     cron     cron job to prune and release build artificats
     help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --debug                     enable debug output in the logs
   --buildkit value, -b value  buildkit address (default: "127.0.0.1:9500") [$BUILDKIT]
   --help, -h                  show help
   --version, -v               print the version
```

## Local Output

If you have buildkit already setup, we can build `vab` with `vab` and get the `vab` binary
in our local directory.

```bash
> vab build --local
```

## Image and Push

To build an image and push the results.

```bash
> vab build --push --ref docker.io/stellarproject/vab:latest
```
