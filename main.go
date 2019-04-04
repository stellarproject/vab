package main

import (
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

func main() {
	app := cli.NewApp()
	app.Name = "vab"
	app.Version = "4"
	app.Usage = "container assembly builder"
	app.Description = `
        _..-.._
     .'  _   _  ` + "`" + `.
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

container assembly builder`
	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:  "debug",
			Usage: "enable debug output in the logs",
		},
		cli.StringFlag{
			Name:   "buildkit,b",
			Usage:  "buildkit address",
			Value:  "127.0.0.1:9500",
			EnvVar: "BUILDKIT",
		},
	}
	app.Before = func(clix *cli.Context) error {
		if clix.GlobalBool("debug") {
			logrus.SetLevel(logrus.DebugLevel)
		}
		return nil
	}
	app.Commands = []cli.Command{
		buildCommand,
		cronCommand,
	}
	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
