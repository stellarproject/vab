package main

import (
	"github.com/moby/buildkit/client"
	"github.com/urfave/cli"
)

var cronCommand = cli.Command{
	Name:  "cron",
	Usage: "cron job to prune and release build artificats",
	Flags: []cli.Flag{
		cli.DurationFlag{
			Name:  "duration,d",
			Usage: "Keep data newer than this limit",
		},
	},
	Action: func(clix *cli.Context) error {
		c, err := resolveClient(clix)
		if err != nil {
			return err
		}
		defer c.Close()
		opts := []client.PruneOption{
			client.WithKeepOpt(clix.Duration("duration"), 2048*1e6),
		}
		return c.Prune(commandContext(clix), nil, opts...)
	},
}
