package main

import (
	"github.com/iami317/definger"
	"github.com/urfave/cli/v2"
	"log"
	"os"
)

const defaultPort = "443"

func RunApp() {
	app := cli.NewApp()
	app.Usage = ""
	app.Name = "deFinger"
	app.Usage = "author: mlh"
	app.Version = "0.1 beta"
	app.Description = ""
	app.Copyright = "hzon.com"
	app.HelpName = "-h"
	app.Flags = []cli.Flag{
		&cli.StringFlag{
			Name:    "url",
			Aliases: []string{"u"},
			Usage:   "Specify a target URL [e.g. -url https://example.com]",
		},
	}
	app.Action = RunServer
	err := app.Run(os.Args)
	if err != nil {
		log.Fatalf("engin err: %v", err)
		return
	}

}

func main() {
	RunApp()
}

func RunServer(c *cli.Context) error {
	scheme, host, port, _ := definger.SplitSchemeHostPort(c.String("url"))
	client := definger.NewDefineResult(host, port, scheme)
	client.HttpIdentifyResult()
	client.Print()
	return nil
}
