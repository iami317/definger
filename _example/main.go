package main

import (
	"github.com/iami317/definger"
	"github.com/urfave/cli/v2"
	"log"
	"os"
)

const defaultPort = "443"

func RunApp() {
	//host := "gitee.com"
	//port := 443
	//pt := "https"
	//result := definger.NewDefineResult(host, port, pt)
	//result.RunDefinger()
	//fmt.Println("result.title: ", result.Title)
	//fmt.Println("result.host: ", result.Host)
	//fmt.Println("result.port: ", result.Port)
	//fmt.Println("result.path: ", result.Path)
	//fmt.Println("result.protocol: ", result.Protocol)
	//fmt.Println("result.identify: ", result.Identify)
	//fmt.Println("result.identify_info: ", result.IdentifyInfo)
	//fmt.Println("result.url: ", result.Url)
	app := cli.NewApp()
	app.Usage = ""
	app.Name = "definger"
	app.Usage = "author: mlh"
	app.Version = "0.1 beta"
	app.Description = ""
	app.Copyright = "qdcx co."
	app.HelpName = "-h"
	app.Flags = []cli.Flag{
		&cli.StringFlag{
			Name:    "target",
			Aliases: []string{"t"},
			Usage:   "Specify a target URL [e.g. -url https://example.com]",
		},
		&cli.BoolFlag{
			Name:    "tech-detect",
			Aliases: []string{"td"},
			Usage:   "display technology in use based on wappalyzer dataset",
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
	scheme, host, port, _ := definger.SplitSchemeHostPort(c.String("target"))
	client := definger.NewDefineResult(host, port, scheme)
	client.HttpIdentifyResult()
	client.Print()
	return nil
}
