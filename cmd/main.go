package main

import (
	"log"
	"os"

	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:  "goport",
		Usage: "Portscanner using go",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "p",
				Value: "1-1024",
				Usage: "-p 22,80 or -p 22 for specific ports // -p 22-443 for ranges // -p- for all ports // omitting -p or -p without any arguments scans the first 1024 ports",
			},
			&cli.StringFlag{
				Name:  "mode",
				Value: "stealth",
				Usage: "Scanning mode. Options: 'stealth' (default), 'speed', 'accuracy'.",
			},
			&cli.StringFlag{
				Name:  "ip",
				Value: "0",
				Usage: "target",
			},
		},
		Action: func(cCtx *cli.Context) error {
			handlePorts(cCtx.String("p"))
			handleModes(cCtx.String("mode"))
			handleTarget(cCtx.String("ip"))
			return nil
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatalf("Problem running arguments: %v\nos.Args: %v\n", err, os.Args)
	}

}

func parseSinglePort(p string) (int, error) {

	return 0, nil
}

func parsePortRange(p string) ([]int, error) {

	return nil, nil
}

func handlePorts(p string) ([]int, error) {

	return nil, nil
}

func handleModes(m string) {

}

func handleTarget(t string) {

}
