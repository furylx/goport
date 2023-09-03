package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

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

// parseSinglePort extracts the port from the string, checks for errors, if none it returns the port as in
func parseSinglePort(p string) (int, error) {
	fmt.Printf("parsingSinglePort: %v\n", p)
	port, err := strconv.Atoi(p)
	if err != nil {
		log.Fatalf("invalid port format: %v\terror: %v\n", port, err)
		return 0, err
	}
	return port, nil
}

// parseMultiPort extracts multiple ports separated by commas and returns a slice of int containg the ports
func parseMultiPort(p string) ([]int, error) {
	portsRaw := strings.Split(p, ",")

	var ports []int

	for _, i := range portsRaw {
		port, err := parseSinglePort(i)

		if err != nil {
			log.Fatalf("invalid port format: %v\terror: %v", p, err)
			return nil, err
		}
		ports = append(ports, port)
	}

	return ports, nil
}

// parsePortRange extracts the range of ports and returns a slice of int containg all the ports from i - n
func parsePortRange(p string) ([]int, error) {
	portRange := strings.Split(p, "-")
	lower, err1 := strconv.Atoi(portRange[0])
	upper, err2 := strconv.Atoi(portRange[1])

	if err1 != nil || err2 != nil {

		return nil, fmt.Errorf("invalid port format: %v\t%v\terrors: %v\t%v\n", lower, upper, err1, err2)
	}

	var ports []int

	for i := lower; i <= upper; i++ {
		ports = append(ports, i)
	}

	fmt.Printf("parsingPortRange: %v\n", ports)
	return ports, nil
}

// handlePorts is the wrapper function for the different inputs for the -p flag
func handlePorts(p string) ([]int, error) {
	fmt.Printf("handlePorts: %v\n", p)
	var ports []int
	// All ports or default case
	if p == "1-1024" {
		ports, err := parsePortRange(p)
		if err != nil {
			return nil, err
		}
		return ports, nil
	} else if p == "-" {
		ports, err := parsePortRange("1-65535")
		if err != nil {
			return nil, err
		}
		return ports, nil
	} else if strings.Contains(p, "-") {
		ports, err := parsePortRange(p)
		if err != nil {
			return nil, err
		}
		return ports, nil
	} else if strings.Contains(p, ",") {
		ports, err := parseMultiPort(p)
		if err != nil {
			return nil, err
		}
		return ports, nil
	} else {
		single, err := parseSinglePort(p)
		if err != nil {
			return nil, err
		}
		ports = append(ports, single)
		return ports, nil
	}
}

// handleModes handles modes...
func handleModes(m string) {
	fmt.Printf("handleModes: %v\n", m)

}

// handleTarget handles the target, if a URL is passed, the URL is resolved into an IPv4 address
func handleTarget(t string) {
	fmt.Printf("handleTarget: %v\n", t)

}
