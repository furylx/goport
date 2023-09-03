package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	scn "goport/pkg/scanner"

	"github.com/urfave/cli/v2"
)

func main() {
	start := time.Now()
	app := &cli.App{
		Name:  "goport",
		Usage: "goport -ip <ipv4> | <url> -p <22> | <22-80> | <22,80,443> | <-> for ports, if omitted 1-1024 are scanned --mode=<stealth> | <speed> | <accuracy> stealth is default",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "p",
				Value: "1-1024",
				Usage: "-p 22,80 or -p 22 for specific ports // -p 22-443 for ranges // -p - for all ports // omitting -p scans the first 1024 ports",
			},
			&cli.StringFlag{
				Name:  "mode",
				Value: "stealth",
				Usage: "Scanning mode. Options: 'stealth' (default), 'speed', 'accuracy'.",
			},
			&cli.StringFlag{
				Name:  "ip",
				Value: "",
				Usage: "target",
			},
		},
		Action: func(cCtx *cli.Context) error {
			var target string
			var ports []int
			var mode string
			if cCtx.String("ip") == "" {
				return cli.Exit("Target must be specified!", 1)
			} else {
				parsedTarget, errTargetHandler := handleTarget(cCtx.String("ip"))
				if errTargetHandler != nil {
					log.Fatalf("Error handling target: %v", errTargetHandler)
				} else {
					target = parsedTarget
				}
			}
			parsedPorts, errPortHandler := handlePorts(cCtx.String("p"))
			if errPortHandler != nil {
				log.Fatalf("Error handling ports: %v", errPortHandler)
			} else {
				ports = parsedPorts
			}

			parsedMode, errModeHandler := handleModes(cCtx.String("mode"))
			if errModeHandler != nil {
				log.Fatalf("Error handling modes: %v", errModeHandler)
			} else {
				mode = parsedMode
			}
			scn.Scan(target, ports, mode)
			return nil
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatalf("Problem running arguments: %v\nos.Args: %v\n", err, os.Args)
	}
	fmt.Println("Time taken since start: ", time.Since(start))
}

// parseSinglePort extracts the port from the string, checks for errors, if none it returns the port as in
func parseSinglePort(p string) (int, error) {
	port, err := strconv.Atoi(p)
	if err != nil {
		return 0, fmt.Errorf("<parseSinglePort> invalid port format: %v\terror: %v\n", p, err)
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
			return nil, fmt.Errorf("<parseMultiPort> invalid port format: %v\terror: %v\n", p, err)
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

		return nil, fmt.Errorf("<parsePortRange> invalid port format: %v\terrors: %v\t%v\n", p, err1, err2)
	}

	var ports []int

	for i := lower; i <= upper; i++ {
		ports = append(ports, i)
	}
	return ports, nil
}

// handlePorts is the wrapper function for the different inputs for the -p flag
func handlePorts(p string) ([]int, error) {
	var ports []int
	// All ports or default case
	if p == "1-1024" {
		parsedPorts, err := parsePortRange(p)
		ports = append(ports, parsedPorts...)
		if err != nil {
			return nil, fmt.Errorf("<handlePorts> error during default case: %v\terror: %v\n", p, err)
		}
		return ports, nil
	} else if p == "-" {
		parsedPorts, err := parsePortRange("1-65535")
		ports = append(ports, parsedPorts...)
		if err != nil {
			return nil, fmt.Errorf("<handlePorts> error all ports case: %v\terror: %v\n", p, err)
		}
		return ports, nil
	} else if strings.Contains(p, "-") {
		parsedPorts, err := parsePortRange(p)
		ports = append(ports, parsedPorts...)
		if err != nil {
			return nil, fmt.Errorf("<handlePorts> error during range case: %v\terror: %v\n", p, err)
		}
		return ports, nil
	} else if strings.Contains(p, ",") {
		parsedPorts, err := parseMultiPort(p)
		ports = append(ports, parsedPorts...)
		if err != nil {
			return nil, fmt.Errorf("<handlePorts> error during multiple ports case: %v\terror: %v\n", p, err)
		}
		return ports, nil
	} else {
		single, err := parseSinglePort(p)
		if err != nil {
			return nil, fmt.Errorf("<handlePorts> error during single port case: %v\terror: %v\n", p, err)
		}
		ports = append(ports, single)
		return ports, nil
	}
}

// handleModes handles modes...
func handleModes(m string) (string, error) {
	fmt.Printf("handleModes: %v\n", m)
	return "", nil

}

// handleTarget handles the target, if a URL is passed, the URL is resolved into an IPv4 address
func handleTarget(t string) (string, error) {
	fmt.Printf("handleTarget: %v\n", t)
	return "", nil
}

func resolveDomain(d string) (string, error) {
	var ip string
	return ip, nil
}
