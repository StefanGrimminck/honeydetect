package main

import (
	"github.com/fatih/color"
	"net"
	"strings"
	"sync"
	"sync/atomic"
)

func (h *honeydetect) checkForTelnet(addressList []string) (positives uint64,negatives uint64) {
	color.Blue("Starting TELNET check...")

	var wg sync.WaitGroup
	for _, target := range addressList {
		host := target + ":23"
		wg.Add(1)
		go func() {
			defer wg.Done()

			// Will authenticate with client "Depth" amount of times.
			for i := 0; i < h.config.Depth; i++ {
				if !h.checkTELNET(host) {
					atomic.AddUint64(&negatives, 1)
					return
				}
			}

			atomic.AddUint64(&positives, 1)
			color.Yellow("TELNET honeypot found: %s", host)
		}()
	}
	wg.Wait()
	color.Blue("Done scanning for TELNET honeypots.")

	return
}

func (h *honeydetect)checkTELNET(host string) bool {
	var user, pass bool
	buf := make([]byte, 4096)
	conn, err := net.Dial("tcp", host)

	if err != nil{
		return false
	}

	defer conn.Close()

	for {
		n, err := conn.Read(buf)
		if err != nil{
			break
		}
		//Check for username prompt. Respond with configured username
		input := string(buf[:n])
		if strings.Contains(strings.ToLower(input), "username:" ) ||
			strings.Contains(strings.ToLower(input), "login:" ){
			_, err = conn.Write([]byte(h.config.Username))
			if err != nil{
				break
			}
			_, err = conn.Write([]byte("\n"))
			if err != nil{
				break
			}

			user = true

		}
		//Check for password prompt. Respond with configured password
		if strings.Contains(string(buf[:n]), "Password:" ){
			_, err = conn.Write([]byte(generatePassword(h.config.PasswordLength)))
			if err != nil{
				break
			}
			_, err = conn.Write([]byte("\n"))
			if err != nil{
				break
			}
			pass = true
		}

		//If credentials check has been passed. Scan for ">" icon as an indication of success
		if user && pass && (strings.Contains(string(buf[:n]),">") || strings.Contains(string(buf[:n]),"~#")) {
			return true
		}
	}

	return false
}

