package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/fatih/color"
	"golang.org/x/crypto/ssh"
	"sync"
	"time"
)

// check if authentication succeeds. If so, close connection and return true.
func (h *honeydetect) checkSSH(host string) bool {
	config := spawnConfig(h.config.Username, generatePassword(h.config.PasswordLength), h.config.Timeout.Duration)
	conn, err := ssh.Dial("tcp", host, config)

	if err != nil {
		fmt.Println(err)
		return false
	}
	_ = conn.Close()
	return true
}

// Generate an ssh configuration based on input parameters from TOML config
func spawnConfig(username string, password string, timeout time.Duration) *ssh.ClientConfig {

	reader := rand.Reader
	bitSize := 2048
	key, err := rsa.GenerateKey(reader, bitSize)

	signer, err := ssh.ParsePrivateKey(encodePrivateKeyToPEM(key))
	if err != nil{
		panic(err)
	}

	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
			ssh.PublicKeys(signer),
		},
		Timeout:         timeout,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	return config
}

// Check if hosts in the supplied address list are honeypots by connecting multiple times with different configs
func (h *honeydetect) checkForSSH(addressList []string) (scanned int, positives int,negatives int) {


	color.Blue("Starting SSH check...")

	var wg sync.WaitGroup
	for _, target := range addressList {
		host := target + ":22"
		wg.Add(1)
		go func() {
			defer wg.Done()

			// Will authenticate with client "Depth" amount of times.
			for i := 0; i < h.config.Depth; i++ {
				if !h.checkSSH(host) {
					scanned++
					negatives++
					return
				}
			}
			scanned++
			positives++
			color.Yellow("SSH honeypot found: %s", host)
		}()
	}
	wg.Wait()
	color.Blue("Done scanning for SSH honeypots.")

	return
}

func encodePrivateKeyToPEM(privateKey *rsa.PrivateKey) []byte {
	private := x509.MarshalPKCS1PrivateKey(privateKey)
	privBlock := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   private,
	}
	return pem.EncodeToMemory(&privBlock)
}