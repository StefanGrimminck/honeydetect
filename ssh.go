package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"github.com/fatih/color"
	"golang.org/x/crypto/ssh"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// check if authentication succeeds. If so, close connection and return true.
func (h *honeydetect) checkSSH(host string, signer *ssh.Signer) bool {
	config := spawnConfig(h.config.Username, signer , generatePassword(h.config.PasswordLength), h.config.Timeout.Duration)
	conn, err := ssh.Dial("tcp", host, config)

	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// Generate an ssh configuration based on input parameters from TOML config
func spawnConfig(username string, signer *ssh.Signer, password string, timeout time.Duration) *ssh.ClientConfig {

	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
			ssh.PublicKeys(),
			ssh.PublicKeys(*signer),
		},
		Timeout:         timeout,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	return config
}

// Check if hosts in the supplied address list are honeypots by connecting multiple times with different configs
func (h *honeydetect) checkForSSH(addressList []string) (positives uint64, negatives uint64) {
	color.Blue("Starting SSH check...")

	signer, err := generateSSHKeys()

	if err != nil{
		panic(err)
	}

	var wg sync.WaitGroup

	for _, target := range addressList {
		host := target + ":22"
		wg.Add(1)


		go func() {
			defer wg.Done()

			// Will authenticate with client "Depth" amount of times.
			for i := 0; i < h.config.Depth; i++ {
				if !h.checkSSH(host, &signer){
					atomic.AddUint64(&negatives, 1)
					color.Red("No honeypot found at: " + host)
					return
				}
			}

			if falsePositiveCheck(host){
				atomic.AddUint64(&negatives, 1)
				return
			}

			atomic.AddUint64(&positives, 1)
			color.Yellow("SSH honeypot found: %s", host)
			}()
	}
	wg.Wait()
	color.Blue("Done scanning for SSH honeypots.")

	return
}

func generateSSHKeys() (ssh.Signer, error) {
	bitSize := 4096
	privateKey, err := rsa.GenerateKey(rand.Reader, bitSize)

	if err != nil{
		panic(err)
	}

	privDER := x509.MarshalPKCS1PrivateKey(privateKey)

	// pem.Block
	privBlock := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   privDER,
	}

	// Private key in PEM format
	privatePEM := pem.EncodeToMemory(&privBlock)

	return ssh.ParsePrivateKey(privatePEM)

}


// Returns true if a false-positive is detected or when host is unreachable
func falsePositiveCheck(host string) bool {
	c, err := net.Dial("tcp", host)
	if err != nil {
		return true
	}
	c.Write([]byte("\n"))
	message, _ := bufio.NewReader(c).ReadString('\n')
	c.Close()

	return strings.Contains(message, "dropbear")

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