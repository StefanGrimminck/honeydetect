package main

import (
	"bufio"
	"github.com/BurntSushi/toml"
	"github.com/fatih/color"
	cache "github.com/patrickmn/go-cache"
	"math/rand"
	"net"
	"os"
	"strings"
	"time"
)

type Config struct {
	InputFile      string
	Depth          int
	Timeout        duration
	Username       string
	PasswordLength int
	OutputFile     string
}

type honeydetect struct{
	cache *cache.Cache
	config Config
}

type duration struct {
	time.Duration
}

func loadTite() {

	yellow := color.New(color.FgYellow)
	boldYellow := yellow.Add(color.Bold)

	boldYellow.Println(`
______                           _________    _____           _____ 
___  /________________________  _______  /______  /_____________  /_
__  __ \  __ \_  __ \  _ \_  / / /  __  /_  _ \  __/  _ \  ___/  __/
_  / / / /_/ /  / / /  __/  /_/ // /_/ / /  __/ /_ /  __/ /__ / /_  
/_/ /_/\____//_/ /_/\___/_\__, / \__,_/  \___/\__/ \___/\___/ \__/  
                         /____/                                      `)
}

func main() {

	app := honeydetect{
		cache: cache.New(cache.DefaultExpiration, 1 * time.Hour),
	}

	//Load configuration from config.toml
	config, err := loadConfiguration()
	if err != nil {
		color.Red("Error loading configuration file: %s", err.Error())
		os.Exit(1)
	}

	app.setConfig(config)
	app.Run()

}

func (h *honeydetect) setConfig(config *Config){
	h.config = *config
}

func (h *honeydetect) Run(){
	//Print ASCII title to screen
	loadTite()

	//Load address list from configured file
	addressList, err := h.parseFile()
	if err != nil {
		color.Red("Error parsing input address list: %s", err.Error())
		os.Exit(1)
	}

	blue := color.New(color.FgBlue)
	boldBlue := blue.Add(color.Bold)
	_, _ = boldBlue.Printf("Amount of loaded addresses: %v\n", len(addressList))


	//Check if server from list is a SSH honeypot
	sshTotal, sshPositives, sshNegtive := h.checkForSSH(addressList)
	telnetTotal, telnetPositive, telnetNegative := h.checkForTelnet(addressList)

	color.Green("Scanned devices for SSH: \t%d. SSH Honeypots found: %d, Negatives: %d", sshTotal, sshPositives, sshNegtive)
	color.Green("Scanned devices for TELNET: \t%d. TELNET Honeypots found: %d, Negatives: %d", telnetTotal, telnetPositive, telnetNegative)
}

// Load configuration from TOML file into Configuration struct
func loadConfiguration() (conf *Config, err error) {
	if _, err := toml.DecodeFile("config.toml", &conf); err != nil {
		return nil, err
	}
	return conf, nil
}

// Parse address list into a string slice of addresses
func (h *honeydetect) parseFile() (list []string, err error) {

	file, err := os.Open(h.config.InputFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {

		record := scanner.Text()
		if ip := net.ParseIP(record); ip == nil {
			color.Red("Error parsing record as ip address: \"%v\". Skipped...", record)
			continue
		}

		list = append(list, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return list, nil
}

func (d *duration) UnmarshalText(text []byte) error {
	var err error
	d.Duration, err = time.ParseDuration(string(text))
	return err
}

// Generate a password to use for authentication
func generatePassword(length int) string {
	rand.Seed(time.Now().UnixNano())
	chars := []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
		"abcdefghijklmnopqrstuvwxyz" +
		"0123456789")
	var b strings.Builder
	for i := 0; i < length; i++ {
		b.WriteRune(chars[rand.Intn(len(chars))])
	}
	return b.String()
}
