package SSHUtil

import (
	"bufio"
	"fmt"
	"log"
	"os"

	"sync"

	"golang.org/x/crypto/ssh"
)

type SSHConfig struct {
	user     string
	password string
	config   *ssh.ClientConfig
	host_ip  string
}

func (ssh_config *SSHConfig) ConfigureSSHClient(username, password, host_ip string) {

	ssh_config.user = username
	ssh_config.password = password
	ssh_config.host_ip = host_ip

	config := &ssh.ClientConfig{
		User: ssh_config.user,
		Auth: []ssh.AuthMethod{
			ssh.Password(ssh_config.password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	ssh_config.config = config
}

func (ssh_config *SSHConfig) EstablishTCPConnection() *ssh.Client {
	client, err := ssh.Dial("tcp", ssh_config.host_ip, ssh_config.config)
	if err != nil {
		log.Fatal("Failed to dial: ", err)
	}
	return client
}

func (ssh_config *SSHConfig) EstablishSession(client *ssh.Client) *ssh.Session {
	session, err := client.NewSession()
	if err != nil {
		log.Fatal("Failed to create a session", err)
	}
	return session
}

func (ssh_config *SSHConfig) CreateTerminal(session *ssh.Session, cmd string) {

	defer session.Close()
	modes := ssh.TerminalModes{
		ssh.ECHO:          0,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	if err := session.RequestPty("linux", 80, 40, modes); err != nil {
		log.Fatal("Request for pseudo terminal failed: ", err)
	}

	session.Stdout = os.Stdout
	session.Stdin = os.Stdin
	session.Stderr = os.Stderr

	if err := session.Run(cmd); err != nil {
		log.Fatal("Command execution failed: ", err)
	}
}

func (ssh_config *SSHConfig) ExecuteCommand(session *ssh.Session, cmd string) {

	defer session.Close()
	var wg sync.WaitGroup

	stdout, err := session.StdoutPipe()
	if err != nil {
		log.Fatal("Failed to create stdout from session: ", err)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(stdout)
		for {

			if tkn := scanner.Scan(); tkn {
				rcv := scanner.Bytes()

				raw := make([]byte, len(rcv))
				copy(raw, rcv)

				fmt.Println(string(raw))
			} else {
				if scanner.Err() != nil {
					log.Fatal("Error occured while scanning: ", err)
				} else {
					log.Fatal("End of file reached.")
				}
				return
			}
		}

	}()

	if err := session.Run(cmd); err != nil {
		log.Fatal("Command execution failed: ", err)
	}
	wg.Wait()
}
