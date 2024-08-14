package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"

	"github.com/landlock-lsm/go-landlock/landlock"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

func main() {
	eccpriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatal(err)
	}
	config := &ssh.ServerConfig{
		NoClientAuth: true,
	}

	sshprivrsa, err := ssh.NewSignerFromSigner(priv)
	if err != nil {
		log.Fatal(err)
	}
	config.AddHostKey(sshprivrsa)

	sshprivecc, err := ssh.NewSignerFromKey(eccpriv)
	if err != nil {
		log.Fatal(err)
	}
	config.AddHostKey(sshprivecc)
	if err := landlock.V5.BestEffort().RestrictPaths(
		landlock.ROFiles("hackers.txt"),
	); err != nil {
		log.Fatal(err)
	}

	if err = landlock.V5.BestEffort().RestrictNet(
		landlock.BindTCP(2200),
	); err != nil {
		log.Fatal(err)
	}

	listener, err := net.Listen("tcp", "0.0.0.0:2200")
	if err != nil {
		log.Fatalf("Failed to listen on 2200 (%s)", err)
	}

	// Accept all connections
	log.Print("Listening on 2200...")
	for {
		tcpConn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept incoming connection (%s)", err)
			continue
		}
		sshConn, chans, reqs, err := ssh.NewServerConn(tcpConn, config)
		if err != nil {
			log.Printf("Failed to handshake (%s)", err)
			continue
		}

		log.Printf("New SSH connection from %s (%s)", sshConn.RemoteAddr(), sshConn.ClientVersion())
		go ssh.DiscardRequests(reqs)
		go func(chans <-chan ssh.NewChannel) {
			for newChannel := range chans {
				if newChannel.ChannelType() != "session" {
					log.Fatal(err)
				}
				go func(ch ssh.NewChannel) {
					channel, requests, err := ch.Accept()
					if err != nil {
						log.Fatal(err)
					}
					sshterm := term.NewTerminal(channel, "")
					go func(sshterm *term.Terminal) {
						for req := range requests {
							reqSize := len(req.Payload)
							switch req.Type {
							case "exec":
								channel.Close()
								return
							case "pty-req":
								// p10, 6.2.  Requesting a Pseudo-Terminal, RFC4254
								if reqSize < 4 {
									log.Printf("malformed pty-req request")
									continue
								}

								termVariableSize := int(req.Payload[3])

								if reqSize < 4+termVariableSize+8 {
									log.Printf("malformed pty-req request")
									continue
								}

								w := binary.BigEndian.Uint32(req.Payload[4+termVariableSize:])
								h := binary.BigEndian.Uint32(req.Payload[4+termVariableSize+4:])

								sshterm.SetSize(int(w), int(h))
								req.Reply(true, nil)
							case "window-change":
								// p10, 6.7.  Window Dimension Change Message, RFC4254
								if reqSize < 8 {
									log.Printf("malformed window-change request")
									continue
								}

								w := binary.BigEndian.Uint32(req.Payload)
								h := binary.BigEndian.Uint32(req.Payload[4:])

								_ = sshterm.SetSize(int(w), int(h))
							case "shell":
								log.Printf("shell")
								go func(conn ssh.Channel) {
									log.SetOutput(io.MultiWriter(os.Stdout, sshterm))
									defer log.SetOutput(os.Stdout)
									b, err := os.ReadFile("hackers.txt")
									if err != nil {
										log.Print(err)
										conn.Close()
									}
									sshterm.Write(sshterm.Escape.Green)
									for _, bb := range b {
										fmt.Fprint(sshterm, string(bb))
										time.Sleep(20 * time.Millisecond)
									}
									conn.Close()
								}(channel)
								req.Reply(true, nil)
							}
						}
					}(sshterm)
				}(newChannel)
			}
		}(chans)
	}
}
