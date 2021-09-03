package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	quic "github.com/lucas-clemente/quic-go"
	"log"
	"math/big"
	"net"
	"sync"
	"time"
)

type clientSessionCache struct {
	mutex sync.Mutex
	cache map[string]*tls.ClientSessionState

	gets chan<- string
	puts chan<- string
}

func newClientSessionCache(gets, puts chan<- string) *clientSessionCache {
	return &clientSessionCache{
		cache: make(map[string]*tls.ClientSessionState),
		gets:  gets,
		puts:  puts,
	}
}

var _ tls.ClientSessionCache = &clientSessionCache{}

func (c *clientSessionCache) Get(sessionKey string) (*tls.ClientSessionState, bool) {
	c.gets <- sessionKey
	c.mutex.Lock()
	session, ok := c.cache[sessionKey]
	c.mutex.Unlock()
	return session, ok
}

func (c *clientSessionCache) Put(sessionKey string, cs *tls.ClientSessionState) {
	c.puts <- sessionKey
	c.mutex.Lock()
	c.cache[sessionKey] = cs
	c.mutex.Unlock()
}

const addr = "127.0.0.1:784"

const message = "foobar"

// We start a server echoing data on the first stream the client opens,
// then connect with a client, send the message, and wait for its receipt.
func main() {
	log.Fatal(echoServer())
}

// Start a server that echos all data on the first stream opened by the client
func echoServer() error {
	listener, err := quic.ListenAddrEarly(addr, generateTLSConfig(), nil)
	if err != nil {
		return err
	}
	for {
		_, err := listener.Accept(context.Background())
		if err != nil {
			return err
		}
	}
	return err
}

func clientMain() error {
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"quic-echo-example"},
	}

	gets := make(chan string, 100)
	puts := make(chan string, 100)
	tlsConf.ClientSessionCache = newClientSessionCache(gets,puts)

	quicConfig := &quic.Config{
		AcceptToken: func(clientAddr net.Addr, token *quic.Token) bool {
			return true
		},
	}

	quicConfig.TokenStore = quic.NewLRUTokenStore(100, 100)

	session, err := quic.DialAddrEarly(addr, tlsConf, quicConfig)
	if err != nil {
		return err
	}

	time.Sleep(time.Second * 2)
	session.CloseWithError(0, "0")

	session, err = quic.DialAddrEarly(addr, tlsConf, quicConfig)
	if err != nil {
		return err
	}

	session.CloseWithError(0, "0")
	fmt.Printf("UsedRTT0: %t\n", session.ConnectionState().TLS.Used0RTT)

	return nil
}

// Setup a bare-bones TLS config for the server
func generateTLSConfig() *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}
	return &tls.Config{
		InsecureSkipVerify: true,
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"doq-i01", "doq-i02"},
	}
}
