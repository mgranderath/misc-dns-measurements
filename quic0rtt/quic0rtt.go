package quic0rtt

import (
	"crypto/tls"
	"github.com/lucas-clemente/quic-go"
	"net"
	"strconv"
	"sync"
	"tcpfastopen/cert"
	"time"
)

const (
	VersionDoQ00 = "doq-i00"
	VersionDoQ01 = "doq-i01"
	VersionDoQ02 = "doq-i02"
	VersionDoQ03 = "doq-i03"
	VersionDoQ04 = "doq-i04"
	VersionDoQ05 = "doq-i05"
	VersionDoQ06 = "doq-i06"
)

var DefaultDoQVersions = []string{VersionDoQ06, VersionDoQ05, VersionDoQ04, VersionDoQ03, VersionDoQ02, VersionDoQ01, VersionDoQ00}

var DefaultQUICVersions = []quic.VersionNumber{
	quic.Version1,
	quic.VersionDraft34,
	quic.VersionDraft32,
	quic.VersionDraft29,
}

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

func Check0RTT(ip string, port int) (bool, error) {
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         DefaultDoQVersions,
		VerifyPeerCertificate: cert.SkipHostnameVerification,
	}

	gets := make(chan string, 100)
	puts := make(chan string, 100)
	tlsConf.ClientSessionCache = newClientSessionCache(gets,puts)

	quicConfig := &quic.Config{
		HandshakeIdleTimeout: 2 * time.Second,
		Versions: DefaultQUICVersions,
		AcceptToken: func(clientAddr net.Addr, token *quic.Token) bool {
			return true
		},
	}

	quicConfig.TokenStore = quic.NewLRUTokenStore(100, 100)

	session, err := quic.DialAddrEarly(ip + ":" + strconv.Itoa(port), tlsConf, quicConfig)
	if err != nil {
		return false, err
	}

	select {
	case <-puts:
	case <-time.After(time.Second * 2):
		return false, err
	}

	session.CloseWithError(0, "0")

	session, err = quic.DialAddrEarly(ip + ":" + strconv.Itoa(port), tlsConf, quicConfig)
	if err != nil {
		return false, err
	}

	used0RTT := session.ConnectionState().TLS.Used0RTT

	//fmt.Printf("UsedRTT0: %t\n", session.ConnectionState().TLS.Used0RTT)
	session.CloseWithError(0, "0")

	return used0RTT, nil
}
