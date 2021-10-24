package cert

import (
	"crypto/tls"
	"crypto/x509"
	"github.com/lucas-clemente/quic-go"
	"net"
	"tcpfastopen/quic0rtt"
	"time"
)

func SkipHostnameVerification(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	return nil
}

func GetTLSCert(ip net.IP, port string) ([]*x509.Certificate, error) {
	d := &net.Dialer{Timeout: 2 * time.Second}

	conn, err := tls.DialWithDialer(d, "tcp", ip.String() + ":" + port, &tls.Config{
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: SkipHostnameVerification,
	})
	if err != nil {
		return []*x509.Certificate{{}}, err
	}
	defer conn.Close()
	cert := conn.ConnectionState().PeerCertificates[:1]

	return cert, nil
}

func GetQUICCert(ip string, port string) ([]*x509.Certificate, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: SkipHostnameVerification,
		NextProtos: quic0rtt.DefaultDoQVersions,
	}
	quicConfig := &quic.Config{
		HandshakeIdleTimeout: 2 * time.Second,
		Versions: quic0rtt.DefaultQUICVersions,
	}
	session, err := quic.DialAddr(ip + ":"+port, tlsConfig, quicConfig)
	if err != nil {
		return nil, err
	}
	defer session.CloseWithError(0, "")

	return session.ConnectionState().TLS.PeerCertificates[:1], nil
}
