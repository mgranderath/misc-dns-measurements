package quic0rtt

import (
	"crypto/tls"
	"crypto/x509"
	"github.com/lucas-clemente/quic-go"
	"reflect"
	"strconv"
	"time"
)

func GetVersion(ip string, port int) (*uint64, *string, error) {
	session, err := quic.DialAddr(ip + ":" + strconv.Itoa(port), &tls.Config{
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			return nil
		},
		NextProtos: defaultDoQVersions,
	},&quic.Config{
		HandshakeIdleTimeout: time.Second * 2,
		Versions: defaultQUICVersions,
	})

	if err != nil {
		return nil, nil, err
	}

	quicVersion := reflect.ValueOf(session).Elem().FieldByName("version").Uint()
	negotiated := session.ConnectionState().TLS.NegotiatedProtocol

	return &quicVersion, &negotiated, nil
}
