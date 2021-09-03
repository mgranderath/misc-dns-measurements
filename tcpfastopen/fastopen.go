// +build !windows

package tcpfastopen

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"net"
	"os/exec"
	"regexp"
	"syscall"
	"time"
)

type TFOClient struct {
	ServerAddr [4]byte
	ServerPort int
	fd         int
}

const MSG_FASTOPEN = 0x20000000

const (
	MAXMSGSIZE = 8000
)

// Create a tcp socket and send data on it. This uses the sendto() system call
// instead of connect() - because connect() calls does not support sending
// data in the syn packet, but the sendto() system call does (as often used in
// connectionless protocols such as udp.
func (c *TFOClient) Send() (err error) {
	c.fd, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, syscall.IPPROTO_IP)
	if err != nil {
		return
	}
	defer syscall.Close(c.fd)

	sa := &syscall.SockaddrInet4{Addr: c.ServerAddr, Port: c.ServerPort}

	// Data to appear, if an existing tcp fast open cookie is available, this
	// data will appear in the SYN packet, if not, it will appear in the ACK.
	data := []byte("Hello TCP Fast Open")

	tv := syscall.NsecToTimeval(1000 * 1000 * 4000)
	syscall.SetsockoptTimeval(c.fd, syscall.SOL_SOCKET, syscall.SO_SNDTIMEO, &tv)

	// Use the sendto() syscall, instead of connect()
	err = syscall.Sendto(c.fd, data, syscall.MSG_FASTOPEN, sa)
	if err != nil {
		if err == syscall.EOPNOTSUPP {
			err = errors.New("TCP Fast Open client support is unavailable (unsupported kernel or disabled, see /proc/sys/net/ipv4/tcp_fastopen).")
		}
		err = errors.New(fmt.Sprintf("Received error in sendTo():", err))
		return
	}
	// Note, this exists before waiting for response and is meant to illustrate
	// the use of the sendto() system call, not of a complete and proper socket
	// setup and teardown processes.

	return
}

// Use `ip tcp_metrics` to check whether we received a cookie or not. Only
// available in later versions of iproute
func checkTcpMetrics(ip string) (success bool, cached []string, err error) {
	cmd := exec.Command("ip", "tcp_metrics", "show", ip)

	var out bytes.Buffer
	cmd.Stdout = &out
	err = cmd.Run()
	if err != nil {
		return
	}

	reFOc := regexp.MustCompile(" fo_cookie ([a-z0-9]+)")
	reFOmss := regexp.MustCompile(" fo_mss ([0-9]+)")
	reFOdrop := regexp.MustCompile(" fo_syn_drops ([0-9./]sec ago)")

	cookie := reFOc.FindStringSubmatch(out.String())
	mss := reFOmss.FindStringSubmatch(out.String())
	drop := reFOdrop.FindStringSubmatch(out.String())

	success = len(cookie) > 0

	if len(cookie) > 0 {
		cached = append(cached, "cookie: "+cookie[1])
	}

	if len(mss) > 0 {
		cached = append(cached, "mss: "+mss[1])
	}

	if len(drop) > 0 {
		cached = append(cached, "syn_drops: "+drop[1])
	}
	return
}

func SupportsTFO(ip string, port int) (bool, error) {
	IP := net.ParseIP(ip)
	var serverAddr [4]byte
	copy(serverAddr[:], IP[12:16])

	client := TFOClient{ServerAddr: serverAddr, ServerPort: port}

	err := client.Send()
	if err != nil {
		return false, err
	}

	time.Sleep(time.Millisecond * 500)

	success, _, err := checkTcpMetrics(ip)
	if err != nil {
		return false, err
	} else {
		log.Println(ip, success)
		if success {
			return true, nil
		} else {
			return false, nil
		}
	}
}