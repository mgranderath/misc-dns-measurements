// +build windows

package tcpfastopen

func SupportsTFO(ip string, port int) (bool, error) {
	return false, nil
}