package main

import (
	"bufio"
	"context"
	"github.com/urfave/cli/v2"
	"golang.org/x/sync/semaphore"
	"log"
	"net"
	"os"
	"strconv"
	"sync"
	"tcpfastopen/cert"
	"tcpfastopen/db"
	"tcpfastopen/edns"
	"tcpfastopen/quic0rtt"
	"tcpfastopen/tcpfastopen"
)

func runQVersion(fileName string, parallel int64, port int) {
	file, err := os.Open(fileName)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	var sem = semaphore.NewWeighted(parallel)
	wg := sync.WaitGroup{}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		ip := net.ParseIP(scanner.Text())
		if ip.To4() == nil {
			continue
		}

		sem.Acquire(context.Background(), 1)
		wg.Add(1)
		go func() {
			defer sem.Release(1)
			defer wg.Done()

			qVersion, draftVersion, err := quic0rtt.GetVersion(ip.To4().String(), port)
			if err != nil {
				log.Println(err)
				return
			}
			if qVersion != nil && draftVersion != nil {
				db.AddQVersion(ip.To4().String(), port, *qVersion, *draftVersion)
			}
		}()
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	wg.Wait()
}

func run0RTT(fileName string, parallel int64, port int) {
	file, err := os.Open(fileName)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	var sem = semaphore.NewWeighted(parallel)
	wg := sync.WaitGroup{}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		ip := net.ParseIP(scanner.Text())
		if ip.To4() != nil {
			sem.Acquire(context.Background(), 1)
			wg.Add(1)
			go func() {
				supports, err := quic0rtt.Check0RTT(ip.To4().String(), port)
				if err != nil {
					log.Println(err)
					sem.Release(1)
					wg.Done()
					return
				}
				db.Add0RTTRecord(ip.To4().String(), port, supports)
				log.Println(ip, supports)
				sem.Release(1)
				wg.Done()
			}()
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	wg.Wait()
}

func runEDNS0(fileName string, parallel int64) {
	file, err := os.Open(fileName)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	var sem = semaphore.NewWeighted(parallel)
	wg := sync.WaitGroup{}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		ip := net.ParseIP(scanner.Text())
		if ip.To4() != nil {
			sem.Acquire(context.Background(), 1)
			wg.Add(1)
			go func() {
				data, timeout, err := edns.Exchange(ip.To4().String())
				if err != nil {
					sem.Release(1)
					wg.Done()
					return
				}
				db.AddEDNS0(ip.To4().String(), data, timeout)
				sem.Release(1)
				wg.Done()
			}()
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	wg.Wait()
}

func runQUICCertificates(fileName string, parallel int64, port853 bool) {
	file, err := os.Open(fileName)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	var sem = semaphore.NewWeighted(parallel)
	wg := sync.WaitGroup{}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		ip := net.ParseIP(scanner.Text())
		if ip.To4() != nil {
			sem.Acquire(context.Background(), 1)
			wg.Add(1)
			go func() {
				defer sem.Release(1)
				defer wg.Done()
				if !port853 {
					certChain, err := cert.GetQUICCert(ip.To4().String(), "784")
					if err == nil {
						for _, fetchedCert := range certChain {
							db.AddCertificate(ip.To4().String(), "quic", 784, fetchedCert.Raw)
						}
					}
					certChain, err = cert.GetQUICCert(ip.To4().String(), "8853")
					if err == nil {
						for _, fetchedCert := range certChain {
							db.AddCertificate(ip.To4().String(), "quic", 8853, fetchedCert.Raw)
						}
					}
				}
				certChain, err := cert.GetQUICCert(ip.To4().String(), "853")
				if err == nil {
					for _, fetchedCert := range certChain {
						db.AddCertificate(ip.To4().String(), "quic", 853, fetchedCert.Raw)
					}
				}
			}()
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	wg.Wait()
}

func runTLSCertificates(fileName string, parallel int64, port string) {
	file, err := os.Open(fileName)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	var sem = semaphore.NewWeighted(parallel)
	wg := sync.WaitGroup{}

	protocol := "tls"
	if port == "443" {
		protocol = "https"
	}

	portInt, err := strconv.Atoi(port)
	if err != nil {
		log.Fatal(err)
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		ip := net.ParseIP(scanner.Text())
		if ip.To4() != nil {
			sem.Acquire(context.Background(), 1)
			wg.Add(1)
			go func() {
				defer sem.Release(1)
				defer wg.Done()
				certChain, err := cert.GetTLSCert(ip, port)
				if err != nil {
					log.Println(err)
					return
				}
				for _, fetchedCert := range certChain {
					db.AddCertificate(ip.To4().String(), protocol, portInt, fetchedCert.Raw)
				}
			}()
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	wg.Wait()
}

func runTFO(fileName string, parallel int64, port int) {
	file, err := os.Open(fileName)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	var sem = semaphore.NewWeighted(parallel)
	wg := sync.WaitGroup{}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		ip := net.ParseIP(scanner.Text())
		if ip.To4() != nil {
			sem.Acquire(context.Background(), 1)
			wg.Add(1)
			go func() {
				supports, err := tcpfastopen.SupportsTFO(ip.To4().String(), port)
				if err != nil {
					log.Println(err)
					sem.Release(1)
					wg.Done()
					return
				}
				db.AddFastOpenRecord(ip.To4().String(), port, supports)
				sem.Release(1)
				wg.Done()
			}()
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	wg.Wait()
}

func main() {
	defer db.Close()
	app := &cli.App{
		Commands: []*cli.Command{
			{
				Name: "tcpfastopen",
				Usage: "Scan list for tcp fast open support",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name: "infile",
						Usage: "the files of IPs to scan",
						Required: true,
					},
					&cli.Int64Flag{
						Name: "parallel",
						Aliases: []string{"p"},
						Usage: "the number of parallel requests",
						Value: 30,
					},
				},
				Action:  func(c *cli.Context) error {
					runTFO(c.String("infile"), c.Int64("parallel"), 53)
					runTFO(c.String("infile"), c.Int64("parallel"), 853)
					runTFO(c.String("infile"), c.Int64("parallel"), 443)
					return nil
				},
			},
			{
				Name: "cert-tls",
				Usage: "Download TLS certificates for list of IPs",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name: "infile",
						Usage: "the files of IPs to scan",
						Required: true,
					},
					&cli.Int64Flag{
						Name: "parallel",
						Aliases: []string{"p"},
						Usage: "the number of parallel requests",
						Value: 30,
					},
				},
				Action:  func(c *cli.Context) error {
					runTLSCertificates(c.String("infile"), c.Int64("parallel"), "853")
					return nil
				},
			},
			{
				Name: "cert-https",
				Usage: "Download TLS certificates for list of IPs with HTTPS",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name: "infile",
						Usage: "the files of IPs to scan",
						Required: true,
					},
					&cli.Int64Flag{
						Name: "parallel",
						Aliases: []string{"p"},
						Usage: "the number of parallel requests",
						Value: 30,
					},
				},
				Action:  func(c *cli.Context) error {
					runTLSCertificates(c.String("infile"), c.Int64("parallel"), "443")
					return nil
				},
			},
			{
				Name: "cert-quic",
				Usage: "Download TLS certificates for list of IPs with QUIC",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name: "infile",
						Usage: "the files of IPs to scan",
						Required: true,
					},
					&cli.Int64Flag{
						Name: "parallel",
						Aliases: []string{"p"},
						Usage: "the number of parallel requests",
						Value: 30,
					},
					&cli.BoolFlag{
						Name: "port853",
						Usage: "only scan port 853",
						Value: false,
					},
				},
				Action:  func(c *cli.Context) error {
					runQUICCertificates(c.String("infile"), c.Int64("parallel"), c.Bool("port853"))
					return nil
				},
			},
			{
				Name: "edns",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name: "infile",
						Usage: "the files of IPs to scan",
						Required: true,
					},
					&cli.Int64Flag{
						Name: "parallel",
						Aliases: []string{"p"},
						Usage: "the number of parallel requests",
						Value: 30,
					},
				},
				Action: func(c *cli.Context) error {
					runEDNS0(c.String("infile"), c.Int64("parallel"))
					return nil
				},
			},
			{
				Name: "0rtt",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name: "infile",
						Usage: "the files of IPs to scan",
						Required: true,
					},
					&cli.Int64Flag{
						Name: "parallel",
						Aliases: []string{"p"},
						Usage: "the number of parallel requests",
						Value: 30,
					},
					&cli.BoolFlag{
						Name: "port853",
						Usage: "only scan port 853",
						Value: false,
					},
				},
				Action: func(c *cli.Context) error {
					if c.Bool("port853") {
						run0RTT(c.String("infile"), c.Int64("parallel"), 853)
					} else {
						run0RTT(c.String("infile"), c.Int64("parallel"), 784)
						run0RTT(c.String("infile"), c.Int64("parallel"), 8853)
						run0RTT(c.String("infile"), c.Int64("parallel"), 853)
					}
					return nil
				},
			},
			{
				Name: "quic-version",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name: "infile",
						Usage: "the files of IPs to scan",
						Required: true,
					},
					&cli.Int64Flag{
						Name: "parallel",
						Aliases: []string{"p"},
						Usage: "the number of parallel requests",
						Value: 30,
					},
					&cli.BoolFlag{
						Name: "port853",
						Usage: "only scan port 853",
						Value: false,
					},
				},
				Action: func(c *cli.Context) error {
					if c.Bool("port853") {
						runQVersion(c.String("infile"), c.Int64("parallel"), 853)
					} else {
						runQVersion(c.String("infile"), c.Int64("parallel"), 853)
						runQVersion(c.String("infile"), c.Int64("parallel"), 784)
						runQVersion(c.String("infile"), c.Int64("parallel"), 8853)
					}
					return nil
				},
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}


