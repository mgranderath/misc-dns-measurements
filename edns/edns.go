package edns

import (
	"github.com/miekg/dns"
	"time"
)

func Exchange(ip string) (bool, *uint16, error) {
	req := dns.Msg{}
	req.Id = dns.Id()
	req.RecursionDesired = true
	req.Question = []dns.Question{
		{Name: "test.com" + ".", Qtype: dns.TypeTXT, Qclass: dns.ClassINET},
	}

	o := new(dns.OPT)
	o.Hdr.Name = "."
	o.Hdr.Rrtype = dns.TypeOPT

	e := new(dns.EDNS0_TCP_KEEPALIVE)
	e.Code = dns.EDNS0TCPKEEPALIVE
	e.Length = 0
	o.Option = append(o.Option, e)
	req.Extra = append(req.Extra, o)

	c := new(dns.Client)
	c.Net = "tcp"

	c.Timeout = 2 * time.Second

	in, _, err := c.Exchange(&req, ip+":53")
	if err != nil {
		return false, nil, err
	}

	if in == nil {
		return false, nil, nil
	}

	if len(in.Extra) == 0 {
		return false, nil, nil
	}

	opt := in.Extra[len(in.Extra)-1]

	if opt.Header().Rrtype != dns.TypeOPT {
		return false, nil, nil
	} else {
		optHeader := opt.(*dns.OPT)
		if optHeader.ExtendedRcode() == 0 {
			for _, v := range optHeader.Option {
				switch v := v.(type) {
				case *dns.EDNS0_TCP_KEEPALIVE:
					return true, &v.Timeout, nil
				}
			}
			return false, nil, nil
		} else {
			return false, nil, nil
		}
	}
}
