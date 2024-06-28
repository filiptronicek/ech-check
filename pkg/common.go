package pkg

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/miekg/dns"
)

type DomainResult struct {
	Domain     string
	HasECH     bool
	HasKyber   bool
	Accessible bool
}

// CheckKyberSupport checks if the domain supports Kyber and/or ECH.
func CheckKyberSupport(domain string) (error, DomainResult) {
	var usedKex tls.CurveID
	req, err := http.NewRequestWithContext(
		context.WithValue(
			context.Background(),
			tls.CFEventHandlerContextKey{},
			func(ev tls.CFEvent) {
				switch e := ev.(type) {
				case tls.CFEventTLS13NegotiatedKEX:
					usedKex = e.KEX
				}
			},
		),
		"GET",
		"https://"+domain,
		nil,
	)
	if err != nil {
		return err, DomainResult{
			Domain:     domain,
			HasECH:     false,
			HasKyber:   false,
			Accessible: false,
		}
	}

	config, _ := dns.ClientConfigFromFile("/etc/resolv.conf")
	c := new(dns.Client)

	existsMsg := new(dns.Msg)
	existsMsg.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	existsMsg.RecursionDesired = true

	_, _, err = c.Exchange(existsMsg, net.JoinHostPort(config.Servers[0], config.Port))
	if err != nil {
		return err, DomainResult{
			Domain:     domain,
			HasECH:     false,
			HasKyber:   false,
			Accessible: false,
		}
	}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeHTTPS)
	m.RecursionDesired = true

	var echConfigList []tls.ECHConfig
	useECH := false

	r, _, err := c.Exchange(m, net.JoinHostPort(config.Servers[0], config.Port))
	if r == nil {
		slog.Warn("DNS: error: %s\n", err.Error())
	} else if r.Rcode != dns.RcodeSuccess {
		slog.Warn("DNS: invalid answer name %s after MX query for %s\n", domain, domain)
	} else {
		for _, a := range r.Answer {
			if a.Header().Rrtype == dns.TypeHTTPS {
				// Parse and extract the ECH config
				echValue, err := ExtractECH(a.String())
				if err != nil {
					slog.Debug("Failed to extract ECH value", "err", err)
					break
				}

				slog.Debug("ECH Value:", echValue)
				echConfigListBase64 := echValue
				useECH = true
				echConfigListBtyes, err := base64.StdEncoding.DecodeString(echConfigListBase64)
				if err != nil {
					slog.Error("Failed to decode ECH config", "err", err)
					break
				}

				echConfigList, err = tls.UnmarshalECHConfigs(echConfigListBtyes)
				if err != nil {
					slog.Error("Failed to unmarshal ECH config", "err", err)
					break
				}

				break
			}
		}
	}

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{
		CurvePreferences: []tls.CurveID{tls.X25519Kyber768Draft00, tls.X25519Kyber512Draft00, tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521},
		ECHEnabled:       useECH,
		ClientECHConfigs: echConfigList,
	}

	if _, err = (&http.Client{Timeout: 5 * time.Second}).Do(req); err != nil {
		return err, DomainResult{
			Domain:     domain,
			HasECH:     useECH,
			HasKyber:   false,
			Accessible: false,
		}
	}

	return nil, DomainResult{
		Domain:     domain,
		HasECH:     useECH,
		HasKyber:   usedKex == tls.X25519Kyber768Draft00 || usedKex == tls.X25519Kyber512Draft00,
		Accessible: true,
	}
}
