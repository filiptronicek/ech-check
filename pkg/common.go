package pkg

import (
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
	req, err := http.NewRequest(
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

	var echConfigList []byte

	r, _, err := c.Exchange(m, net.JoinHostPort(config.Servers[0], config.Port))
	if r == nil {
		slog.Warn("DNS error", "err", err)
	} else if r.Rcode != dns.RcodeSuccess {
		slog.Warn("DNS invalid answer", "domain", domain, "rcode", r.Rcode)
	} else {
		for _, a := range r.Answer {
			if a.Header().Rrtype == dns.TypeHTTPS {
				// Parse and extract the ECH config
				echValue, err := ExtractECH(a.String())
				if err != nil {
					slog.Debug("Failed to extract ECH value", "err", err)
					break
				}

				slog.Debug("ECH Value", "value", echValue)
				echConfigListBase64 := echValue
				echConfigList, err = base64.StdEncoding.DecodeString(echConfigListBase64)
				if err != nil {
					slog.Error("Failed to decode ECH config", "err", err)
					break
				}

				break
			}
		}
	}

	tlsConfig := &tls.Config{
		CurvePreferences:               []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521},
		EncryptedClientHelloConfigList: echConfigList,
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return err, DomainResult{
			Domain:     domain,
			HasECH:     false,
			HasKyber:   false,
			Accessible: false,
		}
	}
	defer resp.Body.Close()

	// Get the connection state to check what was negotiated
	if resp.TLS != nil {
		usedKex := resp.TLS.CurveID
		return nil, DomainResult{
			Domain:     domain,
			HasECH:     resp.TLS.ECHAccepted,
			HasKyber:   usedKex == tls.X25519MLKEM768,
			Accessible: true,
		}
	}

	return nil, DomainResult{
		Domain:     domain,
		HasECH:     false,
		HasKyber:   false,
		Accessible: true,
	}
}
