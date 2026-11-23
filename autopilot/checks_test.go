package autopilot

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestTargetScope(t *testing.T) {
	for _, target := range []string{"http://example.com", "https://example.com/private", "https://user:pass@example.com", "https://example.com?secret=1", "https://example.com:8080", "https://127.0.0.1", "https://[::1]", "https://10.0.0.1", "https://169.254.169.254", "https://100.100.100.200", "https://metadata.internal", "https://foo.local", "https://example.com./", "https://[64:ff9b::7f00:1]", "https://[::ffff:127.0.0.1]", "https://example.com/#fragment"} {
		t.Run(target, func(t *testing.T) {
			if got, err := NormalizeTarget(target); err == nil {
				t.Fatalf("accepted out of scope target: %s", got)
			}
		})
	}
	got, err := NormalizeTarget("https://EXAMPLE.com:443/")
	if err != nil || got != "https://example.com/" {
		t.Fatalf("canonical origin: %s %v", got, err)
	}
}
func TestPublicAddress(t *testing.T) {
	for _, raw := range []string{"127.0.0.1", "10.0.0.1", "169.254.169.254", "0.0.0.0", "192.0.2.1", "198.18.0.1", "100.64.0.1", "::1", "::", "fc00::1", "fe80::1", "::ffff:10.0.0.1", "64:ff9b::a00:1", "2002:7f00:1::", "2001:db8::1"} {
		if PublicAddress(netip.MustParseAddr(raw)) {
			t.Errorf("reserved address accepted: %s", raw)
		}
	}
	for _, raw := range []string{"93.184.216.34", "2606:4700:4700::1111"} {
		if !PublicAddress(netip.MustParseAddr(raw)) {
			t.Errorf("public address rejected: %s", raw)
		}
	}
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func publicDNS(context.Context, string, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
}
func fixtureClient(t *testing.T, code int, calls *int, headers http.Header) clientFactory {
	t.Helper()
	return func(host string, ip netip.Addr) *http.Client {
		if host != "example.com" || ip.String() != "93.184.216.34" {
			t.Fatalf("wrong pin %s %s", host, ip)
		}
		client := pinnedClient(host, ip)
		client.Transport = roundTrip(func(req *http.Request) (*http.Response, error) {
			*calls++
			if req.Method != "HEAD" || req.URL.String() != "https://example.com/" || req.Header.Get("Authorization") != "" {
				t.Fatal("unexpected request")
			}
			return &http.Response{StatusCode: code, Header: headers, Body: io.NopCloser(strings.NewReader("PRIVATE BODY NEVER STORED")), Request: req, TLS: &tls.ConnectionState{Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{{NotAfter: time.Now().Add(90 * 24 * time.Hour)}}}}, nil
		})
		return client
	}
}
func TestAuditOneRequestNoRedirectNoSecrets(t *testing.T) {
	for _, code := range []int{200, 302, 429, 503} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			calls := 0
			report := run(context.Background(), "https://example.com", func() bool { return true }, publicDNS, fixtureClient(t, code, &calls, http.Header{"Content-Type": {"text/html"}, "Location": {"http://127.0.0.1/private"}, "Set-Cookie": {"session=SECRET_VALUE; Path=/"}}))
			if calls != 1 || report.Requests != 1 {
				t.Fatalf("expected one bounded request: %d %+v", calls, report)
			}
			raw, _ := json.Marshal(report)
			for _, secret := range []string{"SECRET_VALUE", "PRIVATE BODY", "127.0.0.1", "session="} {
				if strings.Contains(string(raw), secret) {
					t.Fatalf("private source leaked: %s", raw)
				}
			}
			if code >= 429 && report.State != "unavailable" {
				t.Fatalf("availability incorrectly reported: %+v", report)
			}
			if code == 302 {
				for _, o := range report.Observations {
					if o.ID == "csp" && o.Status != "not_evaluated" {
						t.Fatal("redirect incorrectly audited as HTML")
					}
				}
			}
		})
	}
}
func TestMixedDNSAndRevokedAuthorizationNeverSend(t *testing.T) {
	for _, scenario := range []string{"mixed_dns", "expired_before_dns", "revoked_after_dns"} {
		t.Run(scenario, func(t *testing.T) {
			checks, lookups, calls := 0, 0, 0
			lookup := func(ctx context.Context, network, host string) ([]netip.Addr, error) {
				lookups++
				ips, _ := publicDNS(ctx, network, host)
				if scenario == "mixed_dns" {
					ips = append(ips, netip.MustParseAddr("127.0.0.1"))
				}
				return ips, nil
			}
			allowed := func() bool {
				checks++
				return scenario != "expired_before_dns" && (scenario != "revoked_after_dns" || checks == 1)
			}
			report := run(context.Background(), "https://example.com", allowed, lookup, fixtureClient(t, 200, &calls, http.Header{}))
			if calls != 0 || report.Requests != 0 || report.State == "completed" {
				t.Fatalf("request escaped scope: %+v", report)
			}
			if scenario == "expired_before_dns" && lookups != 0 {
				t.Fatal("DNS sent after expiry")
			}
		})
	}
}
func TestPinnedTransportPolicy(t *testing.T) {
	c := pinnedClient("example.com", netip.MustParseAddr("93.184.216.34"))
	tr := c.Transport.(*http.Transport)
	if tr.Proxy != nil || tr.TLSClientConfig.InsecureSkipVerify || tr.MaxResponseHeaderBytes > 32768 || !tr.DisableKeepAlives {
		t.Fatal("unbounded or unverified transport")
	}
	if c.CheckRedirect(nil, nil) != http.ErrUseLastResponse {
		t.Fatal("redirect escape")
	}
	if _, err := tr.DialContext(context.Background(), "tcp", "other.example:443"); err == nil {
		t.Fatal("hostname mismatch allowed")
	}
	if _, err := pinnedClient("example.com", netip.MustParseAddr("127.0.0.1")).Transport.(*http.Transport).DialContext(context.Background(), "tcp", "example.com:443"); err == nil {
		t.Fatal("internal IP dial allowed")
	}
}
func TestCompareRequiresPositiveEvidence(t *testing.T) {
	previous := Report{Version: Version, State: "completed", Observations: []Observation{{ID: "csp", Status: "warning"}, {ID: "hsts", Status: "warning"}, {ID: "cookies", Status: "warning"}}}
	current := Report{Version: Version, State: "completed", Observations: []Observation{{ID: "csp", Status: "not_evaluated"}, {ID: "hsts", Status: "pass"}, {ID: "cookies", Status: "warning"}, {ID: "referrer", Status: "warning"}}}
	Compare(&current, &previous)
	if !current.Compared || current.Resolved != 1 || current.Recurring != 1 || current.New != 1 {
		t.Fatalf("bad diff: %+v", current)
	}
	for _, state := range []string{"unavailable", "blocked", "canceled"} {
		r := Report{Version: Version, State: state}
		Compare(&r, &previous)
		if r.Compared || r.Resolved != 0 {
			t.Fatal("error marked as resolved")
		}
	}
	r := Report{Version: "new-rules", State: "completed"}
	Compare(&r, &previous)
	if r.Compared {
		t.Fatal("compared incompatible rules")
	}
}
func TestReviewedFingerprintAndBackoff(t *testing.T) {
	a := observation("tls_expiry", "TLS", "warning", "29 days")
	b := observation("tls_expiry", "TLS", "warning", "28 days")
	if a.Fingerprint != b.Fingerprint {
		t.Fatal("volatile evidence invalidates review")
	}
	if a.Fingerprint == observation("tls_expiry", "TLS", "pass", "90 days").Fingerprint {
		t.Fatal("verdict crosses result class")
	}
	if Backoff(3600, 1) != 2*time.Hour || Backoff(3600, 3) != 8*time.Hour || Backoff(604800, 50) != 7*24*time.Hour {
		t.Fatal("unbounded backoff")
	}
}
func TestHSTSParsing(t *testing.T) {
	for _, s := range []string{"", "max-age=0", "max-age=-1", "max-age=123garbage", "preload"} {
		if validHSTS(s) {
			t.Errorf("invalid HSTS accepted: %s", s)
		}
	}
	if !validHSTS("max-age=31536000; includeSubDomains") {
		t.Fatal("valid HSTS rejected")
	}
}

func TestAuditLearningCannotCrossOrigins(t *testing.T) {
	factory := func(host string, ip netip.Addr) *http.Client {
		c := pinnedClient(host, ip)
		c.Transport = roundTrip(func(req *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/html"}}, Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
		})
		return c
	}
	a := run(context.Background(), "https://a.example.com", func() bool { return true }, publicDNS, factory)
	b := run(context.Background(), "https://b.example.com", func() bool { return true }, publicDNS, factory)
	c := run(context.Background(), "https://a.example.com", func() bool { return true }, publicDNS, factory)
	for i, o := range a.Observations {
		if o.Fingerprint == b.Observations[i].Fingerprint {
			t.Fatal("review identity crosses origin")
		}
		if o.Fingerprint != c.Observations[i].Fingerprint {
			t.Fatal("review identity not stable for same origin")
		}
	}
	Compare(&b, &a)
	if b.Compared {
		t.Fatal("baseline crossed origin")
	}
	Compare(&c, &a)
	if !c.Compared {
		t.Fatal("same-origin baseline rejected")
	}
}
