package tls

import (
	"encoding/base64"
	"net"
	"reflect"
	"testing"

	"github.com/metacubex/mihomo/component/ech"

	"github.com/metacubex/tls"
	utls "github.com/metacubex/utls"
)

// clientHelloSummary extracts only the stable, structurally meaningful fields
// from a built ClientHello. Random bytes, session IDs, key-share public
// values, GREASE, and ECH ciphertexts are deliberately excluded so the test
// does not depend on random handshake values.
func clientHelloSummary(hello *utls.PubClientHelloMsg) summary {
	extensions := make([]uint16, 0, len(hello.Extensions))
	for _, extension := range hello.Extensions {
		extensions = append(extensions, uint16(extension.Type()))
	}

	var alpn []string
	if extension := findExtension[*utls.ALPNExtension](hello); extension != nil {
		alpn = extension.AlpnProtocols
	}

	var groups []utls.CurveID
	if extension := findExtension[*utls.SupportedCurvesExtension](hello); extension != nil {
		groups = extension.Curves
	}

	var keyShareGroups []utls.CurveID
	if extension := findExtension[*utls.KeyShareExtension](hello); extension != nil {
		for _, share := range extension.KeyShares {
			keyShareGroups = append(keyShareGroups, share.Group)
		}
	}

	var signatureSchemes []utls.SignatureScheme
	if extension := findExtension[*utls.SignatureAlgorithmsExtension](hello); extension != nil {
		signatureSchemes = extension.SupportedSignatureAlgorithms
	}

	return summary{
		versions:          append([]uint16(nil), hello.SupportedVersions...),
		cipherSuites:      append([]uint16(nil), hello.CipherSuites...),
		extensions:        extensions,
		supportedGroups:   append([]utls.CurveID(nil), groups...),
		keyShareGroups:    keyShareGroups,
		signatureSchemes:  signatureSchemes,
		alpn:              alpn,
		echConfigListSeen: findExtension[*utls.ECHGREASEAndDeprecatedExtension](hello) != nil,
	}
}

func findExtension[T any](hello *utls.PubClientHelloMsg) T {
	var zero T
	for _, extension := range hello.Extensions {
		if typed, ok := extension.(T); ok {
			return typed
		}
	}
	return zero
}

type summary struct {
	versions          []uint16
	cipherSuites      []uint16
	extensions        []uint16
	supportedGroups   []utls.CurveID
	keyShareGroups    []utls.CurveID
	signatureSchemes  []utls.SignatureScheme
	alpn              []string
	echConfigListSeen bool
}

func TestChromeClientHelloSummary(t *testing.T) {
	cases := []struct {
		name      string
		config    *utls.Config
		mutate    func(*UConn) error
		wantALPN  []string
		wantECH   bool
		wantNoECH bool
	}{
		{
			name: "chrome_https",
			config: &utls.Config{
				ServerName: "example.com",
				NextProtos: []string{"h2", "http/1.1"},
			},
			wantALPN: []string{"h2", "http/1.1"},
		},
		{
			name: "chrome_websocket",
			config: &utls.Config{
				ServerName: "example.com",
				NextProtos: []string{"h2", "http/1.1"},
			},
			mutate:   func(uConn *UConn) error { return BuildWebsocketHandshakeState(uConn) },
			wantALPN: []string{"http/1.1"},
		},
		{
			name: "chrome_ech",
			config: &utls.Config{
				ServerName:             "example.com",
				NextProtos:             []string{"h2", "http/1.1"},
				EncryptedClientHelloConfigList: genECHConfigList(t),
			},
			wantALPN: []string{"h2", "http/1.1"},
			wantECH:  true,
		},
		{
			name: "chrome120_no_mlkem",
			config: &utls.Config{
				ServerName: "example.com",
				NextProtos: []string{"h2", "http/1.1"},
			},
			mutate: func(uConn *UConn) error {
				return BuildRemovedX25519MLKEM768HandshakeState(uConn)
			},
			wantALPN: []string{"h2", "http/1.1"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()

			uConfig := UConfig(toStdConfig(tc.config))
			uConn := UClient(client, uConfig, utls.HelloChrome_Auto)
			if err := uConn.BuildHandshakeState(); err != nil {
				t.Fatalf("BuildHandshakeState: %v", err)
			}
			if tc.mutate != nil {
				if err := tc.mutate(uConn); err != nil {
					t.Fatalf("mutate: %v", err)
				}
			}

			got := clientHelloSummary(uConn.HandshakeState.Hello)
			if got.versions == nil {
				t.Fatal("no supported versions extracted")
			}
			if !contains(got.versions, uint16(utls.VersionTLS13)) {
				t.Fatalf("TLS 1.3 not offered: %v", got.versions)
			}
			if !reflect.DeepEqual(got.alpn, tc.wantALPN) {
				t.Fatalf("ALPN = %v, want %v", got.alpn, tc.wantALPN)
			}
			if tc.wantECH && !got.echConfigListSeen {
				t.Fatal("ECH config supplied but no ECH extension in the ClientHello")
			}
			if tc.wantNoECH && got.echConfigListSeen {
				t.Fatal("unexpected ECH extension in the ClientHello")
			}
		})
	}
}

func toStdConfig(config *utls.Config) *tls.Config {
	return &tls.Config{
		ServerName:                     config.ServerName,
		NextProtos:                     config.NextProtos,
		EncryptedClientHelloConfigList: config.EncryptedClientHelloConfigList,
	}
}

func genECHConfigList(t *testing.T) []byte {
	t.Helper()
	configBase64, _, err := ech.GenECHConfig("example.com")
	if err != nil {
		t.Fatalf("GenECHConfig: %v", err)
	}
	echConfigList, err := base64Decode(configBase64)
	if err != nil {
		t.Fatalf("decode ECH config: %v", err)
	}
	return echConfigList
}

func contains(values []uint16, target uint16) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func base64Decode(value string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(value)
}
