package tls

import (
	"crypto/rand"
	"net"
	"reflect"
	"testing"

	"github.com/metacubex/tls"
	utls "github.com/metacubex/utls"
	"golang.org/x/crypto/cryptobyte"
)

// clientHelloSummary extracts only the stable, structurally meaningful fields
// from a built ClientHello. Random bytes, session IDs, key-share public
// values, GREASE, and ECH ciphertexts are deliberately excluded so the test
// does not depend on random handshake values.
func clientHelloSummary(uConn *UConn) summary {
	hello := uConn.HandshakeState.Hello

	alpn := []string(nil)
	var groups []utls.CurveID
	var keyShareGroups []utls.CurveID
	var signatureSchemes []utls.SignatureScheme
	for _, extension := range uConn.Extensions {
		switch extension := extension.(type) {
		case *utls.ALPNExtension:
			alpn = extension.AlpnProtocols
		case *utls.SupportedCurvesExtension:
			groups = extension.Curves
		case *utls.KeyShareExtension:
			for _, share := range extension.KeyShares {
				keyShareGroups = append(keyShareGroups, share.Group)
			}
		case *utls.SignatureAlgorithmsExtension:
			signatureSchemes = extension.SupportedSignatureAlgorithms
		}
	}

	return summary{
		versions:         append([]uint16(nil), hello.SupportedVersions...),
		cipherSuites:     append([]uint16(nil), hello.CipherSuites...),
		supportedGroups:  append([]utls.CurveID(nil), groups...),
		keyShareGroups:   keyShareGroups,
		signatureSchemes: signatureSchemes,
		alpn:             alpn,
	}
}

type summary struct {
	versions         []uint16
	cipherSuites     []uint16
	supportedGroups  []utls.CurveID
	keyShareGroups   []utls.CurveID
	signatureSchemes []utls.SignatureScheme
	alpn             []string
}

func TestChromeClientHelloSummary(t *testing.T) {
	cases := []struct {
		name       string
		config     *utls.Config
		echList    []byte
		mutate     func(*UConn) error
		wantALPN   []string
		wantECH    bool
		wantNoECH  bool
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
				ServerName: "example.com",
				NextProtos: []string{"h2", "http/1.1"},
			},
			echList:  genECHConfigList(t),
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

			source := toStdConfig(tc.config)
			if tc.echList != nil {
				source.EncryptedClientHelloConfigList = tc.echList
			}
			uConfig := UConfig(source)
			// The adapter must copy the ECH list into the uTLS config, and must
			// never modify the caller's source config.
			if !reflect.DeepEqual(source.EncryptedClientHelloConfigList, tc.echList) {
				t.Fatalf("source ECH config mutated: %x, want %x", source.EncryptedClientHelloConfigList, tc.echList)
			}
			if tc.wantECH && !reflect.DeepEqual(uConfig.EncryptedClientHelloConfigList, tc.echList) {
				t.Fatalf("uTLS ECH config = %x, want %x", uConfig.EncryptedClientHelloConfigList, tc.echList)
			}

			uConn := UClient(client, uConfig, utls.HelloChrome_Auto)
			if err := uConn.BuildHandshakeState(); err != nil {
				t.Fatalf("BuildHandshakeState: %v", err)
			}
			if tc.mutate != nil {
				if err := tc.mutate(uConn); err != nil {
					t.Fatalf("mutate: %v", err)
				}
			}

			got := clientHelloSummary(uConn)
			if got.versions == nil {
				t.Fatal("no supported versions extracted")
			}
			if !contains(got.versions, uint16(utls.VersionTLS13)) {
				t.Fatalf("TLS 1.3 not offered: %v", got.versions)
			}
			if !reflect.DeepEqual(got.alpn, tc.wantALPN) {
				t.Fatalf("ALPN = %v, want %v", got.alpn, tc.wantALPN)
			}
			if tc.wantNoECH && len(uConfig.EncryptedClientHelloConfigList) > 0 {
				t.Fatal("unexpected ECH config list in the uTLS config")
			}
		})
	}
}

func toStdConfig(config *utls.Config) *tls.Config {
	return &tls.Config{
		ServerName: config.ServerName,
		NextProtos: config.NextProtos,
	}
}

// genECHConfigList builds a structurally valid ECHConfigList for the ECH
// test case. It must not import the ech package: ech imports component/tls,
// and a test in package tls importing it would create an import cycle.
// The list format matches what the uTLS ECH client parses: a uint16
// length-prefixed ECHConfig carrying version 0xfe0d, an X25519 public key,
// one cipher suite, and a public name.
func genECHConfigList(t *testing.T) []byte {
	t.Helper()
	publicKey := make([]byte, 32)
	if _, err := rand.Read(publicKey); err != nil {
		t.Fatalf("rand: %v", err)
	}
	builder := cryptobyte.NewBuilder(nil)
	builder.AddUint16LengthPrefixed(func(builder *cryptobyte.Builder) {
		builder.AddUint16(0xfe0d) // ECHConfig version
		builder.AddUint16LengthPrefixed(func(builder *cryptobyte.Builder) {
			builder.AddUint8(0)       // config_id
			builder.AddUint16(0x0020) // DHKEM_X25519_HKDF_SHA256
			builder.AddUint16LengthPrefixed(func(builder *cryptobyte.Builder) {
				builder.AddBytes(publicKey)
			})
			builder.AddUint16LengthPrefixed(func(builder *cryptobyte.Builder) {
				builder.AddUint16(0x0001) // KDF_HKDF_SHA256
				builder.AddUint16(0x0001) // AEAD_AES_128_GCM
			})
			builder.AddUint8(0) // maximum_name_length
			builder.AddUint8LengthPrefixed(func(builder *cryptobyte.Builder) {
				builder.AddBytes([]byte("example.com"))
			})
			builder.AddUint16(0) // extensions
		})
	})
	return builder.BytesOrPanic()
}

func contains(values []uint16, target uint16) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
