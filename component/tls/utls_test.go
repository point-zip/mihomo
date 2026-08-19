package tls

import (
	"bytes"
	"net"
	"testing"

	"github.com/metacubex/tls"
	utls "github.com/metacubex/utls"
)

// TestUConfigCopiesECHConfigList guards the direction of the ECH config list
// copy inside UConfig. The source standard tls.Config owns the ECH data and
// must never be overwritten by the destination uTLS config.
func TestUConfigCopiesECHConfigList(t *testing.T) {
	want := []byte{1, 2, 3, 4}
	got := UConfig(&tls.Config{EncryptedClientHelloConfigList: want})
	if !bytes.Equal(got.EncryptedClientHelloConfigList, want) {
		t.Fatalf("ECH config list = %x, want %x", got.EncryptedClientHelloConfigList, want)
	}
}

// TestUConfigDoesNotMutateSourceConfig ensures the adapter never writes ECH
// data back into the caller's standard tls.Config.
func TestUConfigDoesNotMutateSourceConfig(t *testing.T) {
	source := &tls.Config{EncryptedClientHelloConfigList: []byte{9, 8, 7}}
	_ = UConfig(source)
	if !bytes.Equal(source.EncryptedClientHelloConfigList, []byte{9, 8, 7}) {
		t.Fatalf("source config mutated, got %x", source.EncryptedClientHelloConfigList)
	}
}

// TestGetFingerprint documents the contract that empty and "none" fall back to
// standard TLS, unlike Xray's GetFingerprint("") which defaults to Chrome.
func TestGetFingerprint(t *testing.T) {
	chrome, ok := GetFingerprint("chrome")
	if !ok {
		t.Fatal("GetFingerprint(chrome): not found")
	}
	if chrome != utls.HelloChrome_Auto {
		t.Fatalf("GetFingerprint(chrome) = %v, want HelloChrome_Auto", chrome)
	}

	if _, ok := GetFingerprint(""); ok {
		t.Fatal("GetFingerprint(\"\"): empty fingerprint must fall back to standard TLS")
	}
	if _, ok := GetFingerprint("none"); ok {
		t.Fatal("GetFingerprint(none): none fingerprint must fall back to standard TLS")
	}

	if _, ok := GetFingerprint("chrome120"); !ok {
		t.Fatal("GetFingerprint(chrome120): documented classical fingerprint not found")
	}
}

// TestChromeClientHelloBuild verifies structural properties of the Chrome
// ClientHello after the initial build: the hello exists, TLS 1.3 is offered,
// and the ALPN extension advertises the configured protocols. Exact bytes are
// intentionally variable (random, GREASE, uTLS version) and not asserted.
func TestChromeClientHelloBuild(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	uConn := UClient(client, &utls.Config{
		ServerName: "example.com",
		NextProtos: []string{"h2", "http/1.1"},
	}, utls.HelloChrome_Auto)
	if err := uConn.BuildHandshakeState(); err != nil {
		t.Fatalf("BuildHandshakeState: %v", err)
	}

	hello := uConn.HandshakeState.Hello
	if hello == nil {
		t.Fatal("HandshakeState.Hello is nil")
	}
	if !containsVersion(hello.SupportedVersions, utls.VersionTLS13) {
		t.Fatalf("ClientHello does not offer TLS 1.3: %v", hello.SupportedVersions)
	}
	if !equalStrings(hello.AlpnProtocols, []string{"h2", "http/1.1"}) {
		t.Fatalf("ClientHello ALPN = %v, want [h2 http/1.1]", hello.AlpnProtocols)
	}
}

// TestBuildWebsocketHandshakeState forces the outer ALPN to http/1.1, exactly
// once, regardless of what the fingerprint originally advertised.
func TestBuildWebsocketHandshakeState(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	uConn := UClient(client, &utls.Config{
		ServerName: "example.com",
		NextProtos: []string{"h2", "http/1.1"},
	}, utls.HelloChrome_Auto)
	if err := BuildWebsocketHandshakeState(uConn); err != nil {
		t.Fatalf("BuildWebsocketHandshakeState: %v", err)
	}

	hello := uConn.HandshakeState.Hello
	if hello == nil {
		t.Fatal("HandshakeState.Hello is nil")
	}
	if !equalStrings(hello.AlpnProtocols, []string{"http/1.1"}) {
		t.Fatalf("WebSocket ALPN = %v, want [http/1.1]", hello.AlpnProtocols)
	}
}

// TestBuildRemovedX25519MLKEM768HandshakeState ensures the post-quantum group
// disappears from both the supported-curves and key-share extensions.
func TestBuildRemovedX25519MLKEM768HandshakeState(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	uConn := UClient(client, &utls.Config{
		ServerName: "example.com",
		NextProtos: []string{"h2", "http/1.1"},
	}, utls.HelloChrome_Auto)
	if err := uConn.BuildHandshakeState(); err != nil {
		t.Fatalf("initial BuildHandshakeState: %v", err)
	}
	hello := uConn.HandshakeState.Hello
	if hello == nil {
		t.Fatal("HandshakeState.Hello is nil")
	}
	if !hasCurve(hello, utls.X25519MLKEM768) {
		t.Skip("current Chrome template does not include X25519MLKEM768; removal is a no-op")
	}

	if err := BuildRemovedX25519MLKEM768HandshakeState(uConn); err != nil {
		t.Fatalf("BuildRemovedX25519MLKEM768HandshakeState: %v", err)
	}
	if hasCurve(uConn.HandshakeState.Hello, utls.X25519MLKEM768) {
		t.Fatal("X25519MLKEM768 still present after removal")
	}
}

func hasCurve(hello *utls.PubClientHelloMsg, curveID utls.CurveID) bool {
	for _, supported := range hello.SupportedCurves {
		if supported == curveID {
			return true
		}
	}
	for _, share := range hello.KeyShares {
		if share.Group == curveID {
			return true
		}
	}
	return false
}

func containsVersion(versions []uint16, target uint16) bool {
	for _, version := range versions {
		if version == target {
			return true
		}
	}
	return false
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
