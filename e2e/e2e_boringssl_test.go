// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build boringssl && !js

// Interop tests against BoringSSL's bssl_shim for the DTLS profile WebRTC
// uses with Chrome: a DTLS 1.2 and 1.3 dual stack, mutual authentication
// with self-signed ECDSA P-256 certificates checked by fingerprint, use_srtp
// and the EXTRACTOR-dtls_srtp exporter, post-quantum key shares in a
// fragmented ClientHello, and the fallback to a DTLS 1.2-only peer.
//
// Build bssl_shim at the revision pion/dtls-interop pins (needs cmake,
// ninja, a C++ compiler, perl and go):
//
//	git init boringssl && cd boringssl
//	git fetch --depth=1 https://github.com/google/boringssl.git \
//	  79a292fdae25c074f19e6ec53a9b0c465051be91
//	git checkout FETCH_HEAD
//	cmake -S . -B build -GNinja -DCMAKE_BUILD_TYPE=Release
//	ninja -C build bssl_shim
//
// and run:
//
//	DTLS_INTEROP_BSSL_SHIM_BIN=$PWD/build/ssl/test/bssl_shim \
//	  go test -tags boringssl -run BoringSSL ./e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pion/dtls/v4"
	"github.com/pion/dtls/v4/pkg/crypto/elliptic"
	"github.com/pion/dtls/v4/pkg/crypto/selfsign"
	"github.com/pion/dtls/v4/pkg/protocol"
	"github.com/pion/dtls/v4/pkg/protocol/handshake"
	"github.com/pion/dtls/v4/pkg/protocol/recordlayer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	bsslShimEnv       = "DTLS_INTEROP_BSSL_SHIM_BIN"
	bsslShimID        = uint64(1)
	bsslPacketOpcode  = byte('P')
	bsslTimeoutACK    = byte('t')
	bsslMTU           = 1200 // libwebrtc's DTLS MTU
	srtpExporterLabel = "EXTRACTOR-dtls_srtp"
	pionPayload       = "pion to boringssl"
)

var errBSSLFingerprint = errors.New("peer certificate fingerprint mismatch")

// bsslPacketConn carries datagrams over the shim's TCP socket using
// BoringSSL's packeted BIO framing ('P', 32-bit length, datagram) and logs
// the datagrams in both directions.
type bsslPacketConn struct {
	net.Conn

	mu       sync.Mutex
	written  [][]byte
	received [][]byte
}

func (c *bsslPacketConn) ReadFrom(payload []byte) (int, net.Addr, error) {
	for {
		var opcode [1]byte
		if _, err := io.ReadFull(c.Conn, opcode[:]); err != nil {
			return 0, nil, err
		}
		if opcode[0] == bsslTimeoutACK {
			continue
		}
		if opcode[0] != bsslPacketOpcode {
			return 0, nil, fmt.Errorf("unexpected packeted BIO opcode %q", opcode[0]) //nolint:err113
		}
		var size [4]byte
		if _, err := io.ReadFull(c.Conn, size[:]); err != nil {
			return 0, nil, err
		}
		datagram := make([]byte, binary.BigEndian.Uint32(size[:]))
		if _, err := io.ReadFull(c.Conn, datagram); err != nil {
			return 0, nil, err
		}
		c.mu.Lock()
		c.received = append(c.received, datagram)
		c.mu.Unlock()

		return copy(payload, datagram), c.RemoteAddr(), nil
	}
}

func (c *bsslPacketConn) WriteTo(payload []byte, _ net.Addr) (int, error) {
	frame := make([]byte, 5+len(payload))
	frame[0] = bsslPacketOpcode
	binary.BigEndian.PutUint32(frame[1:5], uint32(len(payload))) //nolint:gosec
	copy(frame[5:], payload)

	c.mu.Lock()
	defer c.mu.Unlock()
	if _, err := c.Conn.Write(frame); err != nil {
		return 0, err
	}
	c.written = append(c.written, bytes.Clone(payload))

	return len(payload), nil
}

// plaintextHandshakes returns the epoch 0 handshake fragments in datagrams.
func plaintextHandshakes(datagrams [][]byte) []bsslHandshakeFragment {
	var out []bsslHandshakeFragment
	for _, datagram := range datagrams {
		records, err := recordlayer.UnpackDatagram(datagram, recordlayer.UnpackDatagramConfig{TargetVersion: protocol.Version1_3})
		if err != nil {
			continue
		}
		for _, raw := range records {
			record, err := recordlayer.ParseRecord(raw, 0)
			if err != nil || record.IsUnified() || record.Epoch() != 0 || record.ContentType() != protocol.ContentTypeHandshake {
				continue
			}
			var header handshake.Header
			payload := record.Payload()
			if header.Unmarshal(payload) != nil || len(payload) < handshake.HeaderLength+int(header.FragmentLength) {
				continue
			}
			out = append(out, bsslHandshakeFragment{header: header, body: payload[handshake.HeaderLength:]})
		}
	}

	return out
}

// lockedBuffer collects the shim's output while the test reads it.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.String()
}

type bsslHandshakeFragment struct {
	header handshake.Header
	body   []byte
}

func (f bsslHandshakeFragment) isHelloRetryRequest() bool {
	return f.header.Type == handshake.TypeServerHello && f.header.FragmentOffset == 0 && len(f.body) >= 2+handshake.RandomLength &&
		bytes.Equal(f.body[2:2+handshake.RandomLength], handshake.HelloRetryRequestRandom())
}

// bsslCase is one WebRTC-shaped handshake between Pion and bssl_shim. Both
// sides authenticate with self-signed ECDSA P-256 certificates, negotiate
// use_srtp and export SRTP keying material, which must match.
type bsslCase struct {
	name string
	// bssl_shim's version range.
	shimMin, shimMax protocol.Version
	shimGroups       []elliptic.Curve
	pionMaxVersion   protocol.Version
	pionGroups       []elliptic.Curve
	srtpProfile      dtls.SRTPProtectionProfile
	wantVersion      protocol.Version
	wantGroup        elliptic.Curve // key exchange group, DTLS 1.3 only
	// Expect the ClientHello to be split into more than one fragment.
	wantFragmentedClientHello bool
	// Run only with Pion as the server.
	pionServerOnly bool
}

// bsslSRTPProfile returns BoringSSL's name for an SRTP profile and the
// length of its keying material: 2 * (master key + master salt).
func bsslSRTPProfile(profile dtls.SRTPProtectionProfile) (string, int) {
	switch profile { //nolint:exhaustive
	case dtls.SRTP_AEAD_AES_128_GCM:
		return "SRTP_AEAD_AES_128_GCM", 56
	case dtls.SRTP_AES128_CM_HMAC_SHA1_80:
		return "SRTP_AES128_CM_SHA1_80", 60
	default:
		return "", 0
	}
}

func TestBoringSSLWebRTCProfile(t *testing.T) {
	shim := os.Getenv(bsslShimEnv)
	if shim == "" {
		t.Skipf("%s is not set", bsslShimEnv)
	}

	var (
		v12, v13 = protocol.Version1_2, protocol.Version1_3
		mlkem    = elliptic.X25519MLKEM768
		x25519   = elliptic.X25519
		p256     = elliptic.P256
		p384     = elliptic.P384
	)
	// Chrome's groups with post-quantum key agreement on and off.
	chromePQ := []elliptic.Curve{mlkem, x25519, p256, p384}
	chromeClassic := []elliptic.Curve{x25519, p256, p384}

	cases := []bsslCase{
		{
			name:    "DTLS13/SRTP_AEAD_AES_128_GCM",
			shimMin: v12, shimMax: v13, shimGroups: chromeClassic,
			pionMaxVersion: v13, pionGroups: chromeClassic,
			srtpProfile: dtls.SRTP_AEAD_AES_128_GCM, wantVersion: v13, wantGroup: x25519,
		},
		{
			name:    "DTLS13/SRTP_AES128_CM_SHA1_80",
			shimMin: v12, shimMax: v13, shimGroups: chromeClassic,
			pionMaxVersion: v13, pionGroups: chromeClassic,
			srtpProfile: dtls.SRTP_AES128_CM_HMAC_SHA1_80, wantVersion: v13, wantGroup: x25519,
		},
		{
			name:    "DTLS13/PostQuantumFragmentedClientHello/PreferX25519MLKEM768",
			shimMin: v12, shimMax: v13, shimGroups: chromePQ,
			pionMaxVersion: v13, pionGroups: chromePQ,
			srtpProfile: dtls.SRTP_AEAD_AES_128_GCM, wantVersion: v13, wantGroup: mlkem,
			wantFragmentedClientHello: true,
		},
		{
			// Pion as server takes BoringSSL's X25519 share; as client it
			// lists X25519 first, and BoringSSL follows the client's order.
			name:    "DTLS13/PostQuantumFragmentedClientHello/PreferX25519",
			shimMin: v12, shimMax: v13, shimGroups: chromePQ,
			pionMaxVersion: v13, pionGroups: []elliptic.Curve{x25519, mlkem, p256, p384},
			srtpProfile: dtls.SRTP_AEAD_AES_128_GCM, wantVersion: v13, wantGroup: x25519,
			wantFragmentedClientHello: true,
		},
		{
			// Pion prefers P-256 but BoringSSL only sent an X25519 share:
			// take the share instead of asking for P-256.
			name:    "DTLS13/KeyShareOverServerPreference",
			shimMin: v12, shimMax: v13, shimGroups: chromeClassic,
			pionMaxVersion: v13, pionGroups: []elliptic.Curve{p256, x25519},
			srtpProfile: dtls.SRTP_AEAD_AES_128_GCM, wantVersion: v13, wantGroup: x25519,
			pionServerOnly: true,
		},
		{
			name:    "DTLS12Fallback/SRTP_AEAD_AES_128_GCM",
			shimMin: v12, shimMax: v12, shimGroups: chromeClassic,
			pionMaxVersion: v13, pionGroups: chromeClassic,
			srtpProfile: dtls.SRTP_AEAD_AES_128_GCM, wantVersion: v12,
		},
		{
			name:    "DTLS12Fallback/SRTP_AES128_CM_SHA1_80",
			shimMin: v12, shimMax: v12, shimGroups: chromeClassic,
			pionMaxVersion: v13, pionGroups: chromeClassic,
			srtpProfile: dtls.SRTP_AES128_CM_HMAC_SHA1_80, wantVersion: v12,
		},
		{
			// A 1.3-capable BoringSSL client aborts on a 1.2 ServerHello
			// carrying the RFC 8446 downgrade sentinel. A Pion that is
			// configured for 1.2 only must not send one.
			name:    "DTLS12OnlyPion",
			shimMin: v12, shimMax: v13, shimGroups: chromePQ,
			pionMaxVersion: v12, pionGroups: chromeClassic,
			srtpProfile: dtls.SRTP_AEAD_AES_128_GCM, wantVersion: v12,
			// A 1.2-only Pion client never offers 1.3; nothing to add.
			pionServerOnly: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Run("PionServer_BoringSSLClient", func(t *testing.T) {
				runBoringSSLCase(t, shim, tc, false)
			})
			if tc.pionServerOnly {
				return
			}
			t.Run("PionClient_BoringSSLServer", func(t *testing.T) {
				runBoringSSLCase(t, shim, tc, true)
			})
		})
	}
}

//nolint:cyclop,maintidx
func runBoringSSLCase(t *testing.T, shim string, tc bsslCase, pionIsClient bool) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	dir := t.TempDir()
	shimCert, shimCertPath, shimKeyPath := writeBoringSSLCertificate(t, dir, "shim")
	pionCert, pionCertPath, _ := writeBoringSSLCertificate(t, dir, "pion")
	profileName, keyingLength := bsslSRTPProfile(tc.srtpProfile)
	require.NotZero(t, keyingLength)

	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = listener.Close() }()
	port := listener.Addr().(*net.TCPAddr).Port //nolint:forcetypeassert

	args := []string{
		"-port", strconv.Itoa(port),
		"-shim-id", strconv.FormatUint(bsslShimID, 10),
		"-dtls",
		"-mtu", strconv.Itoa(bsslMTU),
		"-min-version", strconv.Itoa(int(tc.shimMin)),
		"-max-version", strconv.Itoa(int(tc.shimMax)),
		"-expect-version", strconv.Itoa(int(tc.wantVersion)),
		"-cert-file", shimCertPath,
		"-key-file", shimKeyPath,
		"-expect-peer-cert-file", pionCertPath,
		"-srtp-profiles", profileName,
		"-export-keying-material", strconv.Itoa(keyingLength),
		"-export-label", srtpExporterLabel,
		"-no-ticket",
	}
	for _, group := range tc.shimGroups {
		args = append(args, "-curves", strconv.Itoa(int(group)))
	}
	if pionIsClient {
		args = append(args, "-server", "-require-any-client-certificate")
	} else if tc.wantVersion == protocol.Version1_2 {
		// Pion's DTLS 1.2 server sends no session ID, so there is no
		// session to resume. WebRTC does not resume sessions.
		args = append(args, "-expect-no-session")
	}
	if tc.wantVersion == protocol.Version1_3 {
		args = append(args, "-expect-no-hrr", "-expect-curve-id", strconv.Itoa(int(tc.wantGroup)))
	}

	var stderr, stdout lockedBuffer
	cmd := exec.CommandContext(ctx, shim, args...) //nolint:gosec
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	require.NoError(t, cmd.Start())
	waitDone := make(chan error, 1)
	go func() { waitDone <- cmd.Wait() }()
	shimOutput := func() string {
		return fmt.Sprintf("bssl_shim %s\nstdout: %s\nstderr: %s", strings.Join(args, " "), stdout.String(), stderr.String())
	}
	defer func() {
		cancel()
		<-waitDone
	}()

	tcpConn, err := listener.Accept()
	require.NoError(t, err, shimOutput())
	var id [8]byte
	_, err = io.ReadFull(tcpConn, id[:])
	require.NoError(t, err)
	require.Equal(t, bsslShimID, binary.LittleEndian.Uint64(id[:]))
	packetConn := &bsslPacketConn{Conn: tcpConn}

	opts := []dtls.Option{
		dtls.WithCertificates(pionCert),
		dtls.WithInsecureSkipVerify(true),
		dtls.WithVerifyPeerCertificate(func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 || sha256.Sum256(rawCerts[0]) != sha256.Sum256(shimCert.Certificate[0]) {
				return errBSSLFingerprint
			}

			return nil
		}),
		dtls.WithMinVersion(protocol.Version1_2),
		dtls.WithMaxVersion(tc.pionMaxVersion),
		dtls.WithEllipticCurves(tc.pionGroups...),
		dtls.WithSRTPProtectionProfiles(tc.srtpProfile),
		dtls.WithMTU(bsslMTU),
	}
	var conn *dtls.Conn
	if pionIsClient {
		conn, err = dtls.Client(packetConn, packetConn.RemoteAddr(), toClientOptions(opts)...)
	} else {
		serverOpts := toServerOptions(opts)
		serverOpts = append(serverOpts, dtls.WithClientAuth(dtls.RequireAnyClientCert), dtls.WithInsecureSkipVerifyHello(true))
		conn, err = dtls.Server(packetConn, packetConn.RemoteAddr(), serverOpts...)
	}
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	require.NoError(t, conn.HandshakeContext(ctx), shimOutput())
	require.NoError(t, conn.SetDeadline(time.Now().Add(10*time.Second)))

	state, ok := conn.ConnectionState()
	require.True(t, ok)
	assert.Equal(t, tc.wantVersion, state.NegotiatedVersion())
	require.NotEmpty(t, state.PeerCertificates)
	assert.Equal(t, shimCert.Certificate[0], state.PeerCertificates[0])
	selected, ok := conn.SelectedSRTPProtectionProfile()
	require.True(t, ok)
	assert.Equal(t, tc.srtpProfile, selected)

	// bssl_shim writes its exporter output as the first application record.
	shimKeys := make([]byte, keyingLength)
	_, err = io.ReadFull(conn, shimKeys)
	require.NoError(t, err, shimOutput())
	pionKeys, err := state.ExportKeyingMaterial(srtpExporterLabel, nil, keyingLength)
	require.NoError(t, err)
	assert.Equal(t, shimKeys, pionKeys, "SRTP keying material differs")

	// bssl_shim echoes application data with every bit flipped.
	_, err = conn.Write([]byte(pionPayload))
	require.NoError(t, err)
	echo := make([]byte, len(pionPayload))
	_, err = io.ReadFull(conn, echo)
	require.NoError(t, err, shimOutput())
	for i := range echo {
		echo[i] ^= 0xff
	}
	assert.Equal(t, pionPayload, string(echo))

	packetConn.mu.Lock()
	written, received := packetConn.written, packetConn.received
	packetConn.mu.Unlock()
	clientHelloDatagrams := received
	if pionIsClient {
		clientHelloDatagrams = written
	}
	clientHelloFragments := 0
	for _, fragment := range plaintextHandshakes(clientHelloDatagrams) {
		if fragment.header.Type == handshake.TypeClientHello && fragment.header.MessageSequence == 0 {
			clientHelloFragments++
		}
	}
	if tc.wantFragmentedClientHello {
		assert.Greater(t, clientHelloFragments, 1, "ClientHello was not fragmented")
	}
	if !pionIsClient {
		for _, fragment := range plaintextHandshakes(written) {
			assert.False(t, fragment.isHelloRetryRequest(), "Pion sent a HelloRetryRequest")
			assert.NotEqual(t, handshake.TypeHelloVerifyRequest, fragment.header.Type, "Pion sent a HelloVerifyRequest")
		}
	}

	// close_notify ends the shim's read loop; it exits 0 only if every
	// -expect flag held.
	require.NoError(t, conn.Close())
	select {
	case err = <-waitDone:
		waitDone <- err
		require.NoError(t, err, shimOutput())
	case <-ctx.Done():
		require.Fail(t, "bssl_shim did not exit", shimOutput())
	}
	t.Logf("negotiated %#04x, group %s, ClientHello in %d fragment(s)", uint16(tc.wantVersion), tc.wantGroup, clientHelloFragments)
}

func writeBoringSSLCertificate(t *testing.T, dir, name string) (tls.Certificate, string, string) {
	t.Helper()

	cert, err := selfsign.GenerateSelfSigned() // ECDSA P-256
	require.NoError(t, err)
	key, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	require.NoError(t, err)
	certPath := filepath.Join(dir, name+"-cert.pem")
	keyPath := filepath.Join(dir, name+"-key.pem")
	require.NoError(t, os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0o600))
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0o600))

	return cert, certPath, keyPath
}

func toClientOptions(opts []dtls.Option) []dtls.ClientOption {
	out := make([]dtls.ClientOption, 0, len(opts))
	for _, opt := range opts {
		out = append(out, opt)
	}

	return out
}

func toServerOptions(opts []dtls.Option) []dtls.ServerOption {
	out := make([]dtls.ServerOption, 0, len(opts))
	for _, opt := range opts {
		out = append(out, opt)
	}

	return out
}
