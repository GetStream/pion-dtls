// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	dtlsstate "github.com/pion/dtls/v4/internal/state"
	"github.com/pion/dtls/v4/pkg/crypto/elliptic"
	"github.com/pion/dtls/v4/pkg/crypto/selfsign"
	"github.com/pion/dtls/v4/pkg/protocol"
	extension13 "github.com/pion/dtls/v4/pkg/protocol/extension/dtls13"
	"github.com/pion/dtls/v4/pkg/protocol/handshake"
	"github.com/pion/dtls/v4/pkg/protocol/recordlayer"
	"github.com/pion/transport/v5/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests cover the DTLS profile WebRTC endpoints use against browsers:
// a DTLS 1.2 and 1.3 dual stack, no cookie exchange on ICE-authenticated
// paths, certificate fingerprints instead of chains, use_srtp and the
// EXTRACTOR-dtls_srtp exporter.

const srtpExporterLabel = "EXTRACTOR-dtls_srtp"

var errFingerprintMismatch = errors.New("peer certificate fingerprint mismatch")

// wireLog records the datagrams one endpoint writes.
type wireLog struct {
	mu        sync.Mutex
	datagrams [][]byte
}

func (w *wireLog) record(raw []byte) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.datagrams = append(w.datagrams, bytes.Clone(raw))
}

// handshakeMessages returns the plaintext (epoch 0) handshake fragments
// written so far, in order.
func (w *wireLog) handshakeMessages() []plaintextHandshake {
	w.mu.Lock()
	defer w.mu.Unlock()

	var out []plaintextHandshake
	for _, datagram := range w.datagrams {
		out = append(out, plaintextHandshakes(datagram)...)
	}

	return out
}

func (w *wireLog) count(match func(plaintextHandshake) bool) int {
	n := 0
	for _, message := range w.handshakeMessages() {
		if match(message) {
			n++
		}
	}

	return n
}

type plaintextHandshake struct {
	header handshake.Header
	body   []byte
}

func plaintextHandshakes(datagram []byte) []plaintextHandshake {
	records, err := recordlayer.UnpackDatagram(datagram, recordlayer.UnpackDatagramConfig{TargetVersion: protocol.Version1_3})
	if err != nil {
		return nil
	}
	var out []plaintextHandshake
	for _, raw := range records {
		record, parseErr := recordlayer.ParseRecord(raw, 0)
		if parseErr != nil || record.IsUnified() || record.Epoch() != 0 || record.ContentType() != protocol.ContentTypeHandshake {
			continue
		}
		payload := record.Payload()
		var header handshake.Header
		if header.Unmarshal(payload) != nil || len(payload) < handshake.HeaderLength+int(header.FragmentLength) {
			continue
		}
		out = append(out, plaintextHandshake{header: header, body: payload[handshake.HeaderLength : handshake.HeaderLength+int(header.FragmentLength)]})
	}

	return out
}

// serverHelloRandom returns the random of a complete ServerHello fragment.
func (m plaintextHandshake) serverHelloRandom() ([]byte, bool) {
	if m.header.Type != handshake.TypeServerHello || m.header.FragmentOffset != 0 || len(m.body) < 2+handshake.RandomLength {
		return nil, false
	}

	return m.body[2 : 2+handshake.RandomLength], true
}

func isHelloRetryRequest(m plaintextHandshake) bool {
	random, ok := m.serverHelloRandom()

	return ok && bytes.Equal(random, handshake.HelloRetryRequestRandom())
}

func isHelloVerifyRequest(m plaintextHandshake) bool {
	return m.header.Type == handshake.TypeHelloVerifyRequest
}

func isServerHello(m plaintextHandshake) bool {
	_, ok := m.serverHelloRandom()

	return ok && !isHelloRetryRequest(m)
}

// hasDowngradeSentinel reports whether a ServerHello random ends with one of
// the RFC 8446 Section 4.1.3 downgrade sentinels ("DOWNGRD" + 0x01 or 0x00).
func hasDowngradeSentinel(random []byte) bool {
	tail := random[len(random)-8:]

	return bytes.Equal(tail[:7], []byte("DOWNGRD")) && (tail[7] == 0x00 || tail[7] == 0x01)
}

type webRTCPair struct {
	client, server       *Conn
	clientWire           *wireLog
	serverWire           *wireLog
	clientCert           tls.Certificate
	serverCert           tls.Certificate
	clientErr, serverErr error
}

// fingerprintVerifier checks the peer's leaf certificate against a SHA-256
// fingerprint, the way WebRTC checks a=fingerprint.
func fingerprintVerifier(cert tls.Certificate) func([][]byte, [][]*x509.Certificate) error {
	want := sha256.Sum256(cert.Certificate[0])

	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 || sha256.Sum256(rawCerts[0]) != want {
			return errFingerprintMismatch
		}

		return nil
	}
}

// runWebRTCPair runs a handshake with mutual certificate authentication and
// fingerprint verification in both directions, recording both sides' wire.
func runWebRTCPair(t *testing.T, clientOpts []ClientOption, serverOpts []ServerOption) webRTCPair {
	t.Helper()

	clientCert, err := selfsign.GenerateSelfSigned()
	require.NoError(t, err)
	serverCert, err := selfsign.GenerateSelfSigned()
	require.NoError(t, err)

	pair := webRTCPair{clientWire: &wireLog{}, serverWire: &wireLog{}, clientCert: clientCert, serverCert: serverCert}
	ca, cb := packetPipe()
	clientConn := &connWithCallback{packetTestConn: ca, onWrite: pair.clientWire.record}
	serverConn := &connWithCallback{packetTestConn: cb, onWrite: pair.serverWire.record}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	clientOpts = append([]ClientOption{
		WithCertificates(clientCert),
		WithInsecureSkipVerify(true),
		WithVerifyPeerCertificate(fingerprintVerifier(serverCert)),
	}, clientOpts...)
	serverOpts = append([]ServerOption{
		WithCertificates(serverCert),
		WithClientAuth(RequireAnyClientCert),
		WithInsecureSkipVerify(true),
		WithVerifyPeerCertificate(fingerprintVerifier(clientCert)),
	}, serverOpts...)

	pair.client, err = Client(clientConn, clientConn.RemoteAddr(), clientOpts...)
	require.NoError(t, err)
	pair.server, err = Server(serverConn, serverConn.RemoteAddr(), serverOpts...)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = pair.client.Close()
		_ = pair.server.Close()
	})

	clientDone := make(chan error, 1)
	go func() { clientDone <- pair.client.HandshakeContext(ctx) }()
	pair.serverErr = pair.server.HandshakeContext(ctx)
	if pair.serverErr != nil {
		_ = pair.client.Close()
	}
	pair.clientErr = <-clientDone

	return pair
}

func negotiatedVersion(t *testing.T, conn *Conn) protocol.Version {
	t.Helper()

	state, ok := conn.ConnectionState()
	require.True(t, ok)

	return state.NegotiatedVersion()
}

// withKeyShares keeps only the key shares for the given groups in the first
// ClientHello, the way BoringSSL (Chrome) offers shares for a subset of its
// supported_groups. A retried ClientHello, which carries one share for the
// group the server asked for, is left alone.
func withKeyShares(supported []elliptic.Curve, shares ...elliptic.Curve) ClientOption {
	return WithClientHelloMessageHook(func(clientHello handshake.MessageClientHello) handshake.Message {
		for i, ext := range clientHello.Extensions {
			keyShare, ok := ext.(*extension13.ClientKeyShare)
			if !ok || len(keyShare.Shares) != len(supported) {
				continue
			}
			kept := make([]extension13.KeyShareEntry, 0, len(shares))
			for _, share := range keyShare.Shares {
				if slices.Contains(shares, share.Group) {
					kept = append(kept, share)
				}
			}
			extensions := slices.Clone(clientHello.Extensions)
			extensions[i] = &extension13.ClientKeyShare{Shares: kept}
			clientHello.Extensions = extensions
		}

		return &clientHello
	})
}

func TestDTLS13ServerSkipsHelloRetryRequestForOfferedKeyShare(t *testing.T) {
	defer test.CheckRoutines(t)()

	var (
		mlkem  = elliptic.X25519MLKEM768
		x25519 = elliptic.X25519
		p256   = elliptic.P256
		p384   = elliptic.P384
	)
	// Chrome's supported_groups and key shares with post-quantum key
	// agreement on (Chrome 149+ rollout) and off.
	chromePQ := []elliptic.Curve{mlkem, x25519, p256, p384}
	chromeClassic := []elliptic.Curve{x25519, p256, p384}
	preferX25519 := []elliptic.Curve{x25519, mlkem, p256, p384}
	preferMLKEM := []elliptic.Curve{mlkem, x25519, p256, p384}

	for _, tc := range []struct {
		name         string
		clientGroups []elliptic.Curve
		clientShares []elliptic.Curve
		serverGroups []elliptic.Curve
		wantGroup    elliptic.Curve
		wantHRR      int
	}{
		{name: "PQ client, server prefers X25519", clientGroups: chromePQ, clientShares: []elliptic.Curve{mlkem, x25519}, serverGroups: preferX25519, wantGroup: x25519},
		{name: "PQ client, server prefers X25519MLKEM768", clientGroups: chromePQ, clientShares: []elliptic.Curve{mlkem, x25519}, serverGroups: preferMLKEM, wantGroup: mlkem},
		{name: "classic client, server prefers X25519", clientGroups: chromeClassic, clientShares: []elliptic.Curve{x25519}, serverGroups: preferX25519, wantGroup: x25519},
		{name: "classic client, server prefers X25519MLKEM768", clientGroups: chromeClassic, clientShares: []elliptic.Curve{x25519}, serverGroups: preferMLKEM, wantGroup: x25519},
		{name: "server's first group has no share", clientGroups: []elliptic.Curve{p256, x25519}, clientShares: []elliptic.Curve{x25519}, serverGroups: []elliptic.Curve{p256, x25519}, wantGroup: x25519},
		{name: "only a post-quantum share", clientGroups: []elliptic.Curve{mlkem, x25519}, clientShares: []elliptic.Curve{mlkem}, serverGroups: preferX25519, wantGroup: mlkem},
		// Controls: no acceptable share, so the server must ask for one.
		{name: "no acceptable share", clientGroups: []elliptic.Curve{x25519, p256}, clientShares: []elliptic.Curve{x25519}, serverGroups: []elliptic.Curve{p256}, wantGroup: p256, wantHRR: 1},
		// A classical share does not stand in for a preferred post-quantum
		// group the client supports: no downgrade to save a round trip.
		{name: "post-quantum supported but not shared", clientGroups: []elliptic.Curve{mlkem, x25519}, clientShares: []elliptic.Curve{x25519}, serverGroups: preferMLKEM, wantGroup: mlkem, wantHRR: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pair := runWebRTCPair(t,
				[]ClientOption{
					WithMinVersion(protocol.Version1_2),
					WithMaxVersion(protocol.Version1_3),
					WithEllipticCurves(tc.clientGroups...),
					withKeyShares(tc.clientGroups, tc.clientShares...),
				},
				[]ServerOption{
					WithMinVersion(protocol.Version1_2),
					WithMaxVersion(protocol.Version1_3),
					WithEllipticCurves(tc.serverGroups...),
					WithInsecureSkipVerifyHello(true),
				},
			)
			require.NoError(t, pair.clientErr)
			require.NoError(t, pair.serverErr)

			assert.Equal(t, protocol.Version1_3, negotiatedVersion(t, pair.server))
			assert.Equal(t, tc.wantHRR, pair.serverWire.count(isHelloRetryRequest))
			assert.Equal(t, 1, pair.serverWire.count(isServerHello))
			serverState, ok := pair.server.state.(*dtlsstate.State13)
			require.True(t, ok)
			assert.Equal(t, tc.wantGroup, serverState.SelectedGroup)
			clientState, ok := pair.client.state.(*dtlsstate.State13)
			require.True(t, ok)
			assert.Equal(t, tc.wantGroup, clientState.SelectedGroup)
		})
	}
}

func TestInsecureSkipVerifyHelloSendsNoCookieExchange(t *testing.T) {
	defer test.CheckRoutines(t)()

	v12, v13 := protocol.Version1_2, protocol.Version1_3
	for _, tc := range []struct {
		name                   string
		clientMin, clientMax   protocol.Version
		serverMin, serverMax   protocol.Version
		skip                   bool
		wantVersion            protocol.Version
		wantHVR, wantCookieHRR int
	}{
		{name: "1.2 client, dual-stack server", clientMin: v12, clientMax: v12, serverMin: v12, serverMax: v13, skip: true, wantVersion: v12},
		{name: "dual-stack client, dual-stack server", clientMin: v12, clientMax: v13, serverMin: v12, serverMax: v13, skip: true, wantVersion: v13},
		{name: "1.2 only", clientMin: v12, clientMax: v12, serverMin: v12, serverMax: v12, skip: true, wantVersion: v12},
		{name: "1.3 only", clientMin: v13, clientMax: v13, serverMin: v13, serverMax: v13, skip: true, wantVersion: v13},
		// Controls: without the option the cookie exchange happens, which
		// shows the wire checks above can see it.
		{name: "cookie on, 1.2 client, dual-stack server", clientMin: v12, clientMax: v12, serverMin: v12, serverMax: v13, wantVersion: v12, wantHVR: 1},
		{name: "cookie on, dual-stack client, dual-stack server", clientMin: v12, clientMax: v13, serverMin: v12, serverMax: v13, wantVersion: v13, wantCookieHRR: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pair := runWebRTCPair(t,
				[]ClientOption{WithMinVersion(tc.clientMin), WithMaxVersion(tc.clientMax)},
				[]ServerOption{WithMinVersion(tc.serverMin), WithMaxVersion(tc.serverMax), WithInsecureSkipVerifyHello(tc.skip)},
			)
			require.NoError(t, pair.clientErr)
			require.NoError(t, pair.serverErr)

			assert.Equal(t, tc.wantVersion, negotiatedVersion(t, pair.client))
			assert.Equal(t, tc.wantVersion, negotiatedVersion(t, pair.server))
			assert.Equal(t, tc.wantHVR, pair.serverWire.count(isHelloVerifyRequest))
			assert.Equal(t, tc.wantCookieHRR, pair.serverWire.count(isHelloRetryRequest))
			assert.Equal(t, 1, pair.serverWire.count(isServerHello))
		})
	}
}

// TestDualStackVersionFallback checks that a server and client configured
// for DTLS 1.2 to 1.3 negotiate 1.3 with each other and 1.2 with a
// 1.2-only peer, and that no RFC 8446 downgrade sentinel is written: a
// browser that offered 1.3 aborts on a 1.2 ServerHello carrying one.
func TestDualStackVersionFallback(t *testing.T) {
	defer test.CheckRoutines(t)()

	v12, v13 := protocol.Version1_2, protocol.Version1_3
	for _, tc := range []struct {
		name                 string
		clientMin, clientMax protocol.Version
		serverMin, serverMax protocol.Version
		wantVersion          protocol.Version
	}{
		{name: "dual-stack peers", clientMin: v12, clientMax: v13, serverMin: v12, serverMax: v13, wantVersion: v13},
		{name: "1.2-only client", clientMin: v12, clientMax: v12, serverMin: v12, serverMax: v13, wantVersion: v12},
		{name: "1.2-only server", clientMin: v12, clientMax: v13, serverMin: v12, serverMax: v12, wantVersion: v12},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pair := runWebRTCPair(t,
				[]ClientOption{WithMinVersion(tc.clientMin), WithMaxVersion(tc.clientMax)},
				[]ServerOption{WithMinVersion(tc.serverMin), WithMaxVersion(tc.serverMax), WithInsecureSkipVerifyHello(true)},
			)
			require.NoError(t, pair.clientErr)
			require.NoError(t, pair.serverErr)

			assert.Equal(t, tc.wantVersion, negotiatedVersion(t, pair.client))
			assert.Equal(t, tc.wantVersion, negotiatedVersion(t, pair.server))
			serverHellos := 0
			for _, message := range pair.serverWire.handshakeMessages() {
				if random, ok := message.serverHelloRandom(); ok && !isHelloRetryRequest(message) {
					serverHellos++
					assert.False(t, hasDowngradeSentinel(random), "ServerHello random %x carries a downgrade sentinel", random)
				}
			}
			assert.Equal(t, 1, serverHellos)
		})
	}
}

func TestSRTPExporterMatchesOnBothEnds(t *testing.T) {
	defer test.CheckRoutines(t)()

	for _, version := range []struct {
		name  string
		value protocol.Version
	}{{name: "DTLS12", value: protocol.Version1_2}, {name: "DTLS13", value: protocol.Version1_3}} {
		for _, profile := range []struct {
			name   string
			value  SRTPProtectionProfile
			length int // 2 * (master key + master salt)
		}{
			{name: "AEAD_AES_128_GCM", value: SRTP_AEAD_AES_128_GCM, length: 2 * (16 + 12)},
			{name: "AEAD_AES_256_GCM", value: SRTP_AEAD_AES_256_GCM, length: 2 * (32 + 12)},
			{name: "AES128_CM_HMAC_SHA1_80", value: SRTP_AES128_CM_HMAC_SHA1_80, length: 2 * (16 + 14)},
		} {
			t.Run(version.name+"/"+profile.name, func(t *testing.T) {
				pair := runWebRTCPair(t,
					[]ClientOption{
						WithMinVersion(protocol.Version1_2),
						WithMaxVersion(version.value),
						WithSRTPProtectionProfiles(SRTP_AEAD_AES_128_GCM, SRTP_AEAD_AES_256_GCM, SRTP_AES128_CM_HMAC_SHA1_80),
					},
					[]ServerOption{
						WithMinVersion(protocol.Version1_2),
						WithMaxVersion(protocol.Version1_3),
						WithInsecureSkipVerifyHello(true),
						WithSRTPProtectionProfiles(profile.value),
					},
				)
				require.NoError(t, pair.clientErr)
				require.NoError(t, pair.serverErr)
				require.Equal(t, version.value, negotiatedVersion(t, pair.client))

				clientProfile, ok := pair.client.SelectedSRTPProtectionProfile()
				require.True(t, ok)
				assert.Equal(t, profile.value, clientProfile)
				serverProfile, ok := pair.server.SelectedSRTPProtectionProfile()
				require.True(t, ok)
				assert.Equal(t, profile.value, serverProfile)

				clientState, ok := pair.client.ConnectionState()
				require.True(t, ok)
				serverState, ok := pair.server.ConnectionState()
				require.True(t, ok)
				clientKeys, err := clientState.ExportKeyingMaterial(srtpExporterLabel, nil, profile.length)
				require.NoError(t, err)
				serverKeys, err := serverState.ExportKeyingMaterial(srtpExporterLabel, nil, profile.length)
				require.NoError(t, err)
				assert.Len(t, clientKeys, profile.length)
				assert.Equal(t, clientKeys, serverKeys)
				assert.NotEqual(t, make([]byte, profile.length), clientKeys)
			})
		}
	}
}
