// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"crypto/tls"
	"errors"
	"net"
	"testing"

	dtlserrors "github.com/pion/dtls/v4/internal/errors"
	"github.com/pion/dtls/v4/pkg/crypto/selfsign"
	"github.com/pion/dtls/v4/pkg/protocol"
	"github.com/stretchr/testify/require"
)

// detachedPeer is one end of a detached handshake driven by the test, with
// every event it produced in order.
type detachedPeer struct {
	conn   *DetachedConn
	addr   net.Addr
	events []DetachedEventKind
	// exporterAtServerFinished is the SRTP exporter read when the server
	// reported DetachedServerFinishedSent.
	exporterAtServerFinished []byte
	profileAtServerFinished  SRTPProtectionProfile
	closedErr                error
	// inFlight holds datagrams the peer wrote and the test has not delivered.
	inFlight [][]byte
}

// collect drains the peer's events, queueing its datagrams for the other side.
func (p *detachedPeer) collect(t *testing.T) {
	t.Helper()
	for event := p.conn.NextEvent(); event.Kind != DetachedNoEvent; event = p.conn.NextEvent() {
		p.events = append(p.events, event.Kind)
		switch event.Kind {
		case DetachedWriteDatagrams:
			p.inFlight = append(p.inFlight, event.Datagrams...)
		case DetachedServerFinishedSent:
			state, ok := p.conn.ConnectionState()
			require.True(t, ok)
			exporter, err := state.ExportKeyingMaterial(srtpExporterLabel, nil, 2*(16+14))
			require.NoError(t, err)
			p.exporterAtServerFinished = exporter
			p.profileAtServerFinished, ok = p.conn.SelectedSRTPProtectionProfile()
			require.True(t, ok)
		case DetachedClosed:
			p.closedErr = event.Err
		case DetachedApplicationData, DetachedHandshakeDone, DetachedNoEvent:
		}
	}
}

// deliver hands everything from has queued to the other side, one datagram per
// HandleDatagram call, and returns the event kinds the receiver produced during
// each call.
func deliver(t *testing.T, from, to *detachedPeer) [][]DetachedEventKind {
	t.Helper()
	var perCall [][]DetachedEventKind
	datagrams := from.inFlight
	from.inFlight = nil
	for _, datagram := range datagrams {
		before := len(to.events)
		if err := to.conn.HandleDatagram(datagram, from.addr); err != nil {
			to.collect(t)

			return perCall
		}
		to.collect(t)
		perCall = append(perCall, append([]DetachedEventKind(nil), to.events[before:]...))
	}

	return perCall
}

func (p *detachedPeer) count(kind DetachedEventKind) int {
	n := 0
	for _, k := range p.events {
		if k == kind {
			n++
		}
	}

	return n
}

func (p *detachedPeer) index(kind DetachedEventKind) int {
	for i, k := range p.events {
		if k == kind {
			return i
		}
	}

	return -1
}

type detachedPairConfig struct {
	minVersion, maxVersion protocol.Version
	// serverMaxVersion, when set, is the server's maximum instead of maxVersion.
	serverMaxVersion protocol.Version
	// clientCert is the certificate the client presents; the server accepts
	// only acceptedClientCert.
	clientCert, acceptedClientCert tls.Certificate
}

func newDetachedPair(t *testing.T, cfg detachedPairConfig) (client, server *detachedPeer) {
	t.Helper()
	serverCert, err := selfsign.GenerateSelfSigned()
	require.NoError(t, err)
	clientAddr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 4444}
	serverAddr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 2), Port: 5555}

	clientConn, err := DetachedClient(serverAddr,
		WithCertificates(cfg.clientCert),
		WithInsecureSkipVerify(true),
		WithVerifyPeerCertificate(fingerprintVerifier(serverCert)),
		WithSRTPProtectionProfiles(SRTP_AEAD_AES_128_GCM),
		WithMinVersion(cfg.minVersion),
		WithMaxVersion(cfg.maxVersion),
	)
	require.NoError(t, err)
	serverMax := cfg.maxVersion
	if cfg.serverMaxVersion != 0 {
		serverMax = cfg.serverMaxVersion
	}
	serverConn, err := DetachedServer(clientAddr,
		WithCertificates(serverCert),
		WithClientAuth(RequireAnyClientCert),
		WithInsecureSkipVerify(true),
		WithInsecureSkipVerifyHello(true),
		WithVerifyPeerCertificate(fingerprintVerifier(cfg.acceptedClientCert)),
		WithSRTPProtectionProfiles(SRTP_AEAD_AES_128_GCM),
		WithMinVersion(cfg.minVersion),
		WithMaxVersion(serverMax),
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})
	client = &detachedPeer{conn: clientConn, addr: clientAddr}
	server = &detachedPeer{conn: serverConn, addr: serverAddr}
	require.NoError(t, client.conn.Start(t.Context()))
	client.collect(t)
	require.NoError(t, server.conn.Start(t.Context()))
	server.collect(t)

	return client, server
}

// runDetachedPair delivers datagrams both ways until neither side has any left.
func runDetachedPair(t *testing.T, client, server *detachedPeer) {
	t.Helper()
	for range 32 {
		if len(client.inFlight) == 0 && len(server.inFlight) == 0 {
			return
		}
		deliver(t, client, server)
		deliver(t, server, client)
	}
	t.Fatal("handshake did not settle")
}

func TestDetachedServerFinishedSent(t *testing.T) {
	clientCert, err := selfsign.GenerateSelfSigned()
	require.NoError(t, err)

	t.Run("DTLS 1.3 server, once, after its flight and before the client is verified", func(t *testing.T) {
		client, server := newDetachedPair(t, detachedPairConfig{
			minVersion: protocol.Version1_3, maxVersion: protocol.Version1_3,
			clientCert: clientCert, acceptedClientCert: clientCert,
		})

		// The server's flight and the event come out of the HandleDatagram call
		// that completes the ClientHello, flight first.
		perCall := deliver(t, client, server)
		require.NotEmpty(t, perCall)
		last := perCall[len(perCall)-1]
		require.Equal(t, []DetachedEventKind{DetachedWriteDatagrams, DetachedServerFinishedSent}, last)
		for _, call := range perCall[:len(perCall)-1] {
			require.NotContains(t, call, DetachedServerFinishedSent)
		}
		_, err := server.conn.Write([]byte("early"))
		require.ErrorIs(t, err, dtlserrors.ErrHandshakeInProgress, "DTLS application data still waits for the client's Finished")

		runDetachedPair(t, client, server)
		require.Equal(t, 1, server.count(DetachedServerFinishedSent))
		require.Equal(t, 1, server.count(DetachedHandshakeDone))
		require.Less(t, server.index(DetachedServerFinishedSent), server.index(DetachedHandshakeDone))
		require.Zero(t, client.count(DetachedServerFinishedSent), "clients never report it")

		// The keys at the event are the keys of the completed handshake, on both ends.
		serverState, ok := server.conn.ConnectionState()
		require.True(t, ok)
		require.Equal(t, protocol.Version1_3, serverState.NegotiatedVersion())
		after, err := serverState.ExportKeyingMaterial(srtpExporterLabel, nil, 2*(16+14))
		require.NoError(t, err)
		require.Equal(t, after, server.exporterAtServerFinished)
		clientState, ok := client.conn.ConnectionState()
		require.True(t, ok)
		clientExporter, err := clientState.ExportKeyingMaterial(srtpExporterLabel, nil, 2*(16+14))
		require.NoError(t, err)
		require.Equal(t, clientExporter, server.exporterAtServerFinished)
		profile, ok := server.conn.SelectedSRTPProtectionProfile()
		require.True(t, ok)
		require.Equal(t, profile, server.profileAtServerFinished)
	})

	t.Run("not after a retransmitted ClientHello", func(t *testing.T) {
		client, server := newDetachedPair(t, detachedPairConfig{
			minVersion: protocol.Version1_3, maxVersion: protocol.Version1_3,
			clientCert: clientCert, acceptedClientCert: clientCert,
		})
		clientHello := append([][]byte(nil), client.inFlight...)
		deliver(t, client, server)
		client.inFlight = clientHello
		deliver(t, client, server)
		runDetachedPair(t, client, server)
		require.Equal(t, 1, server.count(DetachedServerFinishedSent))
	})

	t.Run("a client the server rejects ends in DetachedClosed after the event", func(t *testing.T) {
		otherCert, err := selfsign.GenerateSelfSigned()
		require.NoError(t, err)
		client, server := newDetachedPair(t, detachedPairConfig{
			minVersion: protocol.Version1_3, maxVersion: protocol.Version1_3,
			clientCert: clientCert, acceptedClientCert: otherCert,
		})
		runDetachedPair(t, client, server)
		require.Equal(t, 1, server.count(DetachedServerFinishedSent))
		require.Zero(t, server.count(DetachedHandshakeDone))
		require.Equal(t, 1, server.count(DetachedClosed))
		require.Less(t, server.index(DetachedServerFinishedSent), server.index(DetachedClosed))
		require.True(t, errors.Is(server.closedErr, errFingerprintMismatch), "closed with %v", server.closedErr)
	})

	for _, tc := range []struct {
		name      string
		serverMax protocol.Version
	}{
		{"never for DTLS 1.2", protocol.Version1_2},
		{"never for a dual-stack server that negotiates DTLS 1.2", protocol.Version1_3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, server := newDetachedPair(t, detachedPairConfig{
				minVersion: protocol.Version1_2, maxVersion: protocol.Version1_2, serverMaxVersion: tc.serverMax,
				clientCert: clientCert, acceptedClientCert: clientCert,
			})
			runDetachedPair(t, client, server)
			require.Equal(t, 1, server.count(DetachedHandshakeDone))
			state, ok := server.conn.ConnectionState()
			require.True(t, ok)
			require.Equal(t, protocol.Version1_2, state.NegotiatedVersion())
			require.Zero(t, server.count(DetachedServerFinishedSent))
			require.Zero(t, client.count(DetachedServerFinishedSent))
		})
	}
}
