// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"testing"
	"time"

	"github.com/pion/dtls/v4/pkg/crypto/selfsign"
	"github.com/pion/dtls/v4/pkg/protocol"
	"github.com/stretchr/testify/require"
)

// TestDetachedReadErrorAfterHandshake delivers records that fail to decode after the
// handshake, three times each, to both ends of a detached pair. Read errors used to go to a
// channel that nothing reads in detached mode, so the second one blocked the read loop and
// HandleDatagram and Close never returned.
func TestDetachedReadErrorAfterHandshake(t *testing.T) {
	records := []struct {
		name   string
		record []byte
		// fatalIn is the version in which the receiver answers with a fatal alert, so the
		// connection ends instead of staying usable.
		fatalIn protocol.Version
	}{
		{name: "plaintext alert in epoch 1", record: []byte{21, 0xfe, 0xfd, 0x00, 0x01, 0, 0, 0, 0, 0, 1, 0x00, 0x02, 1, 0}},
		{
			name:    "plaintext application data in epoch 0",
			record:  []byte{23, 0xfe, 0xfd, 0x00, 0x00, 0, 0, 0, 0, 0, 9, 0x00, 0x02, 1, 0},
			fatalIn: protocol.Version1_2,
		},
		{name: "plaintext application data in epoch 1", record: []byte{23, 0xfe, 0xfd, 0x00, 0x01, 0, 0, 0, 0, 0, 9, 0x00, 0x02, 1, 0}},
		{name: "unified header", record: []byte{0x2c, 0x01, 0x00, 0x05, 1, 2, 3, 4, 5}},
	}
	clientCert, err := selfsign.GenerateSelfSigned()
	require.NoError(t, err)

	for _, version := range []protocol.Version{protocol.Version1_2, protocol.Version1_3} {
		for _, tc := range records {
			t.Run(versionName(version)+"/"+tc.name, func(t *testing.T) {
				client, server := newDetachedPair(t, detachedPairConfig{
					minVersion: version, maxVersion: version,
					clientCert: clientCert, acceptedClientCert: clientCert,
				})
				runDetachedPair(t, client, server)
				require.Equal(t, 1, client.count(DetachedHandshakeDone))
				require.Equal(t, 1, server.count(DetachedHandshakeDone))

				for _, peer := range []struct{ to, from *detachedPeer }{{server, client}, {client, server}} {
					done := make(chan struct{})
					go func() {
						defer close(done)
						for range 3 {
							_ = peer.to.conn.HandleDatagram(tc.record, peer.from.addr)
						}
					}()
					select {
					case <-done:
					case <-time.After(5 * time.Second):
						require.FailNow(t, "HandleDatagram blocked after a read error")
					}
					peer.to.collect(t)
				}

				if tc.fatalIn != version {
					_, err := client.conn.Write([]byte("still open"))
					require.NoError(t, err)
					client.collect(t)
					deliver(t, client, server)
					require.Equal(t, 1, server.count(DetachedApplicationData))
				}

				closed := make(chan struct{})
				go func() {
					defer close(closed)
					_ = client.conn.Close()
					_ = server.conn.Close()
				}()
				select {
				case <-closed:
				case <-time.After(5 * time.Second):
					require.FailNow(t, "Close blocked after a read error")
				}
			})
		}
	}
}

func versionName(version protocol.Version) string {
	if version == protocol.Version1_3 {
		return "DTLS1.3"
	}

	return "DTLS1.2"
}
