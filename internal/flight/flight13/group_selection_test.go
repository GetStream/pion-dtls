// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package flight13

import (
	"testing"

	dtlsconfig "github.com/pion/dtls/v4/internal/config"
	dtlsstate "github.com/pion/dtls/v4/internal/state"
	"github.com/pion/dtls/v4/pkg/crypto/elliptic"
	extension13 "github.com/pion/dtls/v4/pkg/protocol/extension/dtls13"
	"github.com/stretchr/testify/assert"
)

func TestPreferredClientGroup(t *testing.T) {
	var (
		mlkem  = elliptic.X25519MLKEM768
		x25519 = elliptic.X25519
		p256   = elliptic.P256
		p384   = elliptic.P384
	)
	chromePQ := []elliptic.Curve{mlkem, x25519, p256, p384}
	chromeClassic := []elliptic.Curve{x25519, p256, p384}

	for _, test := range []struct {
		name          string
		serverGroups  []elliptic.Curve
		clientGroups  []elliptic.Curve
		clientShares  []elliptic.Curve
		noKeyShareExt bool
		wantGroup     elliptic.Curve
		wantNoGroup   bool
		wantShare     bool
	}{
		{
			name:         "PQ client, server prefers X25519",
			serverGroups: []elliptic.Curve{x25519, mlkem, p256, p384},
			clientGroups: chromePQ, clientShares: []elliptic.Curve{mlkem, x25519},
			wantGroup: x25519, wantShare: true,
		},
		{
			name:         "PQ client, server prefers X25519MLKEM768",
			serverGroups: []elliptic.Curve{mlkem, x25519, p256, p384},
			clientGroups: chromePQ, clientShares: []elliptic.Curve{mlkem, x25519},
			wantGroup: mlkem, wantShare: true,
		},
		{
			name:         "classic client, server prefers X25519MLKEM768",
			serverGroups: []elliptic.Curve{mlkem, x25519, p256, p384},
			clientGroups: chromeClassic, clientShares: []elliptic.Curve{x25519},
			wantGroup: x25519, wantShare: true,
		},
		{
			name:         "classic client, server prefers X25519",
			serverGroups: []elliptic.Curve{x25519, mlkem, p256, p384},
			clientGroups: chromeClassic, clientShares: []elliptic.Curve{x25519},
			wantGroup: x25519, wantShare: true,
		},
		{
			name:         "server preferred group has no share",
			serverGroups: []elliptic.Curve{p256, x25519},
			clientGroups: []elliptic.Curve{p256, x25519}, clientShares: []elliptic.Curve{x25519},
			wantGroup: x25519, wantShare: true,
		},
		{
			name:         "post-quantum preferred, only classical share",
			serverGroups: []elliptic.Curve{mlkem, x25519},
			clientGroups: []elliptic.Curve{mlkem, x25519}, clientShares: []elliptic.Curve{x25519},
			wantGroup: mlkem,
		},
		{
			name:         "classical preferred, only post-quantum share",
			serverGroups: []elliptic.Curve{x25519, mlkem},
			clientGroups: []elliptic.Curve{mlkem, x25519}, clientShares: []elliptic.Curve{mlkem},
			wantGroup: mlkem, wantShare: true,
		},
		{
			name:         "no acceptable share needs retry",
			serverGroups: []elliptic.Curve{p384, p256},
			clientGroups: chromeClassic, clientShares: []elliptic.Curve{x25519},
			wantGroup: p384,
		},
		{
			name:         "share outside supported_groups is ignored",
			serverGroups: []elliptic.Curve{x25519, p256},
			clientGroups: []elliptic.Curve{p256}, clientShares: []elliptic.Curve{x25519},
			wantGroup: p256,
		},
		{
			name:         "empty key_share needs retry",
			serverGroups: []elliptic.Curve{x25519, p256},
			clientGroups: []elliptic.Curve{p256, x25519},
			wantGroup:    x25519,
		},
		{
			name:         "no key_share extension",
			serverGroups: []elliptic.Curve{x25519, p256},
			clientGroups: []elliptic.Curve{p256, x25519}, noKeyShareExt: true,
			wantGroup: x25519,
		},
		{
			name:         "no common group",
			serverGroups: []elliptic.Curve{p384},
			clientGroups: []elliptic.Curve{x25519}, clientShares: []elliptic.Curve{x25519},
			wantNoGroup: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			state := &dtlsstate.State13{
				Common:              &dtlsstate.Common{},
				RemoteGroups:        test.clientGroups,
				HasRemoteKeyEntries: !test.noKeyShareExt,
			}
			for _, group := range test.clientShares {
				state.RemoteKeyEntries = append(state.RemoteKeyEntries, extension13.KeyShareEntry{Group: group, KeyExchange: []byte{1}})
			}
			cfg := &dtlsconfig.HandshakeConfig{EllipticCurves: test.serverGroups}

			group, ok := preferredClientGroup(state, cfg)
			if test.wantNoGroup {
				assert.False(t, ok)

				return
			}
			assert.True(t, ok)
			assert.Equal(t, test.wantGroup, group)
			_, hasShare := matchingClientKeyShare(state, cfg)
			assert.Equal(t, test.wantShare, hasShare)
		})
	}
}
