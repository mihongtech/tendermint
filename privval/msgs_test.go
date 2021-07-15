package privval

import (
	"encoding/hex"
	"github.com/mihongtech/crypto/signature"
	"testing"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/stretchr/testify/require"

	"github.com/mihongtech/crypto"
	cryptoenc "github.com/mihongtech/crypto/encoding"
	"github.com/mihongtech/crypto/tmhash"
	cryptoproto "github.com/tendermint/tendermint/proto/tendermint/crypto"
	privproto "github.com/tendermint/tendermint/proto/tendermint/privval"
	tmproto "github.com/tendermint/tendermint/proto/tendermint/types"
	"github.com/tendermint/tendermint/types"
)

var stamp = time.Date(2019, 10, 13, 16, 14, 44, 0, time.UTC)

func exampleVote() *types.Vote {
	return &types.Vote{
		Type:      tmproto.SignedMsgType(1),
		Height:    3,
		Round:     2,
		Timestamp: stamp,
		BlockID: types.BlockID{
			Hash: tmhash.Sum([]byte("blockID_hash")),
			PartSetHeader: types.PartSetHeader{
				Total: 1000000,
				Hash:  tmhash.Sum([]byte("blockID_part_set_header_hash")),
			},
		},
		ValidatorAddress: crypto.AddressHash([]byte("validator_address")),
		ValidatorIndex:   56789,
	}
}

func exampleProposal() *types.Proposal {

	return &types.Proposal{
		Type:      tmproto.SignedMsgType(1),
		Height:    3,
		Round:     2,
		Timestamp: stamp,
		POLRound:  2,
		Signature: []byte("it's a signature"),
		BlockID: types.BlockID{
			Hash: tmhash.Sum([]byte("blockID_hash")),
			PartSetHeader: types.PartSetHeader{
				Total: 1000000,
				Hash:  tmhash.Sum([]byte("blockID_part_set_header_hash")),
			},
		},
	}
}

// nolint:lll // ignore line length for tests
func TestPrivvalVectors(t *testing.T) {
	pk := signature.GenPrivKeyFromSecret([]byte("it's a secret")).PubKey()
	ppk, err := cryptoenc.PubKeyToProto(pk)
	require.NoError(t, err)

	// Generate a simple vote
	vote := exampleVote()
	votepb := vote.ToProto()

	// Generate a simple proposal
	proposal := exampleProposal()
	proposalpb := proposal.ToProto()

	// Create a Reuseable remote error
	remoteError := &privproto.RemoteSignerError{Code: 1, Description: "it's a error"}

	testCases := []struct {
		testName string
		msg      proto.Message
		expBytes string
	}{
		{"ping request", &privproto.PingRequest{}, "3a00"},
		{"ping response", &privproto.PingResponse{}, "4200"},
		{"pubKey request", &privproto.PubKeyRequest{}, "0a00"},
		{"pubKey response", &privproto.PubKeyResponse{PubKey: ppk, Error: nil}, "12240a220a2028844d85f4f240357adbafaec37e13171b2263b9203a290d63c3b909f625bad4"},
		{"pubKey response with error", &privproto.PubKeyResponse{PubKey: cryptoproto.PublicKey{}, Error: remoteError}, "12140a0012100801120c697427732061206572726f72"},
		{"Vote Request", &privproto.SignVoteRequest{Vote: votepb}, "1a760a74080110031802224a0a20aeec33a2b50baa7373b49260a0bb761f91c1d1c98988f799f0a8050df1b686a1122608c0843d12209d2e1eb75bb8d50b7d65c2fd0727a82e6a1d73ab6ff3397ca88cdbe7dbe4f7082a0608f49a8ded053214c605d815a7781f00219c7f8d9eefc5274e803cb338d5bb03"},
		{"Vote Response", &privproto.SignedVoteResponse{Vote: *votepb, Error: nil}, "22760a74080110031802224a0a20aeec33a2b50baa7373b49260a0bb761f91c1d1c98988f799f0a8050df1b686a1122608c0843d12209d2e1eb75bb8d50b7d65c2fd0727a82e6a1d73ab6ff3397ca88cdbe7dbe4f7082a0608f49a8ded053214c605d815a7781f00219c7f8d9eefc5274e803cb338d5bb03"},
		{"Vote Response with error", &privproto.SignedVoteResponse{Vote: tmproto.Vote{}, Error: remoteError}, "22250a11220212002a0b088092b8c398feffffff0112100801120c697427732061206572726f72"},
		{"Proposal Request", &privproto.SignProposalRequest{Proposal: proposalpb}, "2a700a6e08011003180220022a4a0a20aeec33a2b50baa7373b49260a0bb761f91c1d1c98988f799f0a8050df1b686a1122608c0843d12209d2e1eb75bb8d50b7d65c2fd0727a82e6a1d73ab6ff3397ca88cdbe7dbe4f708320608f49a8ded053a10697427732061207369676e6174757265"},
		{"Proposal Response", &privproto.SignedProposalResponse{Proposal: *proposalpb, Error: nil}, "32700a6e08011003180220022a4a0a20aeec33a2b50baa7373b49260a0bb761f91c1d1c98988f799f0a8050df1b686a1122608c0843d12209d2e1eb75bb8d50b7d65c2fd0727a82e6a1d73ab6ff3397ca88cdbe7dbe4f708320608f49a8ded053a10697427732061207369676e6174757265"},
		{"Proposal Response with error", &privproto.SignedProposalResponse{Proposal: tmproto.Proposal{}, Error: remoteError}, "32250a112a021200320b088092b8c398feffffff0112100801120c697427732061206572726f72"},
	}

	for _, tc := range testCases {
		tc := tc

		pm := mustWrapMsg(tc.msg)
		bz, err := pm.Marshal()
		require.NoError(t, err, tc.testName)

		require.Equal(t, tc.expBytes, hex.EncodeToString(bz), tc.testName)
	}
}
