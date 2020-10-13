// Copyright © 2020 Weald Technology Trading
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package distributed_test

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	distributed "github.com/wealdtech/go-eth2-wallet-distributed"
	keystorev4 "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"
	filesystem "github.com/wealdtech/go-eth2-wallet-store-filesystem"
	scratch "github.com/wealdtech/go-eth2-wallet-store-scratch"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// _byteArray is a helper to turn a string in to a byte array
func _byteArray(input string) []byte {
	x, _ := hex.DecodeString(input)
	return x
}

func TestImportAccount(t *testing.T) {
	tests := []struct {
		name               string
		accountName        string
		key                []byte
		pubKey             []byte
		signingThreshold   uint32
		verificationVector [][]byte
		participants       map[uint64]string
		passphrase         []byte
		err                string
	}{
		{
			name:        "Empty",
			accountName: "",
			err:         "account name missing",
		},
		{
			name:        "Invalid",
			accountName: "_bad",
			err:         `invalid account name "_bad"`,
		},
		{
			name:             "KeyMissing",
			accountName:      "test",
			signingThreshold: 2,
			verificationVector: [][]byte{
				_byteArray("b5f7f572e3f50a970af6c13f02e2c20900cda0dffdcf8b2e2a06c78ba2bae667bfa7aab01b36fba268da4aa2aba5c68f"),
				_byteArray("a88427e16f45b632f83247220bd885241cff6fd035803e976fe96c6352933d01a6205d6f3e87a96789cddcca64bbcf25"),
			},
			participants: map[uint64]string{1: "foo", 2: "bar", 3: "baz"},
			passphrase:   []byte("test passphrase"),
			err:          "private key missing",
		},
		{
			name:             "VerificationVectorMissing",
			accountName:      "test",
			key:              _byteArray("220091d10843519cd1c452a4ec721d378d7d4c5ece81c4b5556092d410e5e0e1"),
			signingThreshold: 2,
			participants:     map[uint64]string{1: "foo", 2: "bar", 3: "baz"},
			passphrase:       []byte("test passphrase"),
			err:              "verification vector missing",
		},
		{
			name:             "ParticipantsMissing",
			accountName:      "test",
			key:              _byteArray("220091d10843519cd1c452a4ec721d378d7d4c5ece81c4b5556092d410e5e0e1"),
			signingThreshold: 2,
			verificationVector: [][]byte{
				_byteArray("b5f7f572e3f50a970af6c13f02e2c20900cda0dffdcf8b2e2a06c78ba2bae667bfa7aab01b36fba268da4aa2aba5c68f"),
				_byteArray("a88427e16f45b632f83247220bd885241cff6fd035803e976fe96c6352933d01a6205d6f3e87a96789cddcca64bbcf25"),
			},
			passphrase: []byte("test passphrase"),
			err:        "participants missing",
		},
		{
			name:        "SigninghTresholdMissing",
			accountName: "test",
			key:         _byteArray("220091d10843519cd1c452a4ec721d378d7d4c5ece81c4b5556092d410e5e0e1"),
			verificationVector: [][]byte{
				_byteArray("b5f7f572e3f50a970af6c13f02e2c20900cda0dffdcf8b2e2a06c78ba2bae667bfa7aab01b36fba268da4aa2aba5c68f"),
				_byteArray("a88427e16f45b632f83247220bd885241cff6fd035803e976fe96c6352933d01a6205d6f3e87a96789cddcca64bbcf25"),
			},
			participants: map[uint64]string{1: "foo", 2: "bar", 3: "baz"},
			passphrase:   []byte("test passphrase"),
			err:          "invalid signing threshold:participant ratio",
		},
		{
			name:             "SigningThresholdTooLow",
			accountName:      "test",
			key:              _byteArray("220091d10843519cd1c452a4ec721d378d7d4c5ece81c4b5556092d410e5e0e1"),
			signingThreshold: 1,
			verificationVector: [][]byte{
				_byteArray("b5f7f572e3f50a970af6c13f02e2c20900cda0dffdcf8b2e2a06c78ba2bae667bfa7aab01b36fba268da4aa2aba5c68f"),
				_byteArray("a88427e16f45b632f83247220bd885241cff6fd035803e976fe96c6352933d01a6205d6f3e87a96789cddcca64bbcf25"),
			},
			participants: map[uint64]string{1: "foo", 2: "bar", 3: "baz"},
			passphrase:   []byte("test passphrase"),
			err:          "invalid signing threshold:participant ratio",
		},
		{
			name:             "ImbalancedParticipants",
			accountName:      "test",
			key:              _byteArray("220091d10843519cd1c452a4ec721d378d7d4c5ece81c4b5556092d410e5e0e1"),
			signingThreshold: 3,
			verificationVector: [][]byte{
				_byteArray("b5f7f572e3f50a970af6c13f02e2c20900cda0dffdcf8b2e2a06c78ba2bae667bfa7aab01b36fba268da4aa2aba5c68f"),
				_byteArray("a88427e16f45b632f83247220bd885241cff6fd035803e976fe96c6352933d01a6205d6f3e87a96789cddcca64bbcf25"),
			},
			participants: map[uint64]string{1: "foo", 2: "bar", 3: "baz", 4: "qux", 5: "quux"},
			passphrase:   []byte("test passphrase"),
			err:          "verification vector invalid",
		},
		{
			name:             "Good",
			accountName:      "test",
			key:              _byteArray("220091d10843519cd1c452a4ec721d378d7d4c5ece81c4b5556092d410e5e0e1"),
			pubKey:           _byteArray("940e2565d2e3079dc1642d042ae000ee2182b37d94f40b68d8376ac1757ff9b87cdd31893986b0049dd62e369bc63d4e"),
			signingThreshold: 2,
			verificationVector: [][]byte{
				_byteArray("b5f7f572e3f50a970af6c13f02e2c20900cda0dffdcf8b2e2a06c78ba2bae667bfa7aab01b36fba268da4aa2aba5c68f"),
				_byteArray("a88427e16f45b632f83247220bd885241cff6fd035803e976fe96c6352933d01a6205d6f3e87a96789cddcca64bbcf25"),
			},
			participants: map[uint64]string{1: "foo", 2: "bar", 3: "baz"},
			passphrase:   []byte("test passphrase"),
		},
		{
			name:             "Duplicate",
			accountName:      "test",
			key:              _byteArray("220091d10843519cd1c452a4ec721d378d7d4c5ece81c4b5556092d410e5e0e2"),
			signingThreshold: 2,
			verificationVector: [][]byte{
				_byteArray("b5f7f572e3f50a970af6c13f02e2c20900cda0dffdcf8b2e2a06c78ba2bae667bfa7aab01b36fba268da4aa2aba5c68f"),
				_byteArray("a88427e16f45b632f83247220bd885241cff6fd035803e976fe96c6352933d01a6205d6f3e87a96789cddcca64bbcf25"),
			},
			participants: map[uint64]string{1: "foo", 2: "bar", 3: "baz"},
			passphrase:   []byte("test passphrase"),
			err:          `account with name "test" already exists`,
		},
	}

	store := scratch.New()
	encryptor := keystorev4.New()
	wallet, err := distributed.CreateWallet(context.Background(), "test wallet", store, encryptor)
	require.Nil(t, err)

	// Try to import without unlocking the wallet; should fail
	_, err = wallet.(e2wtypes.WalletDistributedAccountImporter).ImportDistributedAccount(context.Background(), "Locked", _byteArray("220091d10843519cd1c452a4ec721d378d7d4c5ece81c4b5556092d410e5e0e1"), 2, [][]byte{
		_byteArray("b5f7f572e3f50a970af6c13f02e2c20900cda0dffdcf8b2e2a06c78ba2bae667bfa7aab01b36fba268da4aa2aba5c68f"),
		_byteArray("a88427e16f45b632f83247220bd885241cff6fd035803e976fe96c6352933d01a6205d6f3e87a96789cddcca64bbcf25"),
	},
		map[uint64]string{1: "foo", 2: "bar", 3: "baz"},
		[]byte("test passphrase"))
	require.EqualError(t, err, "wallet must be unlocked to create accounts")

	err = wallet.(e2wtypes.WalletLocker).Unlock(context.Background(), nil)
	require.Nil(t, err)
	defer func() {
		if err := wallet.(e2wtypes.WalletLocker).Lock(context.Background()); err != nil {
			panic(err)
		}
	}()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			account, err := wallet.(e2wtypes.WalletDistributedAccountImporter).ImportDistributedAccount(context.Background(), test.accountName, test.key, test.signingThreshold, test.verificationVector, test.participants, test.passphrase)
			if test.err != "" {
				require.Error(t, err)
				assert.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, test.accountName, account.Name())
				assert.Equal(t, test.pubKey, account.PublicKey().Marshal())
				pathProvider, isPathProvider := account.(e2wtypes.AccountPathProvider)
				require.True(t, isPathProvider)
				assert.NotNil(t, pathProvider.Path())
				// Should not be able to obtain private key from a locked account
				_, err = account.(e2wtypes.AccountPrivateKeyProvider).PrivateKey(context.Background())
				assert.NotNil(t, err)
				locker, isLocker := account.(e2wtypes.AccountLocker)
				require.True(t, isLocker)
				err = locker.Unlock(context.Background(), test.passphrase)
				require.Nil(t, err)
				_, err := account.(e2wtypes.AccountPrivateKeyProvider).PrivateKey(context.Background())
				assert.Nil(t, err)
			}
		})
	}
}

func TestRebuildIndex(t *testing.T) {
	accountName := "test"
	key := _byteArray("220091d10843519cd1c452a4ec721d378d7d4c5ece81c4b5556092d410e5e0e1")
	signingThreshold := uint32(2)
	verificationVector := [][]byte{
		_byteArray("b5f7f572e3f50a970af6c13f02e2c20900cda0dffdcf8b2e2a06c78ba2bae667bfa7aab01b36fba268da4aa2aba5c68f"),
		_byteArray("a88427e16f45b632f83247220bd885241cff6fd035803e976fe96c6352933d01a6205d6f3e87a96789cddcca64bbcf25"),
	}
	participants := map[uint64]string{1: "foo", 2: "bar", 3: "baz"}
	passphrase := []byte("test passphrase")

	rand.Seed(time.Now().Unix())
	// #nosec G404
	path := filepath.Join(os.TempDir(), fmt.Sprintf("TestRebuildIndex-%d", rand.Int31()))
	defer os.RemoveAll(path)
	store := filesystem.New(filesystem.WithLocation(path))

	encryptor := keystorev4.New()
	wallet, err := distributed.CreateWallet(context.Background(), "test wallet", store, encryptor)
	require.Nil(t, err)

	err = wallet.(e2wtypes.WalletLocker).Unlock(context.Background(), nil)
	require.Nil(t, err)
	defer func() {
		if err := wallet.(e2wtypes.WalletLocker).Lock(context.Background()); err != nil {
			panic(err)
		}
	}()

	_, err = wallet.(e2wtypes.WalletDistributedAccountImporter).ImportDistributedAccount(context.Background(), accountName, key, signingThreshold, verificationVector, participants, passphrase)
	require.NoError(t, err)

	// Ensure the wallet can see this account.
	foundAccount := false
	for account := range wallet.Accounts(context.Background()) {
		if account.Name() == "test" {
			foundAccount = true
			break
		}
	}
	require.True(t, foundAccount)

	// Find and confirm the wallet index path.
	indexPath := filepath.Join(
		wallet.(e2wtypes.StoreProvider).Store().(e2wtypes.StoreLocationProvider).Location(),
		wallet.ID().String(),
		"index")
	index, err := os.Open(indexPath)
	require.NoError(t, err)
	require.NoError(t, index.Close())

	// Delete the index.
	require.NoError(t, os.Remove(indexPath))

	// Re-fetch the wallet and account.
	wallet, err = distributed.OpenWallet(context.Background(), "test wallet", store, encryptor)
	require.NoError(t, err)

	// Re-fetch the account.
	foundAccount = false
	for account := range wallet.Accounts(context.Background()) {
		if account.Name() == "test" {
			foundAccount = true
			break
		}
	}
	require.True(t, foundAccount)

	// Confirm the index has been rebuilt.
	index, err = os.Open(indexPath)
	require.NoError(t, err)
	require.NoError(t, index.Close())
}
