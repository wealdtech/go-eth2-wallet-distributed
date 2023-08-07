// Copyright © 2023 Weald Technology Trading.
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
	"testing"

	"github.com/stretchr/testify/require"
	distributed "github.com/wealdtech/go-eth2-wallet-distributed"
	keystorev4 "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"
	scratch "github.com/wealdtech/go-eth2-wallet-store-scratch"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

func TestBatch(t *testing.T) {
	ctx := context.Background()
	store := scratch.New()
	encryptor := keystorev4.New()

	// Create a wallet.
	wallet, err := distributed.CreateWallet(ctx, "test wallet", store, encryptor)
	require.NoError(t, err)
	require.NoError(t, wallet.(e2wtypes.WalletLocker).Unlock(ctx, nil))

	// Import some accounts.
	require.NoError(t, wallet.(e2wtypes.WalletLocker).Unlock(ctx, nil))
	account1, err := wallet.(e2wtypes.WalletDistributedAccountImporter).ImportDistributedAccount(ctx,
		"account 1",
		_byteArray("0a660b6379a25e095590edeb7688a8506653e58310336efcfc98a9e34e485faa"),
		3,
		[][]byte{
			_byteArray("b5d7a0bffb025cca463898a7ff56a613402e40d43ee293b45ee9f7811c17047a43273a0cf843d75995d1150140f6b2ef"),
			_byteArray("b82aa608cd126ff401a458be48944dc84c999cce084fd6c8da816e5548964fc1d71b05d52c528e5ce3657778c573cc31"),
			_byteArray("a4da59f92bea77d3950cb578c2b8c8ee65e12040e9efd4c82cb4b0ac6138fef5d8f4bb53971bafdf6285f22f91b22b2f"),
		},
		map[uint64]string{1: "foo", 2: "bar", 3: "baz"},
		[]byte("aep7beejaChieVei4mongie9"))
	require.NoError(t, err)
	account2, err := wallet.(e2wtypes.WalletDistributedAccountImporter).ImportDistributedAccount(ctx,
		"account 2",
		_byteArray("4aee5bb2fcd7fd954ff86672ac6abce0358c060070537e246cb83152317b729f"),
		3,
		[][]byte{
			_byteArray("af50b5cdf579f86780e482321530a15c387ca9d9e41f43393e604fb675c6389c926b242ffbda80ca55abfd95651fa38d"),
			_byteArray("b927272690e1056cf7dcf85d3296f281e9a2367addb62e6de79d9bce3b5e67cce7aa7961cc5f3ed1dee8eb6ea707f9c6"),
			_byteArray("97bbe8fd154e02af8fcae26b97c9ac618103ba41e3662dbdb762d1721d5672a4c5510270f2ead7f2c332d21a6f7ffe3d"),
		},
		map[uint64]string{1: "foo", 2: "bar", 3: "baz"},
		[]byte("aep7beejaChieVei4mongie9"))
	require.NoError(t, err)

	// Create a batch.
	require.NoError(t, wallet.(e2wtypes.WalletBatchCreator).BatchWallet(ctx, []string{"aep7beejaChieVei4mongie9"}, "batch passphrase"))

	// Re-open the wallet and fetch the accounts through the batch system.
	wallet, err = distributed.OpenWallet(ctx, "test wallet", store, encryptor)
	require.NoError(t, err)
	numAccounts := 0
	for range wallet.Accounts(ctx) {
		numAccounts++
	}
	require.Equal(t, 2, numAccounts)
	obtainedAccount1, err := wallet.(e2wtypes.WalletAccountByNameProvider).AccountByName(ctx, "account 1")
	require.NoError(t, err)
	require.Equal(t, account1.ID(), obtainedAccount1.ID())
	require.Equal(t, account1.Name(), obtainedAccount1.Name())
	require.Equal(t, account1.PublicKey().Marshal(), obtainedAccount1.PublicKey().Marshal())
	require.Equal(t, account1.(e2wtypes.AccountCompositePublicKeyProvider).CompositePublicKey().Marshal(), obtainedAccount1.(e2wtypes.AccountCompositePublicKeyProvider).CompositePublicKey().Marshal())
	require.Equal(t, account1.(e2wtypes.AccountSigningThresholdProvider).SigningThreshold(), obtainedAccount1.(e2wtypes.AccountSigningThresholdProvider).SigningThreshold())
	require.Equal(t, account1.(e2wtypes.AccountParticipantsProvider).Participants(), obtainedAccount1.(e2wtypes.AccountParticipantsProvider).Participants())
	obtainedAccount2, err := wallet.(e2wtypes.WalletAccountByIDProvider).AccountByID(ctx, account2.ID())
	require.NoError(t, err)
	require.Equal(t, account2.ID(), obtainedAccount2.ID())
	require.Equal(t, account2.Name(), obtainedAccount2.Name())
	require.Equal(t, account2.PublicKey().Marshal(), obtainedAccount2.PublicKey().Marshal())
	require.Equal(t, account2.(e2wtypes.AccountCompositePublicKeyProvider).CompositePublicKey().Marshal(), obtainedAccount2.(e2wtypes.AccountCompositePublicKeyProvider).CompositePublicKey().Marshal())
	require.Equal(t, account2.(e2wtypes.AccountSigningThresholdProvider).SigningThreshold(), obtainedAccount2.(e2wtypes.AccountSigningThresholdProvider).SigningThreshold())
	require.Equal(t, account2.(e2wtypes.AccountParticipantsProvider).Participants(), obtainedAccount2.(e2wtypes.AccountParticipantsProvider).Participants())

	// Ensure we can unlock accounts with the batch passphrase.
	require.NoError(t, obtainedAccount1.(e2wtypes.AccountLocker).Unlock(ctx, []byte("batch passphrase")))
	require.NoError(t, obtainedAccount2.(e2wtypes.AccountLocker).Unlock(ctx, []byte("batch passphrase")))

	// Create another account, not in the batch.
	require.NoError(t, wallet.(e2wtypes.WalletLocker).Unlock(ctx, nil))
	account3, err := wallet.(e2wtypes.WalletDistributedAccountImporter).ImportDistributedAccount(ctx,
		"account 3",
		_byteArray("3ff86acb31e3b4f3f2bb190d1782ecdbf2f8af2c0c26a9e4aa93b167c56a2386"),
		3,
		[][]byte{
			_byteArray("b3c8c29d4e0435fb39dcd49147bccaeaadf0c1744b5df5a42a350f4a6492e3cd36e8d135b262bd9d833ecfe48341fdd5"),
			_byteArray("a5914ee2321b2d22e0d422b6293fa0ac438b16efb40220fd6ebc0523ed5b134cdf4f53043efe1173184f84b2a5032073"),
			_byteArray("8d43da5dcdf8f8bddbb243b4fde6c0771ba7ac0978539dbbd6b60f8c0b9f278b26bbf7ccd273a37567092fae008de0be"),
		},
		map[uint64]string{1: "foo", 2: "bar", 3: "baz"},
		[]byte("aep7beejaChieVei4mongie9"))
	require.NoError(t, err)

	// Re-open the wallet and fetch the non-batch account by name.
	wallet, err = distributed.OpenWallet(ctx, "test wallet", store, encryptor)
	require.NoError(t, err)
	numAccounts = 0
	for range wallet.Accounts(ctx) {
		numAccounts++
	}
	require.Equal(t, 2, numAccounts)
	obtainedAccount3, err := wallet.(e2wtypes.WalletAccountByNameProvider).AccountByName(ctx, "account 3")
	require.NoError(t, err)
	require.Equal(t, account3.ID(), obtainedAccount3.ID())
	require.Equal(t, account3.Name(), obtainedAccount3.Name())
	require.Equal(t, account3.PublicKey().Marshal(), obtainedAccount3.PublicKey().Marshal())
	require.Equal(t, account3.(e2wtypes.AccountCompositePublicKeyProvider).CompositePublicKey().Marshal(), obtainedAccount3.(e2wtypes.AccountCompositePublicKeyProvider).CompositePublicKey().Marshal())
	require.Equal(t, account3.(e2wtypes.AccountSigningThresholdProvider).SigningThreshold(), obtainedAccount3.(e2wtypes.AccountSigningThresholdProvider).SigningThreshold())
	require.Equal(t, account3.(e2wtypes.AccountParticipantsProvider).Participants(), obtainedAccount3.(e2wtypes.AccountParticipantsProvider).Participants())

	// Re-open the wallet and fetch the non-batch account by ID.
	wallet, err = distributed.OpenWallet(ctx, "test wallet", store, encryptor)
	require.NoError(t, err)
	numAccounts = 0
	for range wallet.Accounts(ctx) {
		numAccounts++
	}
	require.Equal(t, 2, numAccounts)
	obtainedAccount3, err = wallet.(e2wtypes.WalletAccountByIDProvider).AccountByID(ctx, account3.ID())
	require.NoError(t, err)
	require.Equal(t, account3.ID(), obtainedAccount3.ID())
	require.Equal(t, account3.Name(), obtainedAccount3.Name())
	require.Equal(t, account3.PublicKey().Marshal(), obtainedAccount3.PublicKey().Marshal())
	require.Equal(t, account3.(e2wtypes.AccountCompositePublicKeyProvider).CompositePublicKey().Marshal(), obtainedAccount3.(e2wtypes.AccountCompositePublicKeyProvider).CompositePublicKey().Marshal())
	require.Equal(t, account3.(e2wtypes.AccountSigningThresholdProvider).SigningThreshold(), obtainedAccount3.(e2wtypes.AccountSigningThresholdProvider).SigningThreshold())
	require.Equal(t, account3.(e2wtypes.AccountParticipantsProvider).Participants(), obtainedAccount3.(e2wtypes.AccountParticipantsProvider).Participants())

	// Ensure we can unlock account with the account passphrase.
	require.NoError(t, obtainedAccount3.(e2wtypes.AccountLocker).Unlock(ctx, []byte("aep7beejaChieVei4mongie9")))

	// Recreate the batch.
	require.NoError(t, wallet.(e2wtypes.WalletBatchCreator).BatchWallet(ctx, []string{"aep7beejaChieVei4mongie9", "batch passphrase"}, "batch passphrase"))

	// Re-open the wallet and fetch the accounts through the batch system.
	wallet, err = distributed.OpenWallet(ctx, "test wallet", store, encryptor)
	require.NoError(t, err)
	numAccounts = 0
	for range wallet.Accounts(ctx) {
		numAccounts++
	}
	require.Equal(t, 3, numAccounts)
}
