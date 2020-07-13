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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	distributed "github.com/wealdtech/go-eth2-wallet-distributed"
	keystorev4 "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"
	scratch "github.com/wealdtech/go-eth2-wallet-store-scratch"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

func TestExportWallet(t *testing.T) {
	store := scratch.New()
	encryptor := keystorev4.New()
	wallet, err := distributed.CreateWallet(context.Background(), "test wallet", store, encryptor)
	require.Nil(t, err)
	err = wallet.(e2wtypes.WalletLocker).Unlock(context.Background(), []byte{})
	require.Nil(t, err)

	threshold := uint32(3)
	participants := map[uint64]string{1: "foo", 2: "bar", 3: "baz"}

	account1PrivKey := _byteArray("01e748d098d3bcb477d636f19d510399ae18205fadf9814ee67052f88c1f77c0")
	account1VVec := [][]byte{
		_byteArray("a0633864987df6f7a0f40fbecbe0d15fe5317c00adccc0b816266bcf3d3d1ab6a365b3d79461b5da5a8ea09e37644731"),
		_byteArray("a7430ae4717f511e473ed87a6510c5dfdbf289b7c7c4e083270da487aa146b0291ee701e0c38033aa157a612b8fd488b"),
		_byteArray("b5e95fbcf45c9f2730f04abab22672dddca4b10e32467ab8522d7d153a382c9656d28268b5e75361e4e39a5d12513d8c"),
	}
	account1Passphrase := []byte{0x01, 0x02, 0x03, 0x04}
	account1, err := wallet.(e2wtypes.WalletDistributedAccountImporter).ImportDistributedAccount(context.Background(), "Account 1", account1PrivKey, threshold, account1VVec, participants, account1Passphrase)
	require.Nil(t, err)
	account2PrivKey := _byteArray("376880b8079dca3bbd06c93958b5208929cbc169c9ce4caf8731be10e94f710e")
	account2VVec := [][]byte{
		_byteArray("a0633864987df6f7a0f40fbecbe0d15fe5317c00adccc0b816266bcf3d3d1ab6a365b3d79461b5da5a8ea09e37644731"),
		_byteArray("b13d6e14cce66b3827b816c974e8f52a76e86611de58bbcdac116a9e97b00240a29714646202a65ae72df480bdfa5329"),
		_byteArray("81a00aee312320aa82316ea14b6615eb56f531ecdabc1effca2a55d0282f3c2463124b792da5ec0207d16119360bd896"),
	}
	account2Passphrase := []byte{0x04, 0x03, 0x02, 0x01}
	account2, err := wallet.(e2wtypes.WalletDistributedAccountImporter).ImportDistributedAccount(context.Background(), "Account 2", account2PrivKey, threshold, account2VVec, participants, account2Passphrase)
	require.Nil(t, err)

	dump, err := wallet.(e2wtypes.WalletExporter).Export(context.Background(), []byte("dump"))
	require.Nil(t, err)

	// Import it
	store2 := scratch.New()
	wallet2, err := distributed.Import(context.Background(), dump, []byte("dump"), store2, encryptor)
	require.Nil(t, err)

	// Confirm the accounts are present
	account1Present := false
	account2Present := false
	for account := range wallet2.Accounts(context.Background()) {
		if account.ID().String() == account1.ID().String() {
			account1Present = true
			assert.Equal(t, threshold, account.(e2wtypes.DistributedAccount).SigningThreshold())
			for i, vVecComponent := range account.(e2wtypes.AccountVerificationVectorProvider).VerificationVector() {
				assert.Equal(t, vVecComponent.Marshal(), account1VVec[i])
			}
			assert.Equal(t, participants, account.(e2wtypes.DistributedAccount).Participants())
			locker, isLocker := account.(e2wtypes.AccountLocker)
			require.True(t, isLocker)
			assert.NoError(t, locker.Unlock(context.Background(), account1Passphrase))
			privKey, err := account.(e2wtypes.AccountPrivateKeyProvider).PrivateKey(context.Background())
			assert.NoError(t, err)
			assert.Equal(t, account1PrivKey, privKey.Marshal())
		}
		if account.ID().String() == account2.ID().String() {
			account2Present = true
			assert.Equal(t, threshold, account.(e2wtypes.DistributedAccount).SigningThreshold())
			for i, vVecComponent := range account.(e2wtypes.AccountVerificationVectorProvider).VerificationVector() {
				assert.Equal(t, vVecComponent.Marshal(), account2VVec[i])
			}
			assert.Equal(t, participants, account.(e2wtypes.DistributedAccount).Participants())
			locker, isLocker := account.(e2wtypes.AccountLocker)
			require.True(t, isLocker)
			assert.NoError(t, locker.Unlock(context.Background(), account2Passphrase))
			privKey, err := account.(e2wtypes.AccountPrivateKeyProvider).PrivateKey(context.Background())
			assert.NoError(t, err)
			assert.Equal(t, account2PrivKey, privKey.Marshal())
		}
	}
	assert.True(t, account1Present && account2Present)

	// Try to import it again; should fail
	_, err = distributed.Import(context.Background(), dump, []byte("dump"), store2, encryptor)
	assert.NotNil(t, err)
}
