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

func TestInterfaces(t *testing.T) {
	store := scratch.New()
	encryptor := keystorev4.New()
	wallet, err := distributed.CreateWallet(context.Background(), "test wallet", store, encryptor)
	require.Nil(t, err)

	_, isWalletIDProvider := wallet.(e2wtypes.WalletIDProvider)
	assert.True(t, isWalletIDProvider)
	_, isWalletNameProvider := wallet.(e2wtypes.WalletNameProvider)
	assert.True(t, isWalletNameProvider)
	_, isWalletTypeProvider := wallet.(e2wtypes.WalletTypeProvider)
	assert.True(t, isWalletTypeProvider)
	_, isWalletVersionProvider := wallet.(e2wtypes.WalletVersionProvider)
	assert.True(t, isWalletVersionProvider)
	_, isWalletLocker := wallet.(e2wtypes.WalletLocker)
	assert.True(t, isWalletLocker)
	_, isWalletAccountsProvider := wallet.(e2wtypes.WalletAccountsProvider)
	assert.True(t, isWalletAccountsProvider)
	_, isWalletAccountByIDProvider := wallet.(e2wtypes.WalletAccountByIDProvider)
	assert.True(t, isWalletAccountByIDProvider)
	_, isWalletAccountByNameProvider := wallet.(e2wtypes.WalletAccountByNameProvider)
	assert.True(t, isWalletAccountByNameProvider)
	_, isWalletExporter := wallet.(e2wtypes.WalletExporter)
	assert.True(t, isWalletExporter)
	_, isWalletDistributedAccountImporter := wallet.(e2wtypes.WalletDistributedAccountImporter)
	assert.True(t, isWalletDistributedAccountImporter)
}

func TestCreateWallet(t *testing.T) {
	store := scratch.New()
	encryptor := keystorev4.New()
	wallet, err := distributed.CreateWallet(context.Background(), "test wallet", store, encryptor)
	assert.Nil(t, err)

	assert.Equal(t, "test wallet", wallet.Name())
	assert.Equal(t, uint(1), wallet.Version())

	// Try to create another wallet with the same name; should error
	_, err = distributed.CreateWallet(context.Background(), "test wallet", store, encryptor)
	assert.NotNil(t, err)
}
