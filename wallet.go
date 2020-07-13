// Copyright 2020 Weald Technology Trading
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

package distributed

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/wealdtech/go-ecodec"
	e2types "github.com/wealdtech/go-eth2-types/v2"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
	"github.com/wealdtech/go-indexer"
)

const (
	walletType = "distributed"
	version    = 1
)

// wallet contains the details of the wallet.
type wallet struct {
	id        uuid.UUID
	name      string
	version   uint
	store     e2wtypes.Store
	encryptor e2wtypes.Encryptor
	mutex     *sync.RWMutex
	unlocked  bool
	index     *indexer.Index
}

// newWallet creates a new wallet
func newWallet() *wallet {
	return &wallet{
		mutex: new(sync.RWMutex),
		index: indexer.New(),
	}
}

// MarshalJSON implements custom JSON marshaller.
func (w *wallet) MarshalJSON() ([]byte, error) {
	data := make(map[string]interface{})
	data["uuid"] = w.id.String()
	data["name"] = w.name
	data["version"] = w.version
	data["type"] = walletType
	return json.Marshal(data)
}

// UnmarshalJSON implements custom JSON unmarshaller.
func (w *wallet) UnmarshalJSON(data []byte) error {
	var v map[string]interface{}
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	if val, exists := v["type"]; exists {
		dataWalletType, ok := val.(string)
		if !ok {
			return errors.New("wallet type invalid")
		}
		if dataWalletType != walletType {
			return fmt.Errorf("wallet type %q unexpected", dataWalletType)
		}
	} else {
		return errors.New("wallet type missing")
	}
	if val, exists := v["uuid"]; exists {
		idStr, ok := val.(string)
		if !ok {
			return errors.New("wallet ID invalid")
		}
		id, err := uuid.Parse(idStr)
		if err != nil {
			return err
		}
		w.id = id
	} else {
		return errors.New("wallet ID missing")
	}
	if val, exists := v["name"]; exists {
		name, ok := val.(string)
		if !ok {
			return errors.New("wallet name invalid")
		}
		w.name = name
	} else {
		return errors.New("wallet name missing")
	}
	if val, exists := v["version"]; exists {
		version, ok := val.(float64)
		if !ok {
			return errors.New("wallet version invalid")
		}
		w.version = uint(version)
	} else {
		return errors.New("wallet version missing")
	}

	return nil
}

// CreateWallet creates a new wallet with the given name and stores it in the provided store.
// This will error if the wallet already exists.
func CreateWallet(ctx context.Context, name string, store e2wtypes.Store, encryptor e2wtypes.Encryptor) (e2wtypes.Wallet, error) {
	// First, try to access the wallet to ensure there's nothing there.
	if _, err := store.RetrieveWallet(name); err == nil {
		return nil, fmt.Errorf("wallet %q already exists", name)
	}

	id, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}

	w := newWallet()
	w.id = id
	w.name = name
	w.version = version
	w.store = store
	w.encryptor = encryptor

	return w, w.storeWallet()
}

// OpenWallet opens an existing wallet with the given name.
func OpenWallet(ctx context.Context, name string, store e2wtypes.Store, encryptor e2wtypes.Encryptor) (e2wtypes.Wallet, error) {
	data, err := store.RetrieveWallet(name)
	if err != nil {
		return nil, errors.Wrapf(err, "wallet %q does not exist", name)
	}
	return DeserializeWallet(ctx, data, store, encryptor)
}

// DeserializeWallet deserializes a wallet from its byte-level representation
func DeserializeWallet(ctx context.Context, data []byte, store e2wtypes.Store, encryptor e2wtypes.Encryptor) (e2wtypes.Wallet, error) {
	wallet := newWallet()
	if err := json.Unmarshal(data, wallet); err != nil {
		return nil, errors.Wrap(err, "wallet corrupt")
	}
	wallet.store = store
	wallet.encryptor = encryptor
	if err := wallet.retrieveAccountsIndex(ctx); err != nil {
		return nil, errors.Wrap(err, "wallet index corrupt")
	}

	return wallet, nil
}

// ID provides the ID for the wallet.
func (w *wallet) ID() uuid.UUID {
	return w.id
}

// Type provides the type for the wallet.
func (w *wallet) Type() string {
	return walletType
}

// Name provides the name for the wallet.
func (w *wallet) Name() string {
	return w.name
}

// Version provides the version of the wallet.
func (w *wallet) Version() uint {
	return w.version
}

// Lock locks the wallet.  A locked wallet cannot create new accounts.
func (w *wallet) Lock(ctx context.Context) error {
	w.unlocked = false
	return nil
}

// Unlock unlocks the wallet.  An unlocked wallet can create new accounts.
func (w *wallet) Unlock(ctx context.Context, passphrase []byte) error {
	w.unlocked = true
	return nil
}

// IsUnlocked reports if the wallet is unlocked.
func (w *wallet) IsUnlocked(ctx context.Context) (bool, error) {
	return w.unlocked, nil
}

// storeWallet stores the wallet in the store.
func (w *wallet) storeWallet() error {
	data, err := json.Marshal(w)
	if err != nil {
		return err
	}

	if err := w.storeAccountsIndex(); err != nil {
		return err
	}

	if err := w.store.StoreWallet(w.ID(), w.Name(), data); err != nil {
		return err
	}

	return nil
}

// ImportDistributedAccount creates a new distributed account in the wallet from provided data.
// The only rule for names is that they cannot start with an underscore (_) character.
// This will error if an account with the name already exists.
func (w *wallet) ImportDistributedAccount(ctx context.Context, name string, privatekey []byte, signingThreshold uint32, verificationVector [][]byte, participants map[uint64]string, passphrase []byte) (e2wtypes.Account, error) {
	if name == "" {
		return nil, errors.New("account name missing")
	}
	if strings.HasPrefix(name, "_") {
		return nil, fmt.Errorf("invalid account name %q", name)
	}
	if len(privatekey) == 0 {
		return nil, errors.New("private key missing")
	}
	if len(verificationVector) == 0 {
		return nil, errors.New("verification vector missing")
	}
	if len(participants) == 0 {
		return nil, errors.New("participants missing")
	}
	if signingThreshold <= uint32(len(participants)/2) {
		return nil, errors.New("invalid signing threshold:participant ratio")
	}
	if uint32(len(verificationVector)) != signingThreshold {
		return nil, errors.New("verification vector invalid")
	}
	unlocked, err := w.IsUnlocked(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain wallet lock status")
	}
	if !unlocked {
		return nil, errors.New("wallet must be unlocked to create accounts")
	}

	// Ensure that we don't already have an account with this name
	if _, err := w.AccountByName(ctx, name); err == nil {
		return nil, fmt.Errorf("account with name %q already exists", name)
	}

	a := newAccount()
	if a.id, err = uuid.NewRandom(); err != nil {
		return nil, err
	}
	a.name = name
	privateKey, err := e2types.BLSPrivateKeyFromBytes(privatekey)
	if err != nil {
		return nil, err
	}
	a.publicKey = privateKey.PublicKey()
	// Encrypt the private key
	a.signingThreshold = signingThreshold
	a.verificationVector = make([]e2types.PublicKey, len(verificationVector))
	for i := range verificationVector {
		a.verificationVector[i], err = e2types.BLSPublicKeyFromBytes(verificationVector[i])
		if err != nil {
			return nil, err
		}
	}
	a.participants = make(map[uint64]string, len(participants))
	for k, v := range participants {
		a.participants[k] = v
	}
	a.crypto, err = w.encryptor.Encrypt(privateKey.Marshal(), passphrase)
	if err != nil {
		return nil, err
	}
	a.encryptor = w.encryptor
	a.version = w.encryptor.Version()
	a.wallet = w

	w.index.Add(a.id, a.name)

	if err := a.storeAccount(ctx); err != nil {
		return nil, err
	}

	return a, nil
}

// Accounts provides all accounts in the wallet.
func (w *wallet) Accounts(ctx context.Context) <-chan e2wtypes.Account {
	ch := make(chan e2wtypes.Account, 1024)
	go func() {
		for data := range w.store.RetrieveAccounts(w.ID()) {
			if a, err := deserializeAccount(w, data); err == nil {
				ch <- a
			}
		}
		close(ch)
	}()
	return ch
}

// Export exports the entire wallet, protected by an additional passphrase.
func (w *wallet) Export(ctx context.Context, passphrase []byte) ([]byte, error) {
	type walletExt struct {
		Wallet   *wallet    `json:"wallet"`
		Accounts []*account `json:"accounts"`
	}

	accounts := make([]*account, 0)
	for acc := range w.Accounts(ctx) {
		accounts = append(accounts, acc.(*account))
	}

	ext := &walletExt{
		Wallet:   w,
		Accounts: accounts,
	}

	data, err := json.Marshal(ext)
	if err != nil {
		return nil, err
	}

	return ecodec.Encrypt(data, passphrase)
}

// Import imports the entire wallet, protected by an additional passphrase.
func Import(ctx context.Context, encryptedData []byte, passphrase []byte, store e2wtypes.Store, encryptor e2wtypes.Encryptor) (e2wtypes.Wallet, error) {
	type walletExt struct {
		Wallet   *wallet    `json:"wallet"`
		Accounts []*account `json:"accounts"`
	}

	data, err := ecodec.Decrypt(encryptedData, passphrase)
	if err != nil {
		return nil, err
	}

	ext := &walletExt{}
	if err := json.Unmarshal(data, ext); err != nil {
		return nil, err
	}

	ext.Wallet.mutex = new(sync.RWMutex)
	ext.Wallet.index = indexer.New()
	ext.Wallet.store = store
	ext.Wallet.encryptor = encryptor

	// See if the wallet already exists
	if _, err := OpenWallet(ctx, ext.Wallet.Name(), store, encryptor); err == nil {
		return nil, fmt.Errorf("wallet %q already exists", ext.Wallet.Name())
	}

	// Create the wallet
	if err := ext.Wallet.storeWallet(); err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("failed to store wallet %q", ext.Wallet.Name()))
	}

	// Create the accounts
	for _, acc := range ext.Accounts {
		acc.wallet = ext.Wallet
		acc.encryptor = encryptor
		ext.Wallet.index.Add(acc.id, acc.name)
		if err := acc.storeAccount(ctx); err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("failed to store account %q", acc.Name()))
		}
	}

	return ext.Wallet, nil
}

// AccountByName provides a single account from the wallet given its name.
// This will error if the account is not found.
func (w *wallet) AccountByName(ctx context.Context, name string) (e2wtypes.Account, error) {
	id, exists := w.index.ID(name)
	if !exists {
		return nil, fmt.Errorf("no account with name %q", name)
	}
	return w.AccountByID(ctx, id)
}

// AccountByID provides a single account from the wallet given its ID.
// This will error if the account is not found.
func (w *wallet) AccountByID(ctx context.Context, id uuid.UUID) (e2wtypes.Account, error) {
	data, err := w.store.RetrieveAccount(w.id, id)
	if err != nil {
		return nil, err
	}
	return deserializeAccount(w, data)
}

// Store returns the wallet's store.
func (w *wallet) Store() e2wtypes.Store {
	return w.store
}

// retrieveAccountsIndex retrieves the accounts index for a wallet.
func (w *wallet) retrieveAccountsIndex(ctx context.Context) error {
	serializedIndex, err := w.store.RetrieveAccountsIndex(w.id)
	if err != nil {
		// Attempt to recreate the index.
		w.index = indexer.New()
		for account := range w.Accounts(ctx) {
			idProvider, isIDProvider := account.(e2wtypes.AccountIDProvider)
			if !isIDProvider {
				return errors.New("Cannot index account without ID")
			}
			nameProvider, isNameProvider := account.(e2wtypes.AccountNameProvider)
			if !isNameProvider {
				return errors.New("Cannot index account without name")
			}
			w.index.Add(idProvider.ID(), nameProvider.Name())
		}
		if err := w.storeAccountsIndex(); err != nil {
			return err
		}
	} else {
		index, err := indexer.Deserialize(serializedIndex)
		if err != nil {
			return err
		}
		w.index = index
	}
	return nil
}

// storeAccountsIndex stores the accounts index for a wallet.
func (w *wallet) storeAccountsIndex() error {
	serializedIndex, err := w.index.Serialize()
	if err != nil {
		return err
	}
	if err := w.store.StoreAccountsIndex(w.id, serializedIndex); err != nil {
		return err
	}
	return nil
}
