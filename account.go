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
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"sync"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	e2types "github.com/wealdtech/go-eth2-types/v2"
	keystorev4 "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// account contains the details of the account.
type account struct {
	id                 uuid.UUID
	name               string
	verificationVector []e2types.PublicKey
	signingThreshold   uint32
	participants       map[uint64]string
	crypto             map[string]interface{}
	secretKey          e2types.PrivateKey
	publicKey          e2types.PublicKey
	version            uint
	wallet             e2wtypes.Wallet
	encryptor          e2wtypes.Encryptor
	mutex              sync.RWMutex
}

// newAccount creates a new account
func newAccount() *account {
	return &account{}
}

// MarshalJSON implements custom JSON marshaller.
func (a *account) MarshalJSON() ([]byte, error) {
	data := make(map[string]interface{})
	data["uuid"] = a.id.String()
	data["name"] = a.name
	data["pubkey"] = fmt.Sprintf("%x", a.publicKey.Marshal())
	verificationKeys := make([]string, len(a.verificationVector))
	for i := range a.verificationVector {
		verificationKeys[i] = fmt.Sprintf("%x", a.verificationVector[i].Marshal())
	}
	data["verificationvector"] = verificationKeys
	data["signing_threshold"] = a.signingThreshold
	participants := make(map[string]string, len(a.participants))
	for k, v := range a.participants {
		participants[fmt.Sprintf("%d", k)] = v
	}
	data["participants"] = participants
	data["crypto"] = a.crypto
	data["encryptor"] = a.encryptor.Name()
	data["version"] = a.version
	return json.Marshal(data)
}

// UnmarshalJSON implements custom JSON unmarshaller.
func (a *account) UnmarshalJSON(data []byte) error {
	var v map[string]interface{}
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	if val, exists := v["uuid"]; exists {
		idStr, ok := val.(string)
		if !ok {
			return errors.New("account ID invalid")
		}
		id, err := uuid.Parse(idStr)
		if err != nil {
			return err
		}
		a.id = id
	} else {
		return errors.New("account ID missing")
	}
	if val, exists := v["name"]; exists {
		name, ok := val.(string)
		if !ok {
			return errors.New("account name invalid")
		}
		a.name = name
	} else {
		return errors.New("account name missing")
	}
	if val, exists := v["pubkey"]; exists {
		publicKey, ok := val.(string)
		if !ok {
			return errors.New("account pubkey invalid")
		}
		bytes, err := hex.DecodeString(publicKey)
		if err != nil {
			return err
		}
		a.publicKey, err = e2types.BLSPublicKeyFromBytes(bytes)
		if err != nil {
			return err
		}
	} else {
		return errors.New("account pubkey missing")
	}
	if val, exists := v["verificationvector"]; exists {
		verificationVectorData, ok := val.([]interface{})
		if !ok {
			return errors.New("account verificationvector invalid")
		}
		verificationVector := make([]e2types.PublicKey, len(verificationVectorData))
		for i := range verificationVectorData {
			key, ok := verificationVectorData[i].(string)
			if !ok {
				return errors.New("account verification vector does not contain strings")
			}
			bytes, err := hex.DecodeString(key)
			if err != nil {
				return err
			}
			tmp, err := e2types.BLSPublicKeyFromBytes(bytes)
			if err != nil {
				return err
			}
			verificationVector[i] = tmp
		}
		a.verificationVector = verificationVector
	} else {
		return errors.New("account verificationvector missing")
	}
	if val, exists := v["participants"]; exists {
		participantData, ok := val.(map[string]interface{})
		if !ok {
			return errors.New("account participants invalid")
		}
		participants := make(map[uint64]string, len(participantData))
		for k, v := range participantData {
			id, err := strconv.ParseUint(k, 10, 64)
			if err != nil {
				return errors.New("account participant ID invalid")
			}
			val, ok := v.(string)
			if !ok {
				return errors.New("account participant value invalid")
			}
			participants[id] = val
		}
		a.participants = participants
	} else {
		return errors.New("participants missing")
	}
	if val, exists := v["signing_threshold"]; exists {
		signingThreshold, ok := val.(float64)
		if !ok {
			return errors.New("account signing threshold invalid")
		}
		a.signingThreshold = uint32(signingThreshold)
		if a.signingThreshold <= uint32(len(a.participants)/2) {
			return errors.New("account signing threshold too low")
		}
	} else {
		return errors.New("account signing threshold missing")
	}
	if val, exists := v["crypto"]; exists {
		crypto, ok := val.(map[string]interface{})
		if !ok {
			return errors.New("account crypto invalid")
		}
		a.crypto = crypto
	} else {
		return errors.New("account crypto missing")
	}
	if val, exists := v["version"]; exists {
		version, ok := val.(float64)
		if !ok {
			return errors.New("account version invalid")
		}
		a.version = uint(version)
	} else {
		return errors.New("account version missing")
	}
	// Only support keystorev4 at current...
	if a.version == 4 {
		a.encryptor = keystorev4.New()
	} else {
		return errors.New("unsupported keystore version")
	}

	return nil
}

// ID provides the ID for the account.
func (a *account) ID() uuid.UUID {
	return a.id
}

// Name provides the ID for the account.
func (a *account) Name() string {
	return a.name
}

// PublicKey provides the public key for the account.
func (a *account) PublicKey() e2types.PublicKey {
	// Safe to ignore the error as this is already a public key
	keyCopy, _ := e2types.BLSPublicKeyFromBytes(a.publicKey.Marshal())
	return keyCopy
}

// CompositePublicKey provides the composite public key for the account.
func (a *account) CompositePublicKey() e2types.PublicKey {
	// Safe to ignore the error as this is already a public key and we're just copying.
	keyCopy, _ := e2types.BLSPublicKeyFromBytes(a.verificationVector[0].Marshal())
	return keyCopy
}

// SigningThreshold provides the composite threshold for the account.
func (a *account) SigningThreshold() uint32 {
	return a.signingThreshold
}

// VerificationVector provides the verification vector for the account.
func (a *account) VerificationVector() []e2types.PublicKey {
	verificationVectorCopy := make([]e2types.PublicKey, len(a.verificationVector))
	for i := range a.verificationVector {
		// Safe to ignore the error as this is already a public key and we're just copying.
		verificationVectorCopy[i], _ = e2types.BLSPublicKeyFromBytes(a.verificationVector[i].Marshal())
	}
	return verificationVectorCopy
}

// Participants provides the participants in this distributed account.
func (a *account) Participants() map[uint64]string {
	participantsCopy := make(map[uint64]string, len(a.participants))
	for k, v := range a.participants {
		participantsCopy[k] = v
	}
	return participantsCopy
}

// PrivateKey provides the private key for the account.
func (a *account) PrivateKey(ctx context.Context) (e2types.PrivateKey, error) {
	unlocked, err := a.IsUnlocked(ctx)
	if err != nil {
		return nil, err
	}
	if !unlocked {
		return nil, errors.New("cannot provide private key when account is locked")
	}
	return e2types.BLSPrivateKeyFromBytes(a.secretKey.Marshal())
}

// Wallet provides the wallet for the account.
func (a *account) Wallet() e2wtypes.Wallet {
	return a.wallet
}

// Lock locks the account.  A locked account cannot sign data.
func (a *account) Lock(ctx context.Context) error {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	a.secretKey = nil
	return nil
}

// Unlock unlocks the account.  An unlocked account can sign data.
func (a *account) Unlock(ctx context.Context, passphrase []byte) error {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	secretBytes, err := a.encryptor.Decrypt(a.crypto, passphrase)
	if err != nil {
		return errors.New("incorrect passphrase")
	}
	secretKey, err := e2types.BLSPrivateKeyFromBytes(secretBytes)
	if err != nil {
		return err
	}
	publicKey := secretKey.PublicKey()
	if !bytes.Equal(publicKey.Marshal(), a.publicKey.Marshal()) {
		return errors.New("secret key does not correspond to public key")
	}
	a.secretKey = secretKey
	return nil
}

// IsUnlocked returns true if the account is unlocked.
func (a *account) IsUnlocked(ctx context.Context) (bool, error) {
	return a.secretKey != nil, nil
}

// Path returns "" as non-deterministic accounts are not derived.
func (a *account) Path() string {
	return ""
}

// Sign signs data.
func (a *account) Sign(ctx context.Context, data []byte) (e2types.Signature, error) {
	a.mutex.RLock()
	defer a.mutex.RUnlock()
	unlocked, err := a.IsUnlocked(ctx)
	if err != nil {
		return nil, err
	}

	if !unlocked {
		return nil, errors.New("cannot sign when account is locked")
	}
	return a.secretKey.Sign(data), nil
}

// storeAccount stores the account.
func (a *account) storeAccount(ctx context.Context) error {
	a.mutex.RLock()
	defer a.mutex.RUnlock()
	data, err := json.Marshal(a)
	if err != nil {
		return errors.Wrap(err, "failed to create store format")
	}
	if err := a.wallet.(*wallet).storeAccountsIndex(); err != nil {
		return errors.Wrap(err, "failed to store account index")
	}
	if err := a.wallet.(*wallet).store.StoreAccount(a.wallet.ID(), a.ID(), data); err != nil {
		return errors.Wrap(err, "failed to store account")
	}

	// Check to ensure the account can be retrieved.
	if _, err = a.wallet.(e2wtypes.WalletAccountByNameProvider).AccountByName(ctx, a.name); err != nil {
		return errors.Wrap(err, "failed to confirm account when retrieving by name")
	}
	if _, err = a.wallet.(e2wtypes.WalletAccountByIDProvider).AccountByID(ctx, a.id); err != nil {
		return errors.Wrap(err, "failed to confirm account when retrieveing by ID")
	}

	return nil
}

// deserializeAccount deserializes account data to an account.
func deserializeAccount(w *wallet, data []byte) (e2wtypes.Account, error) {
	a := newAccount()
	a.wallet = w
	a.encryptor = w.encryptor
	if err := json.Unmarshal(data, a); err != nil {
		return nil, err
	}
	return a, nil
}
