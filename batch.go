// Copyright 2023 Weald Technology Trading.
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
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	e2types "github.com/wealdtech/go-eth2-types/v2"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

type batchEntry struct {
	id                 uuid.UUID
	name               string
	verificationVector [][]byte
	signingThreshold   uint32
	participants       map[string]string
	pubkey             []byte
}

type batch struct {
	entries   []*batchEntry
	crypto    map[string]any
	encryptor e2wtypes.Encryptor
}

// BatchWallet encrypts all accounts in to a single file, allowing for faster
// decryption of wallets with large numbers of accounts.
func (w *wallet) BatchWallet(ctx context.Context, passphrases []string, batchPassphrase string) error {
	w.batchMutex.Lock()
	defer w.batchMutex.Unlock()

	batchStorer, isBatchStorer := w.store.(e2wtypes.BatchStorer)
	if !isBatchStorer {
		return fmt.Errorf("store %s cannot store batches", w.store.Name())
	}

	accounts := make([]*account, 0, 1024)

	// Obtain and decrypt individual accounts directly from store.
	for data := range w.store.RetrieveAccounts(w.ID()) {
		if account, err := deserializeAccount(w, data); err == nil {
			unlocked := false
			for _, passphrase := range passphrases {
				if err := account.Unlock(ctx, []byte(passphrase)); err == nil {
					unlocked = true
					break
				}
			}
			if !unlocked {
				return fmt.Errorf("unable to decrypt account %q with supplied passphrases", account.name)
			}

			accounts = append(accounts, account)
		}
	}

	batchEntries := make([]*batchEntry, len(accounts))
	secretKeys := make([]byte, 0, 32*len(accounts))
	for i, account := range accounts {
		verificationVector := make([][]byte, 0, len(account.verificationVector))
		for _, v := range account.verificationVector {
			verificationVector = append(verificationVector, v.Marshal())
		}
		participants := make(map[string]string, len(account.participants))
		for k, v := range account.participants {
			participants[fmt.Sprintf("%d", k)] = v
		}
		batchEntries[i] = &batchEntry{
			id:                 account.id,
			name:               account.name,
			verificationVector: verificationVector,
			signingThreshold:   account.signingThreshold,
			participants:       participants,
			pubkey:             account.publicKey.Marshal(),
		}
		secretKeys = append(secretKeys, account.secretKey.Marshal()...)
	}

	crypto, err := w.encryptor.Encrypt(secretKeys, batchPassphrase)
	if err != nil {
		return errors.Wrap(err, "failed to encrypt batch")
	}

	data := &batch{
		entries:   batchEntries,
		crypto:    crypto,
		encryptor: w.encryptor,
	}
	batch, err := json.Marshal(data)
	if err != nil {
		return errors.Wrap(err, "failed to marshal batch")
	}
	if err := batchStorer.StoreBatch(ctx, w.id, w.name, batch); err != nil {
		return errors.Wrap(err, "failed to store batch")
	}

	return nil
}

// retrieveAccountsBatch retrieves the batched accounts for a wallet.
func (w *wallet) retrieveAccountsBatch(ctx context.Context) error {
	w.batchMutex.Lock()
	defer w.batchMutex.Unlock()

	if w.batch != nil {
		// The batch has been retrieved whilst we were waiting for the lock.
		return nil
	}

	// Place a marker on the batch so that if we error out we don't
	// keep coming back and trying again.
	w.batch = &batch{}

	batchRetriever, isBatchRetriever := w.store.(e2wtypes.BatchRetriever)
	if !isBatchRetriever {
		return errors.New("not a batch retriever")
	}

	serializedBatch, err := batchRetriever.RetrieveBatch(ctx, w.id)
	if err != nil {
		return errors.Wrap(err, "failed to retrieve batch")
	}
	res := &batch{}
	if err := json.Unmarshal(serializedBatch, res); err != nil {
		return errors.Wrap(err, "failed to unmarshal batch")
	}
	w.batch = res

	// Create individual accounts from the batch.
	for i := range res.entries {
		publicKey, err := e2types.BLSPublicKeyFromBytes(res.entries[i].pubkey)
		if err != nil {
			return errors.Wrap(err, "invalid public key")
		}
		verificationVector := make([]e2types.PublicKey, len(res.entries[i].verificationVector))
		for j, v := range res.entries[i].verificationVector {
			verificationVector[j], err = e2types.BLSPublicKeyFromBytes(v)
			if err != nil {
				return errors.Wrapf(err, "invalid verification vector %d", j)
			}
		}
		participants := make(map[uint64]string, len(res.entries[i].participants))
		for k, v := range res.entries[i].participants {
			id, err := strconv.ParseUint(k, 10, 64)
			if err != nil {
				return errors.Wrap(err, "invalid participant ID")
			}
			participants[id] = v
		}
		account := &account{
			id:   res.entries[i].id,
			name: res.entries[i].name,
			// We do not populate crypto, as the secret is in the batch.
			verificationVector: verificationVector,
			signingThreshold:   res.entries[i].signingThreshold,
			participants:       participants,
			publicKey:          publicKey,
			version:            version,
			wallet:             w,
			encryptor:          w.encryptor,
		}
		w.accounts[account.id] = account
	}

	return nil
}

// batchDecrypt decrypts a batch of accounts.
func (w *wallet) batchDecrypt(_ context.Context, passphrase []byte) error {
	w.batchMutex.Lock()
	defer w.batchMutex.Unlock()

	if w.batchDecrypted {
		// Means the batch was decrypted by another thread; all good.
		return nil
	}

	if w.batch == nil || w.batch.crypto == nil {
		return errors.New("no batch to decrypt")
	}

	secretBytes, err := w.encryptor.Decrypt(w.batch.crypto, string(passphrase))
	if err != nil {
		return errors.Wrap(err, "failed to decrypt data")
	}
	for i := range w.batch.entries {
		if w.accounts[w.batch.entries[i].id].secretKey != nil {
			// Already have this key.
			continue
		}
		secretKey, err := e2types.BLSPrivateKeyFromBytes(secretBytes[i*32 : (i+1)*32])
		if err != nil {
			return errors.Wrap(err, "invalid private key")
		}
		publicKey := secretKey.PublicKey()
		if !bytes.Equal(publicKey.Marshal(), w.accounts[w.batch.entries[i].id].publicKey.Marshal()) {
			return errors.New("secret key does not correspond to public key")
		}
		w.accounts[w.batch.entries[i].id].secretKey = secretKey
	}

	w.batchDecrypted = true

	return nil
}
