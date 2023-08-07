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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	keystorev4 "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"
)

type batchEntryJSON struct {
	UUID               uuid.UUID         `json:"uuid"`
	Name               string            `json:"name"`
	VerificationVector []string          `json:"verification_vector"`
	SigningThreshold   string            `json:"signing_threshold"`
	Participants       map[string]string `json:"participants"`
	Pubkey             string            `json:"pubkey"`
}

func (b *batchEntry) MarshalJSON() ([]byte, error) {
	verificationVector := make([]string, len(b.verificationVector))
	for i := range b.verificationVector {
		verificationVector[i] = fmt.Sprintf("%x", b.verificationVector[i])
	}

	return json.Marshal(&batchEntryJSON{
		UUID:               b.id,
		Name:               b.name,
		VerificationVector: verificationVector,
		SigningThreshold:   fmt.Sprintf("%d", b.signingThreshold),
		Participants:       b.participants,
		Pubkey:             fmt.Sprintf("%x", b.pubkey),
	})
}

func (b *batchEntry) UnmarshalJSON(input []byte) error {
	data := batchEntryJSON{}
	if err := json.Unmarshal(input, &data); err != nil {
		return errors.Wrap(err, "invalid JSON")
	}
	b.id = data.UUID
	b.name = data.Name
	var err error
	b.verificationVector = make([][]byte, len(data.VerificationVector))
	for i := range data.VerificationVector {
		b.verificationVector[i], err = hex.DecodeString(strings.TrimPrefix(data.VerificationVector[i], "0x"))
		if err != nil {
			return errors.Wrapf(err, "invalid verification vector %d", i)
		}
	}
	signingThreshold, err := strconv.ParseUint(data.SigningThreshold, 10, 32)
	if err != nil {
		return errors.Wrap(err, "failed to parse signing threshold")
	}
	b.signingThreshold = uint32(signingThreshold)
	b.participants = data.Participants
	b.pubkey, err = hex.DecodeString(strings.TrimPrefix(data.Pubkey, "0x"))
	if err != nil {
		return errors.Wrap(err, "invalid pubkey")
	}

	return nil
}

type batchJSON struct {
	Entries   []*batchEntry  `json:"entries"`
	Crypto    map[string]any `json:"crypto"`
	Encryptor string         `json:"encryptor"`
	Version   int            `json:"version"`
}

func (b *batch) MarshalJSON() ([]byte, error) {
	data := &batchJSON{
		Entries:   b.entries,
		Crypto:    b.crypto,
		Encryptor: b.encryptor.String(),
		Version:   version,
	}

	return json.Marshal(data)
}

func (b *batch) UnmarshalJSON(input []byte) error {
	data := batchJSON{}
	if err := json.Unmarshal(input, &data); err != nil {
		return errors.Wrap(err, "invalid JSON")
	}
	if data.Version != version {
		return fmt.Errorf("unsupported version %d", data.Version)
	}
	b.entries = data.Entries
	switch data.Encryptor {
	case "keystorev4":
		b.encryptor = keystorev4.New()
	default:
		return fmt.Errorf("unsupported encryptor %s", data.Encryptor)
	}
	b.crypto = data.Crypto

	return nil
}
