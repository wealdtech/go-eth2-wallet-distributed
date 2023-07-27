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

package distributed

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	e2types "github.com/wealdtech/go-eth2-types/v2"
)

func TestMain(m *testing.M) {
	if err := e2types.InitBLS(); err != nil {
		os.Exit(1)
	}
	os.Exit(m.Run())
}

func TestUnmarshalAccount(t *testing.T) {
	tests := []struct {
		name      string
		input     []byte
		err       string
		id        uuid.UUID
		version   uint
		publicKey []byte
	}{
		{
			name: "Nil",
			err:  "unexpected end of JSON input",
		},
		{
			name:  "Empty",
			input: []byte{},
			err:   "unexpected end of JSON input",
		},
		{
			name:  "Blank",
			input: []byte(""),
			err:   "unexpected end of JSON input",
		},
		{
			name:  "NotJSON",
			input: []byte(`bad`),
			err:   `invalid character 'b' looking for beginning of value`,
		},
		{
			name:  "MissingID",
			input: []byte(`{"crypto":{"checksum":{"function":"sha256","message":"5b2b545965b45bca2ea3cc47d3ec948e7b2270117f480886804fb8f38659538c","params":{}},"cipher":{"function":"aes-128-ctr","message":"e102b4647c602d58ceecd16c58b5001fb9cfae987664081cc47d73d22e2e12f4","params":{"iv":"a268c48c48bd568f1b03153b45669f31"}},"kdf":{"function":"pbkdf2","message":"","params":{"c":16,"dklen":32,"prf":"hmac-sha256","salt":"344d372d72bdabecd89d30d3cb14d5355b2801b2aa75b08dfeb0711f60f91c07"}}},"encryptor":"keystore","name":"Test account","participants":{"1":"signer-l01.attestant.io:8881","2":"signer-l02.attestant.io:8882","3":"signer-l03.attestant.io:8883"},"pubkey":"a304edb3fd6517ac7b58b9fdba472315adc1fcf9a519a081d0d855e0d65c0e23ea01f801951afa933507f98fc2a900d4","signing_threshold":2,"verificationvector":["b71f3dc08d96fa8b6afacc3d4c9942ec8c8eab6a2b4ee6e885ec34629e672a0f8b7741226df2071ff39afb8b9a08054e","a3a586504cfd4ccca23d0e4b4d198a59f54b5eb1a65e0c7ff2d14f1e8e6667aa45ac0eceb58b805a13e39ab76a2e601e"],"version":4}`),
			err:   "account ID missing",
		},
		{
			name:  "WrongID",
			input: []byte(`{"crypto":{"checksum":{"function":"sha256","message":"5b2b545965b45bca2ea3cc47d3ec948e7b2270117f480886804fb8f38659538c","params":{}},"cipher":{"function":"aes-128-ctr","message":"e102b4647c602d58ceecd16c58b5001fb9cfae987664081cc47d73d22e2e12f4","params":{"iv":"a268c48c48bd568f1b03153b45669f31"}},"kdf":{"function":"pbkdf2","message":"","params":{"c":16,"dklen":32,"prf":"hmac-sha256","salt":"344d372d72bdabecd89d30d3cb14d5355b2801b2aa75b08dfeb0711f60f91c07"}}},"encryptor":"keystore","name":"Test account","participants":{"1":"signer-l01.attestant.io:8881","2":"signer-l02.attestant.io:8882","3":"signer-l03.attestant.io:8883"},"pubkey":"a304edb3fd6517ac7b58b9fdba472315adc1fcf9a519a081d0d855e0d65c0e23ea01f801951afa933507f98fc2a900d4","signing_threshold":2,"uuid":true,"verificationvector":["b71f3dc08d96fa8b6afacc3d4c9942ec8c8eab6a2b4ee6e885ec34629e672a0f8b7741226df2071ff39afb8b9a08054e","a3a586504cfd4ccca23d0e4b4d198a59f54b5eb1a65e0c7ff2d14f1e8e6667aa45ac0eceb58b805a13e39ab76a2e601e"],"version":4}`),
			err:   "account ID invalid",
		},
		{
			name:  "BadID",
			input: []byte(`{"crypto":{"checksum":{"function":"sha256","message":"5b2b545965b45bca2ea3cc47d3ec948e7b2270117f480886804fb8f38659538c","params":{}},"cipher":{"function":"aes-128-ctr","message":"e102b4647c602d58ceecd16c58b5001fb9cfae987664081cc47d73d22e2e12f4","params":{"iv":"a268c48c48bd568f1b03153b45669f31"}},"kdf":{"function":"pbkdf2","message":"","params":{"c":16,"dklen":32,"prf":"hmac-sha256","salt":"344d372d72bdabecd89d30d3cb14d5355b2801b2aa75b08dfeb0711f60f91c07"}}},"encryptor":"keystore","name":"Test account","participants":{"1":"signer-l01.attestant.io:8881","2":"signer-l02.attestant.io:8882","3":"signer-l03.attestant.io:8883"},"pubkey":"a304edb3fd6517ac7b58b9fdba472315adc1fcf9a519a081d0d855e0d65c0e23ea01f801951afa933507f98fc2a900d4","signing_threshold":2,"uuid":"foo","verificationvector":["b71f3dc08d96fa8b6afacc3d4c9942ec8c8eab6a2b4ee6e885ec34629e672a0f8b7741226df2071ff39afb8b9a08054e","a3a586504cfd4ccca23d0e4b4d198a59f54b5eb1a65e0c7ff2d14f1e8e6667aa45ac0eceb58b805a13e39ab76a2e601e"],"version":4}`),
			err:   "invalid UUID length: 3",
		},
		{
			name:  "MissingName",
			input: []byte(`{"crypto":{"checksum":{"function":"sha256","message":"5b2b545965b45bca2ea3cc47d3ec948e7b2270117f480886804fb8f38659538c","params":{}},"cipher":{"function":"aes-128-ctr","message":"e102b4647c602d58ceecd16c58b5001fb9cfae987664081cc47d73d22e2e12f4","params":{"iv":"a268c48c48bd568f1b03153b45669f31"}},"kdf":{"function":"pbkdf2","message":"","params":{"c":16,"dklen":32,"prf":"hmac-sha256","salt":"344d372d72bdabecd89d30d3cb14d5355b2801b2aa75b08dfeb0711f60f91c07"}}},"encryptor":"keystore","participants":{"1":"signer-l01.attestant.io:8881","2":"signer-l02.attestant.io:8882","3":"signer-l03.attestant.io:8883"},"pubkey":"a304edb3fd6517ac7b58b9fdba472315adc1fcf9a519a081d0d855e0d65c0e23ea01f801951afa933507f98fc2a900d4","signing_threshold":2,"uuid":"0ea52ae0-b04a-4582-adc7-149b0a83c030","verificationvector":["b71f3dc08d96fa8b6afacc3d4c9942ec8c8eab6a2b4ee6e885ec34629e672a0f8b7741226df2071ff39afb8b9a08054e","a3a586504cfd4ccca23d0e4b4d198a59f54b5eb1a65e0c7ff2d14f1e8e6667aa45ac0eceb58b805a13e39ab76a2e601e"],"version":4}`),
			err:   "account name missing",
		},
		{
			name:  "WrongName",
			input: []byte(`{"crypto":{"checksum":{"function":"sha256","message":"5b2b545965b45bca2ea3cc47d3ec948e7b2270117f480886804fb8f38659538c","params":{}},"cipher":{"function":"aes-128-ctr","message":"e102b4647c602d58ceecd16c58b5001fb9cfae987664081cc47d73d22e2e12f4","params":{"iv":"a268c48c48bd568f1b03153b45669f31"}},"kdf":{"function":"pbkdf2","message":"","params":{"c":16,"dklen":32,"prf":"hmac-sha256","salt":"344d372d72bdabecd89d30d3cb14d5355b2801b2aa75b08dfeb0711f60f91c07"}}},"encryptor":"keystore","name":true,"participants":{"1":"signer-l01.attestant.io:8881","2":"signer-l02.attestant.io:8882","3":"signer-l03.attestant.io:8883"},"pubkey":"a304edb3fd6517ac7b58b9fdba472315adc1fcf9a519a081d0d855e0d65c0e23ea01f801951afa933507f98fc2a900d4","signing_threshold":2,"uuid":"0ea52ae0-b04a-4582-adc7-149b0a83c030","verificationvector":["b71f3dc08d96fa8b6afacc3d4c9942ec8c8eab6a2b4ee6e885ec34629e672a0f8b7741226df2071ff39afb8b9a08054e","a3a586504cfd4ccca23d0e4b4d198a59f54b5eb1a65e0c7ff2d14f1e8e6667aa45ac0eceb58b805a13e39ab76a2e601e"],"version":4}`),
			err:   "account name invalid",
		},
		{
			name:  "MissingCrypto",
			input: []byte(`{"encryptor":"keystore","name":"Test account","participants":{"1":"signer-l01.attestant.io:8881","2":"signer-l02.attestant.io:8882","3":"signer-l03.attestant.io:8883"},"pubkey":"a304edb3fd6517ac7b58b9fdba472315adc1fcf9a519a081d0d855e0d65c0e23ea01f801951afa933507f98fc2a900d4","signing_threshold":2,"uuid":"0ea52ae0-b04a-4582-adc7-149b0a83c030","verificationvector":["b71f3dc08d96fa8b6afacc3d4c9942ec8c8eab6a2b4ee6e885ec34629e672a0f8b7741226df2071ff39afb8b9a08054e","a3a586504cfd4ccca23d0e4b4d198a59f54b5eb1a65e0c7ff2d14f1e8e6667aa45ac0eceb58b805a13e39ab76a2e601e"],"version":4}`),
			err:   "account crypto missing",
		},
		{
			name:  "BadCrypto",
			input: []byte(`{"crypto":true,"encryptor":"keystore","name":"Test account","participants":{"1":"signer-l01.attestant.io:8881","2":"signer-l02.attestant.io:8882","3":"signer-l03.attestant.io:8883"},"pubkey":"a304edb3fd6517ac7b58b9fdba472315adc1fcf9a519a081d0d855e0d65c0e23ea01f801951afa933507f98fc2a900d4","signing_threshold":2,"uuid":"0ea52ae0-b04a-4582-adc7-149b0a83c030","verificationvector":["b71f3dc08d96fa8b6afacc3d4c9942ec8c8eab6a2b4ee6e885ec34629e672a0f8b7741226df2071ff39afb8b9a08054e","a3a586504cfd4ccca23d0e4b4d198a59f54b5eb1a65e0c7ff2d14f1e8e6667aa45ac0eceb58b805a13e39ab76a2e601e"],"version":4}`),
			err:   "account crypto invalid",
		},
		{
			name:  "MissingVersion",
			input: []byte(`{"crypto":{"checksum":{"function":"sha256","message":"5b2b545965b45bca2ea3cc47d3ec948e7b2270117f480886804fb8f38659538c","params":{}},"cipher":{"function":"aes-128-ctr","message":"e102b4647c602d58ceecd16c58b5001fb9cfae987664081cc47d73d22e2e12f4","params":{"iv":"a268c48c48bd568f1b03153b45669f31"}},"kdf":{"function":"pbkdf2","message":"","params":{"c":16,"dklen":32,"prf":"hmac-sha256","salt":"344d372d72bdabecd89d30d3cb14d5355b2801b2aa75b08dfeb0711f60f91c07"}}},"encryptor":"keystore","name":"Test account","participants":{"1":"signer-l01.attestant.io:8881","2":"signer-l02.attestant.io:8882","3":"signer-l03.attestant.io:8883"},"pubkey":"a304edb3fd6517ac7b58b9fdba472315adc1fcf9a519a081d0d855e0d65c0e23ea01f801951afa933507f98fc2a900d4","signing_threshold":2,"uuid":"0ea52ae0-b04a-4582-adc7-149b0a83c030","verificationvector":["b71f3dc08d96fa8b6afacc3d4c9942ec8c8eab6a2b4ee6e885ec34629e672a0f8b7741226df2071ff39afb8b9a08054e","a3a586504cfd4ccca23d0e4b4d198a59f54b5eb1a65e0c7ff2d14f1e8e6667aa45ac0eceb58b805a13e39ab76a2e601e"]}`),
			err:   "account version missing",
		},
		{
			name:  "BadVersion",
			input: []byte(`{"crypto":{"checksum":{"function":"sha256","message":"5b2b545965b45bca2ea3cc47d3ec948e7b2270117f480886804fb8f38659538c","params":{}},"cipher":{"function":"aes-128-ctr","message":"e102b4647c602d58ceecd16c58b5001fb9cfae987664081cc47d73d22e2e12f4","params":{"iv":"a268c48c48bd568f1b03153b45669f31"}},"kdf":{"function":"pbkdf2","message":"","params":{"c":16,"dklen":32,"prf":"hmac-sha256","salt":"344d372d72bdabecd89d30d3cb14d5355b2801b2aa75b08dfeb0711f60f91c07"}}},"encryptor":"keystore","name":"Test account","participants":{"1":"signer-l01.attestant.io:8881","2":"signer-l02.attestant.io:8882","3":"signer-l03.attestant.io:8883"},"pubkey":"a304edb3fd6517ac7b58b9fdba472315adc1fcf9a519a081d0d855e0d65c0e23ea01f801951afa933507f98fc2a900d4","signing_threshold":2,"uuid":"0ea52ae0-b04a-4582-adc7-149b0a83c030","verificationvector":["b71f3dc08d96fa8b6afacc3d4c9942ec8c8eab6a2b4ee6e885ec34629e672a0f8b7741226df2071ff39afb8b9a08054e","a3a586504cfd4ccca23d0e4b4d198a59f54b5eb1a65e0c7ff2d14f1e8e6667aa45ac0eceb58b805a13e39ab76a2e601e"],"version":true}`),
			err:   "account version invalid",
		},
		{
			name:  "WrongVersion",
			input: []byte(`{"crypto":{"checksum":{"function":"sha256","message":"5b2b545965b45bca2ea3cc47d3ec948e7b2270117f480886804fb8f38659538c","params":{}},"cipher":{"function":"aes-128-ctr","message":"e102b4647c602d58ceecd16c58b5001fb9cfae987664081cc47d73d22e2e12f4","params":{"iv":"a268c48c48bd568f1b03153b45669f31"}},"kdf":{"function":"pbkdf2","message":"","params":{"c":16,"dklen":32,"prf":"hmac-sha256","salt":"344d372d72bdabecd89d30d3cb14d5355b2801b2aa75b08dfeb0711f60f91c07"}}},"encryptor":"keystore","name":"Test account","participants":{"1":"signer-l01.attestant.io:8881","2":"signer-l02.attestant.io:8882","3":"signer-l03.attestant.io:8883"},"pubkey":"a304edb3fd6517ac7b58b9fdba472315adc1fcf9a519a081d0d855e0d65c0e23ea01f801951afa933507f98fc2a900d4","signing_threshold":2,"uuid":"0ea52ae0-b04a-4582-adc7-149b0a83c030","verificationvector":["b71f3dc08d96fa8b6afacc3d4c9942ec8c8eab6a2b4ee6e885ec34629e672a0f8b7741226df2071ff39afb8b9a08054e","a3a586504cfd4ccca23d0e4b4d198a59f54b5eb1a65e0c7ff2d14f1e8e6667aa45ac0eceb58b805a13e39ab76a2e601e"],"version":99}`),
			err:   "unsupported keystore version",
		},
		{
			name:  "MissingParticipants",
			input: []byte(`{"crypto":{"checksum":{"function":"sha256","message":"5b2b545965b45bca2ea3cc47d3ec948e7b2270117f480886804fb8f38659538c","params":{}},"cipher":{"function":"aes-128-ctr","message":"e102b4647c602d58ceecd16c58b5001fb9cfae987664081cc47d73d22e2e12f4","params":{"iv":"a268c48c48bd568f1b03153b45669f31"}},"kdf":{"function":"pbkdf2","message":"","params":{"c":16,"dklen":32,"prf":"hmac-sha256","salt":"344d372d72bdabecd89d30d3cb14d5355b2801b2aa75b08dfeb0711f60f91c07"}}},"encryptor":"keystore","name":"Test account","pubkey":"a304edb3fd6517ac7b58b9fdba472315adc1fcf9a519a081d0d855e0d65c0e23ea01f801951afa933507f98fc2a900d4","signing_threshold":2,"uuid":"0ea52ae0-b04a-4582-adc7-149b0a83c030","verificationvector":["b71f3dc08d96fa8b6afacc3d4c9942ec8c8eab6a2b4ee6e885ec34629e672a0f8b7741226df2071ff39afb8b9a08054e","a3a586504cfd4ccca23d0e4b4d198a59f54b5eb1a65e0c7ff2d14f1e8e6667aa45ac0eceb58b805a13e39ab76a2e601e"],"version":4}`),
			err:   "participants missing",
		},
		{
			name:  "BadParticipants",
			input: []byte(`{"crypto":{"checksum":{"function":"sha256","message":"5b2b545965b45bca2ea3cc47d3ec948e7b2270117f480886804fb8f38659538c","params":{}},"cipher":{"function":"aes-128-ctr","message":"e102b4647c602d58ceecd16c58b5001fb9cfae987664081cc47d73d22e2e12f4","params":{"iv":"a268c48c48bd568f1b03153b45669f31"}},"kdf":{"function":"pbkdf2","message":"","params":{"c":16,"dklen":32,"prf":"hmac-sha256","salt":"344d372d72bdabecd89d30d3cb14d5355b2801b2aa75b08dfeb0711f60f91c07"}}},"encryptor":"keystore","name":"Test account","participants":true,"pubkey":"a304edb3fd6517ac7b58b9fdba472315adc1fcf9a519a081d0d855e0d65c0e23ea01f801951afa933507f98fc2a900d4","signing_threshold":2,"uuid":"0ea52ae0-b04a-4582-adc7-149b0a83c030","verificationvector":["b71f3dc08d96fa8b6afacc3d4c9942ec8c8eab6a2b4ee6e885ec34629e672a0f8b7741226df2071ff39afb8b9a08054e","a3a586504cfd4ccca23d0e4b4d198a59f54b5eb1a65e0c7ff2d14f1e8e6667aa45ac0eceb58b805a13e39ab76a2e601e"],"version":4}`),
			err:   "account participants invalid",
		},
		{
			name:  "WrongParticipants",
			input: []byte(`{"crypto":{"checksum":{"function":"sha256","message":"5b2b545965b45bca2ea3cc47d3ec948e7b2270117f480886804fb8f38659538c","params":{}},"cipher":{"function":"aes-128-ctr","message":"e102b4647c602d58ceecd16c58b5001fb9cfae987664081cc47d73d22e2e12f4","params":{"iv":"a268c48c48bd568f1b03153b45669f31"}},"kdf":{"function":"pbkdf2","message":"","params":{"c":16,"dklen":32,"prf":"hmac-sha256","salt":"344d372d72bdabecd89d30d3cb14d5355b2801b2aa75b08dfeb0711f60f91c07"}}},"encryptor":"keystore","name":"Test account","participants":{"1":true,"2":true,"3":true},"pubkey":"a304edb3fd6517ac7b58b9fdba472315adc1fcf9a519a081d0d855e0d65c0e23ea01f801951afa933507f98fc2a900d4","signing_threshold":2,"uuid":"0ea52ae0-b04a-4582-adc7-149b0a83c030","verificationvector":["b71f3dc08d96fa8b6afacc3d4c9942ec8c8eab6a2b4ee6e885ec34629e672a0f8b7741226df2071ff39afb8b9a08054e","a3a586504cfd4ccca23d0e4b4d198a59f54b5eb1a65e0c7ff2d14f1e8e6667aa45ac0eceb58b805a13e39ab76a2e601e"],"version":4}`),
			err:   "account participant value invalid",
		},
		{
			name:  "InvalidParticipants",
			input: []byte(`{"crypto":{"checksum":{"function":"sha256","message":"5b2b545965b45bca2ea3cc47d3ec948e7b2270117f480886804fb8f38659538c","params":{}},"cipher":{"function":"aes-128-ctr","message":"e102b4647c602d58ceecd16c58b5001fb9cfae987664081cc47d73d22e2e12f4","params":{"iv":"a268c48c48bd568f1b03153b45669f31"}},"kdf":{"function":"pbkdf2","message":"","params":{"c":16,"dklen":32,"prf":"hmac-sha256","salt":"344d372d72bdabecd89d30d3cb14d5355b2801b2aa75b08dfeb0711f60f91c07"}}},"encryptor":"keystore","name":"Test account","participants":"signer-l01.attestant.io:8881","pubkey":"a304edb3fd6517ac7b58b9fdba472315adc1fcf9a519a081d0d855e0d65c0e23ea01f801951afa933507f98fc2a900d4","signing_threshold":2,"uuid":"0ea52ae0-b04a-4582-adc7-149b0a83c030","verificationvector":["b71f3dc08d96fa8b6afacc3d4c9942ec8c8eab6a2b4ee6e885ec34629e672a0f8b7741226df2071ff39afb8b9a08054e","a3a586504cfd4ccca23d0e4b4d198a59f54b5eb1a65e0c7ff2d14f1e8e6667aa45ac0eceb58b805a13e39ab76a2e601e"],"version":4}`),
			err:   `account participants invalid`,
		},
		{
			name:  "MissingSigningThreshold",
			input: []byte(`{"crypto":{"checksum":{"function":"sha256","message":"5b2b545965b45bca2ea3cc47d3ec948e7b2270117f480886804fb8f38659538c","params":{}},"cipher":{"function":"aes-128-ctr","message":"e102b4647c602d58ceecd16c58b5001fb9cfae987664081cc47d73d22e2e12f4","params":{"iv":"a268c48c48bd568f1b03153b45669f31"}},"kdf":{"function":"pbkdf2","message":"","params":{"c":16,"dklen":32,"prf":"hmac-sha256","salt":"344d372d72bdabecd89d30d3cb14d5355b2801b2aa75b08dfeb0711f60f91c07"}}},"encryptor":"keystore","name":"Test account","participants":{"1":"signer-l01.attestant.io:8881","2":"signer-l02.attestant.io:8882","3":"signer-l03.attestant.io:8883"},"pubkey":"a304edb3fd6517ac7b58b9fdba472315adc1fcf9a519a081d0d855e0d65c0e23ea01f801951afa933507f98fc2a900d4","uuid":"0ea52ae0-b04a-4582-adc7-149b0a83c030","verificationvector":["b71f3dc08d96fa8b6afacc3d4c9942ec8c8eab6a2b4ee6e885ec34629e672a0f8b7741226df2071ff39afb8b9a08054e","a3a586504cfd4ccca23d0e4b4d198a59f54b5eb1a65e0c7ff2d14f1e8e6667aa45ac0eceb58b805a13e39ab76a2e601e"],"version":4}`),
			err:   "account signing threshold missing",
		},
		{
			name:  "BadSigningThreshold",
			input: []byte(`{"crypto":{"checksum":{"function":"sha256","message":"5b2b545965b45bca2ea3cc47d3ec948e7b2270117f480886804fb8f38659538c","params":{}},"cipher":{"function":"aes-128-ctr","message":"e102b4647c602d58ceecd16c58b5001fb9cfae987664081cc47d73d22e2e12f4","params":{"iv":"a268c48c48bd568f1b03153b45669f31"}},"kdf":{"function":"pbkdf2","message":"","params":{"c":16,"dklen":32,"prf":"hmac-sha256","salt":"344d372d72bdabecd89d30d3cb14d5355b2801b2aa75b08dfeb0711f60f91c07"}}},"encryptor":"keystore","name":"Test account","participants":{"1":"signer-l01.attestant.io:8881","2":"signer-l02.attestant.io:8882","3":"signer-l03.attestant.io:8883"},"pubkey":"a304edb3fd6517ac7b58b9fdba472315adc1fcf9a519a081d0d855e0d65c0e23ea01f801951afa933507f98fc2a900d4","signing_threshold":1,"uuid":"0ea52ae0-b04a-4582-adc7-149b0a83c030","verificationvector":["b71f3dc08d96fa8b6afacc3d4c9942ec8c8eab6a2b4ee6e885ec34629e672a0f8b7741226df2071ff39afb8b9a08054e","a3a586504cfd4ccca23d0e4b4d198a59f54b5eb1a65e0c7ff2d14f1e8e6667aa45ac0eceb58b805a13e39ab76a2e601e"],"version":4}`),
			err:   "account signing threshold too low",
		},
		{
			name:  "WrongSigningThreshold",
			input: []byte(`{"crypto":{"checksum":{"function":"sha256","message":"5b2b545965b45bca2ea3cc47d3ec948e7b2270117f480886804fb8f38659538c","params":{}},"cipher":{"function":"aes-128-ctr","message":"e102b4647c602d58ceecd16c58b5001fb9cfae987664081cc47d73d22e2e12f4","params":{"iv":"a268c48c48bd568f1b03153b45669f31"}},"kdf":{"function":"pbkdf2","message":"","params":{"c":16,"dklen":32,"prf":"hmac-sha256","salt":"344d372d72bdabecd89d30d3cb14d5355b2801b2aa75b08dfeb0711f60f91c07"}}},"encryptor":"keystore","name":"Test account","participants":{"1":"signer-l01.attestant.io:8881","2":"signer-l02.attestant.io:8882","3":"signer-l03.attestant.io:8883"},"pubkey":"a304edb3fd6517ac7b58b9fdba472315adc1fcf9a519a081d0d855e0d65c0e23ea01f801951afa933507f98fc2a900d4","signing_threshold":"two","uuid":"0ea52ae0-b04a-4582-adc7-149b0a83c030","verificationvector":["b71f3dc08d96fa8b6afacc3d4c9942ec8c8eab6a2b4ee6e885ec34629e672a0f8b7741226df2071ff39afb8b9a08054e","a3a586504cfd4ccca23d0e4b4d198a59f54b5eb1a65e0c7ff2d14f1e8e6667aa45ac0eceb58b805a13e39ab76a2e601e"],"version":4}`),
			err:   "account signing threshold invalid",
		},
		{
			name:  "MissingVerificationVector",
			input: []byte(`{"crypto":{"checksum":{"function":"sha256","message":"5b2b545965b45bca2ea3cc47d3ec948e7b2270117f480886804fb8f38659538c","params":{}},"cipher":{"function":"aes-128-ctr","message":"e102b4647c602d58ceecd16c58b5001fb9cfae987664081cc47d73d22e2e12f4","params":{"iv":"a268c48c48bd568f1b03153b45669f31"}},"kdf":{"function":"pbkdf2","message":"","params":{"c":16,"dklen":32,"prf":"hmac-sha256","salt":"344d372d72bdabecd89d30d3cb14d5355b2801b2aa75b08dfeb0711f60f91c07"}}},"encryptor":"keystore","name":"Test account","participants":{"1":"signer-l01.attestant.io:8881","2":"signer-l02.attestant.io:8882","3":"signer-l03.attestant.io:8883"},"pubkey":"a304edb3fd6517ac7b58b9fdba472315adc1fcf9a519a081d0d855e0d65c0e23ea01f801951afa933507f98fc2a900d4","signing_threshold":2,"uuid":"0ea52ae0-b04a-4582-adc7-149b0a83c030","version":4}`),
			err:   "account verificationvector missing",
		},
		{
			name:  "BadVerificationVector",
			input: []byte(`{"crypto":{"checksum":{"function":"sha256","message":"5b2b545965b45bca2ea3cc47d3ec948e7b2270117f480886804fb8f38659538c","params":{}},"cipher":{"function":"aes-128-ctr","message":"e102b4647c602d58ceecd16c58b5001fb9cfae987664081cc47d73d22e2e12f4","params":{"iv":"a268c48c48bd568f1b03153b45669f31"}},"kdf":{"function":"pbkdf2","message":"","params":{"c":16,"dklen":32,"prf":"hmac-sha256","salt":"344d372d72bdabecd89d30d3cb14d5355b2801b2aa75b08dfeb0711f60f91c07"}}},"encryptor":"keystore","name":"Test account","participants":{"1":"signer-l01.attestant.io:8881","2":"signer-l02.attestant.io:8882","3":"signer-l03.attestant.io:8883"},"pubkey":"a304edb3fd6517ac7b58b9fdba472315adc1fcf9a519a081d0d855e0d65c0e23ea01f801951afa933507f98fc2a900d4","signing_threshold":2,"uuid":"0ea52ae0-b04a-4582-adc7-149b0a83c030","verificationvector":true,"version":4}`),
			err:   "account verificationvector invalid",
		},
		{
			name:  "BadVerificationVector2",
			input: []byte(`{"crypto":{"checksum":{"function":"sha256","message":"5b2b545965b45bca2ea3cc47d3ec948e7b2270117f480886804fb8f38659538c","params":{}},"cipher":{"function":"aes-128-ctr","message":"e102b4647c602d58ceecd16c58b5001fb9cfae987664081cc47d73d22e2e12f4","params":{"iv":"a268c48c48bd568f1b03153b45669f31"}},"kdf":{"function":"pbkdf2","message":"","params":{"c":16,"dklen":32,"prf":"hmac-sha256","salt":"344d372d72bdabecd89d30d3cb14d5355b2801b2aa75b08dfeb0711f60f91c07"}}},"encryptor":"keystore","name":"Test account","participants":{"1":"signer-l01.attestant.io:8881","2":"signer-l02.attestant.io:8882","3":"signer-l03.attestant.io:8883"},"pubkey":"a304edb3fd6517ac7b58b9fdba472315adc1fcf9a519a081d0d855e0d65c0e23ea01f801951afa933507f98fc2a900d4","signing_threshold":2,"uuid":"0ea52ae0-b04a-4582-adc7-149b0a83c030","verificationvector":[true, true],"version":4}`),
			err:   "account verification vector does not contain strings",
		},
		{
			name:  "BadVerificationVector3",
			input: []byte(`{"crypto":{"checksum":{"function":"sha256","message":"5b2b545965b45bca2ea3cc47d3ec948e7b2270117f480886804fb8f38659538c","params":{}},"cipher":{"function":"aes-128-ctr","message":"e102b4647c602d58ceecd16c58b5001fb9cfae987664081cc47d73d22e2e12f4","params":{"iv":"a268c48c48bd568f1b03153b45669f31"}},"kdf":{"function":"pbkdf2","message":"","params":{"c":16,"dklen":32,"prf":"hmac-sha256","salt":"344d372d72bdabecd89d30d3cb14d5355b2801b2aa75b08dfeb0711f60f91c07"}}},"encryptor":"keystore","name":"Test account","participants":{"1":"signer-l01.attestant.io:8881","2":"signer-l02.attestant.io:8882","3":"signer-l03.attestant.io:8883"},"pubkey":"a304edb3fd6517ac7b58b9fdba472315adc1fcf9a519a081d0d855e0d65c0e23ea01f801951afa933507f98fc2a900d4","signing_threshold":2,"uuid":"0ea52ae0-b04a-4582-adc7-149b0a83c030","verificationvector":["000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","a3a586504cfd4ccca23d0e4b4d198a59f54b5eb1a65e0c7ff2d14f1e8e6667aa45ac0eceb58b805a13e39ab76a2e601e"],"version":4}`),
			err:   "failed to deserialize public key: err blsPublicKeyDeserialize 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		},
		{
			name:  "WrongVerificationVector",
			input: []byte(`{"crypto":{"checksum":{"function":"sha256","message":"5b2b545965b45bca2ea3cc47d3ec948e7b2270117f480886804fb8f38659538c","params":{}},"cipher":{"function":"aes-128-ctr","message":"e102b4647c602d58ceecd16c58b5001fb9cfae987664081cc47d73d22e2e12f4","params":{"iv":"a268c48c48bd568f1b03153b45669f31"}},"kdf":{"function":"pbkdf2","message":"","params":{"c":16,"dklen":32,"prf":"hmac-sha256","salt":"344d372d72bdabecd89d30d3cb14d5355b2801b2aa75b08dfeb0711f60f91c07"}}},"encryptor":"keystore","name":"Test account","participants":{"1":"signer-l01.attestant.io:8881","2":"signer-l02.attestant.io:8882","3":"signer-l03.attestant.io:8883"},"pubkey":"a304edb3fd6517ac7b58b9fdba472315adc1fcf9a519a081d0d855e0d65c0e23ea01f801951afa933507f98fc2a900d4","signing_threshold":2,"uuid":"0ea52ae0-b04a-4582-adc7-149b0a83c030","verificationvector":["w71f3dc08d96fa8b6afacc3d4c9942ec8c8eab6a2b4ee6e885ec34629e672a0f8b7741226df2071ff39afb8b9a08054e","a3a586504cfd4ccca23d0e4b4d198a59f54b5eb1a65e0c7ff2d14f1e8e6667aa45ac0eceb58b805a13e39ab76a2e601e"],"version":4}`),
			err:   "encoding/hex: invalid byte: U+0077 'w'",
		},
		{
			name:      "Good",
			input:     []byte(`{"crypto":{"checksum":{"function":"sha256","message":"5b2b545965b45bca2ea3cc47d3ec948e7b2270117f480886804fb8f38659538c","params":{}},"cipher":{"function":"aes-128-ctr","message":"e102b4647c602d58ceecd16c58b5001fb9cfae987664081cc47d73d22e2e12f4","params":{"iv":"a268c48c48bd568f1b03153b45669f31"}},"kdf":{"function":"pbkdf2","message":"","params":{"c":16,"dklen":32,"prf":"hmac-sha256","salt":"344d372d72bdabecd89d30d3cb14d5355b2801b2aa75b08dfeb0711f60f91c07"}}},"encryptor":"keystore","name":"Test account","participants":{"1":"signer-l01.attestant.io:8881","2":"signer-l02.attestant.io:8882","3":"signer-l03.attestant.io:8883"},"pubkey":"a304edb3fd6517ac7b58b9fdba472315adc1fcf9a519a081d0d855e0d65c0e23ea01f801951afa933507f98fc2a900d4","signing_threshold":2,"uuid":"0ea52ae0-b04a-4582-adc7-149b0a83c030","verificationvector":["b71f3dc08d96fa8b6afacc3d4c9942ec8c8eab6a2b4ee6e885ec34629e672a0f8b7741226df2071ff39afb8b9a08054e","a3a586504cfd4ccca23d0e4b4d198a59f54b5eb1a65e0c7ff2d14f1e8e6667aa45ac0eceb58b805a13e39ab76a2e601e"],"version":4}`),
			id:        uuid.MustParse("0ea52ae0-b04a-4582-adc7-149b0a83c030"),
			publicKey: []byte{0xb7, 0x1f, 0x3d, 0xc0, 0x8d, 0x96, 0xfa, 0x8b, 0x6a, 0xfa, 0xcc, 0x3d, 0x4c, 0x99, 0x42, 0xec, 0x8c, 0x8e, 0xab, 0x6a, 0x2b, 0x4e, 0xe6, 0xe8, 0x85, 0xec, 0x34, 0x62, 0x9e, 0x67, 0x2a, 0x0f, 0x8b, 0x77, 0x41, 0x22, 0x6d, 0xf2, 0x07, 0x1f, 0xf3, 0x9a, 0xfb, 0x8b, 0x9a, 0x08, 0x05, 0x4e},
			version:   4,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			output, err := newAccount()
			require.NoError(t, err)
			err = json.Unmarshal(test.input, output)
			if test.err != "" {
				require.Error(t, err)
				assert.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, test.id, output.ID())
				assert.Equal(t, test.publicKey, output.CompositePublicKey().Marshal())
			}
		})
	}
}

func TestUnlock(t *testing.T) {
	tests := []struct {
		name       string
		account    []byte
		passphrase []byte
		err        error
	}{
		{
			name:       "Good",
			account:    []byte(`{"crypto":{"checksum":{"function":"sha256","message":"5b2b545965b45bca2ea3cc47d3ec948e7b2270117f480886804fb8f38659538c","params":{}},"cipher":{"function":"aes-128-ctr","message":"e102b4647c602d58ceecd16c58b5001fb9cfae987664081cc47d73d22e2e12f4","params":{"iv":"a268c48c48bd568f1b03153b45669f31"}},"kdf":{"function":"pbkdf2","message":"","params":{"c":16,"dklen":32,"prf":"hmac-sha256","salt":"344d372d72bdabecd89d30d3cb14d5355b2801b2aa75b08dfeb0711f60f91c07"}}},"encryptor":"keystore","name":"Test account","participants":{"1":"signer-l01.attestant.io:8881","2":"signer-l02.attestant.io:8882","3":"signer-l03.attestant.io:8883"},"pubkey":"a304edb3fd6517ac7b58b9fdba472315adc1fcf9a519a081d0d855e0d65c0e23ea01f801951afa933507f98fc2a900d4","signing_threshold":2,"uuid":"0ea52ae0-b04a-4582-adc7-149b0a83c030","verificationvector":["b71f3dc08d96fa8b6afacc3d4c9942ec8c8eab6a2b4ee6e885ec34629e672a0f8b7741226df2071ff39afb8b9a08054e","a3a586504cfd4ccca23d0e4b4d198a59f54b5eb1a65e0c7ff2d14f1e8e6667aa45ac0eceb58b805a13e39ab76a2e601e"],"version":4}`),
			passphrase: []byte("secret"),
		},
		{
			name:       "BadPassphrase",
			account:    []byte(`{"crypto":{"checksum":{"function":"sha256","message":"5b2b545965b45bca2ea3cc47d3ec948e7b2270117f480886804fb8f38659538c","params":{}},"cipher":{"function":"aes-128-ctr","message":"e102b4647c602d58ceecd16c58b5001fb9cfae987664081cc47d73d22e2e12f4","params":{"iv":"a268c48c48bd568f1b03153b45669f31"}},"kdf":{"function":"pbkdf2","message":"","params":{"c":16,"dklen":32,"prf":"hmac-sha256","salt":"344d372d72bdabecd89d30d3cb14d5355b2801b2aa75b08dfeb0711f60f91c07"}}},"encryptor":"keystore","name":"Test account","participants":{"1":"signer-l01.attestant.io:8881","2":"signer-l02.attestant.io:8882","3":"signer-l03.attestant.io:8883"},"pubkey":"a304edb3fd6517ac7b58b9fdba472315adc1fcf9a519a081d0d855e0d65c0e23ea01f801951afa933507f98fc2a900d4","signing_threshold":2,"uuid":"0ea52ae0-b04a-4582-adc7-149b0a83c030","verificationvector":["b71f3dc08d96fa8b6afacc3d4c9942ec8c8eab6a2b4ee6e885ec34629e672a0f8b7741226df2071ff39afb8b9a08054e","a3a586504cfd4ccca23d0e4b4d198a59f54b5eb1a65e0c7ff2d14f1e8e6667aa45ac0eceb58b805a13e39ab76a2e601e"],"version":4}`),
			passphrase: []byte("wrong passphrase"),
			err:        errors.New("incorrect passphrase"),
		},
		{
			name:       "EmptyPassphrase",
			account:    []byte(`{"crypto":{"checksum":{"function":"sha256","message":"5b2b545965b45bca2ea3cc47d3ec948e7b2270117f480886804fb8f38659538c","params":{}},"cipher":{"function":"aes-128-ctr","message":"e102b4647c602d58ceecd16c58b5001fb9cfae987664081cc47d73d22e2e12f4","params":{"iv":"a268c48c48bd568f1b03153b45669f31"}},"kdf":{"function":"pbkdf2","message":"","params":{"c":16,"dklen":32,"prf":"hmac-sha256","salt":"344d372d72bdabecd89d30d3cb14d5355b2801b2aa75b08dfeb0711f60f91c07"}}},"encryptor":"keystore","name":"Test account","participants":{"1":"signer-l01.attestant.io:8881","2":"signer-l02.attestant.io:8882","3":"signer-l03.attestant.io:8883"},"pubkey":"a304edb3fd6517ac7b58b9fdba472315adc1fcf9a519a081d0d855e0d65c0e23ea01f801951afa933507f98fc2a900d4","signing_threshold":2,"uuid":"0ea52ae0-b04a-4582-adc7-149b0a83c030","verificationvector":["b71f3dc08d96fa8b6afacc3d4c9942ec8c8eab6a2b4ee6e885ec34629e672a0f8b7741226df2071ff39afb8b9a08054e","a3a586504cfd4ccca23d0e4b4d198a59f54b5eb1a65e0c7ff2d14f1e8e6667aa45ac0eceb58b805a13e39ab76a2e601e"],"version":4}`),
			passphrase: []byte(""),
			err:        errors.New("incorrect passphrase"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			account, err := newAccount()
			require.NoError(t, err)
			require.NoError(t, json.Unmarshal(test.account, account))

			// Try to sign something - should fail because locked
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, err = account.Sign(ctx, []byte("test"))
			assert.NotNil(t, err)

			ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			err = account.Unlock(ctx, test.passphrase)
			if test.err != nil {
				require.NotNil(t, err)
				assert.Equal(t, test.err.Error(), err.Error())
			} else {
				require.Nil(t, err)

				// Try to sign something - should succeed because unlocked
				ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				signature, err := account.Sign(ctx, []byte("test"))
				require.Nil(t, err)

				privKey, err := account.PrivateKey(context.Background())
				require.Nil(t, err)
				verified := signature.Verify([]byte("test"), privKey.PublicKey())
				assert.Equal(t, true, verified)

				require.NoError(t, account.Lock(context.Background()))

				// Try to sign something - should fail because locked (again)
				ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_, err = account.Sign(ctx, []byte("test"))
				assert.NotNil(t, err)
			}
		})
	}
}
