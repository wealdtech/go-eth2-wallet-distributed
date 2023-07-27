# go-eth2-wallet-distributed

[![Tag](https://img.shields.io/github/tag/wealdtech/go-eth2-wallet-distributed.svg)](https://github.com/wealdtech/go-eth2-wallet-distributed/releases/)
[![License](https://img.shields.io/github/license/wealdtech/go-eth2-wallet-distributed.svg)](LICENSE)
[![GoDoc](https://godoc.org/github.com/wealdtech/go-eth2-wallet-distributed?status.svg)](https://godoc.org/github.com/wealdtech/go-eth2-wallet-distributed)
[![codecov.io](https://img.shields.io/codecov/c/github/wealdtech/go-eth2-wallet-distributed.svg)](https://codecov.io/github/wealdtech/go-eth2-wallet-distributed)
[![Go Report Card](https://goreportcard.com/badge/github.com/wealdtech/go-eth2-wallet-distributed)](https://goreportcard.com/report/github.com/wealdtech/go-eth2-wallet-distributed)

Distributed [Ethereum 2 wallet](https://github.com/wealdtech/go-eth2-wallet).


## Table of Contents

- [Install](#install)
- [Usage](#usage)
- [Maintainers](#maintainers)
- [Contribute](#contribute)
- [License](#license)

## Install

`go-eth2-wallet-distributed` is a standard Go module which can be installed with:

```sh
go get github.com/wealdtech/go-eth2-wallet-distributed
```

## Usage

Access to the `wallet` is usually via [go-eth2-wallet](https://github.com/wealdtech/go-eth2-wallet); the first two examples below shows how this can be achieved.

This wallet generates keys non-deterministically, _i.e._ there is no relationship between keys or idea of a "seed".

Wallet and account names may be composed of any valid UTF-8 characters; the only restriction is they can not start with the underscore (`_`) character.

Due to their nature, distributed wallets are not capable of creating accounts by themselves.  Distributed accounts are created by a separate process, and a local part of the distributed wallet can be imported.  Note that although distributed wallets do not have passphrases they still need to be unlocked before accounts can be imported.  This can be carried out with `walllet.Unlock(nil)`

### Example

#### Creating a wallet
```go
package main

import (
	context

	e2wallet "github.com/wealdtech/go-eth2-wallet"
)

func main() {

    // Create a wallet
    wallet, err := e2wallet.CreateWallet("My wallet", e2wallet.WithType("distributed"))
    if err != nil {
        panic(err)
    }

    ...
}
```

#### Accessing a wallet
```go
package main

import (
	e2wallet "github.com/wealdtech/go-eth2-wallet"
)

func main() {

    // Open a wallet
    wallet, err := e2wallet.OpenWallet("My wallet")
    if err != nil {
        panic(err)
    }

    ...
}
```

#### Importing an account
```go
package main

import (
	"context"

	e2wallet "github.com/wealdtech/go-eth2-wallet"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

func main() {

	// Open a wallet
	wallet, err := e2wallet.OpenWallet("My wallet")
	if err != nil {
		panic(err)
	}

	err = wallet.(e2wtypes.WalletLocker).Unlock(context.Background(), nil)
	if err != nil {
		panic(err)
	}
	// Always immediately defer locking the wallet to ensure it does not remain unlocked outside of the function.
	defer wallet.(e2wtypes.WalletLocker).Lock(context.Background())

	// Data obtained from a distributed key generation process.
	privateKey := []byte{
		0x36, 0xe7, 0x51, 0xee, 0x36, 0x9c, 0x2d, 0xdd, 0xf3, 0x1a, 0x2b, 0x84, 0x0b, 0x05, 0x81, 0x92,
		0x77, 0xfc, 0xb3, 0xde, 0x81, 0xc3, 0xeb, 0x80, 0xde, 0x21, 0xcf, 0x2c, 0x74, 0xd6, 0xda, 0x3b,
	}
	signingThreshold := uint32(2)
	verificationVector := [][]byte{
		[]byte{
			0xb6, 0x81, 0x88, 0x71, 0x95, 0x0a, 0x0a, 0x51, 0x13, 0xbe, 0x35, 0xbb, 0x07, 0x06, 0x18, 0x4b,
			0x84, 0x16, 0x40, 0x8a, 0x9e, 0x8b, 0x64, 0x98, 0xd3, 0x07, 0xa5, 0x6f, 0xbb, 0x63, 0x4f, 0x93,
			0x4e, 0xf6, 0x1d, 0x39, 0x88, 0xcd, 0x0d, 0xa3, 0xf0, 0xa8, 0x5d, 0xf9, 0x07, 0x9d, 0x9b, 0x92,
		},
		[]byte{
			0x88, 0x8f, 0x45, 0xa1, 0x4a, 0x3f, 0x01, 0xff, 0x7c, 0xd1, 0xd4, 0xb0, 0x8b, 0xec, 0xd8, 0xfd,
			0x55, 0xfb, 0xf9, 0x2f, 0x40, 0xd1, 0x4d, 0xbd, 0xe8, 0xfd, 0x26, 0xe8, 0x65, 0xea, 0xda, 0x99,
			0xf4, 0x6b, 0x85, 0xa3, 0xbd, 0xf4, 0xd2, 0x33, 0xff, 0x3e, 0xe5, 0x67, 0x5d, 0xeb, 0x41, 0xef,
		},
	}
	participants := map[uint64]string{
		1: "server1:443",
		2: "server2:443",
		3: "server3:443",
	}

	account, err := wallet.(e2wtypes.WalletDistributedAccountImporter).ImportDistributedAccount(context.Background(),
		"My account",
		privateKey,
		signingThreshold,
		verificationVector,
		participants,
		[]byte("my account secret"))
	if err != nil {
		panic(err)
	}

	// Wallet should be locked as soon as unlocked operations have finished; it is safe to explicitly call wallet.Lock() as well
	// as defer it as per above.
	wallet.(e2wtypes.WalletLocker).Lock(context.Background())

	...
}
```

## Maintainers

Jim McDonald: [@mcdee](https://github.com/mcdee).

## Contribute

Contributions welcome. Please check out [the issues](https://github.com/wealdtech/go-eth2-wallet-distributed/issues).

## License

[Apache-2.0](LICENSE) © 2020 Weald Technology Trading Ltd
