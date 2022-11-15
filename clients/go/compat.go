package sapphire

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

var SapphireChainID = big.NewInt(23295)

const DefaultGasLimit = 30_000_000
const DefaultGasPrice = 1
const DefaultBlockRange = 15

// TODO: maybe i need to modify this
// NewKeyedTransactorWithChainID is a utility method to easily create a transaction signer
// from a single private key.
func NewKeyedTransactorWithChainID(key *ecdsa.PrivateKey, chainID *big.Int) (*bind.TransactOpts, error) {
	keyAddr := crypto.PubkeyToAddress(key.PublicKey)
	if chainID == nil {
		return nil, bind.ErrNoChainID
	}
	signer := types.LatestSignerForChainID(chainID)
	return &bind.TransactOpts{
		From: keyAddr,
		Signer: func(address common.Address, tx *types.Transaction) (*types.Transaction, error) {
			if address != keyAddr {
				return nil, bind.ErrNotAuthorized
			}
			signature, err := crypto.Sign(signer.Hash(tx).Bytes(), key)
			if err != nil {
				return nil, err
			}
			return tx.WithSignature(signer, signature)
		},
		Context: context.Background(),
	}, nil
}

type WrappedBackend struct {
	Backend bind.ContractBackend
	Signer  Signer
}

func WrapBackend(backend bind.ContractBackend) WrappedBackend {
	return WrappedBackend{
		Backend: backend,
	}
}

func (b WrappedBackend) SendTransaction(ctx context.Context, tx *types.Transaction) error {
	fmt.Println(tx)
	return b.Backend.SendTransaction(ctx, tx)
}

func (b WrappedBackend) CallContract(ctx context.Context, call ethereum.CallMsg, blockNumber *big.Int) ([]byte, error) {
	return b.Backend.CallContract(ctx, call, blockNumber)
}

func (b WrappedBackend) CodeAt(ctx context.Context, contract common.Address, blockNumber *big.Int) ([]byte, error) {
	return b.Backend.CodeAt(ctx, contract, blockNumber)
}

func (b WrappedBackend) EstimateGas(ctx context.Context, call ethereum.CallMsg) (gas uint64, err error) {
	fmt.Println("sapp estimate gas")
	fmt.Println("contract data:")
	fmt.Println(call.Data)
	fmt.Println(hex.EncodeToString(call.Data))
	header, err := b.Backend.HeaderByNumber(ctx, nil)
	if err != nil {
		return 0, err
	}

	blockHash := header.Hash()
	leash := Leash{
		Nonce:       header.Nonce.Uint64(),
		BlockNumber: header.Number.Uint64(),
		BlockHash:   blockHash[:],
		BlockRange:  DefaultBlockRange,
	}
	dp, err := NewDataPack(nil, SapphireChainID.Uint64(), call.From[:], call.To[:], DefaultGasLimit, call.GasPrice, call.Value, call.Data, leash)

	if err != nil {
		return 0, err
	}
	return b.Backend.EstimateGas(ctx, call)
}

func (b WrappedBackend) FilterLogs(ctx context.Context, query ethereum.FilterQuery) ([]types.Log, error) {
	return b.Backend.FilterLogs(ctx, query)
}

func (b WrappedBackend) HeaderByNumber(ctx context.Context, number *big.Int) (*types.Header, error) {
	fmt.Println("sapp header by number")
	return b.Backend.HeaderByNumber(ctx, number)
}

func (b WrappedBackend) PendingCodeAt(ctx context.Context, account common.Address) ([]byte, error) {
	return b.Backend.PendingCodeAt(ctx, account)
}

func (b WrappedBackend) PendingNonceAt(ctx context.Context, account common.Address) (uint64, error) {
	return b.Backend.PendingNonceAt(ctx, account)
}

func (b WrappedBackend) SuggestGasPrice(ctx context.Context) (*big.Int, error) {
	fmt.Println("sapp suggest gas price")

	return b.Backend.SuggestGasPrice(ctx)
}

func (b WrappedBackend) SuggestGasTipCap(ctx context.Context) (*big.Int, error) {
	return b.Backend.SuggestGasTipCap(ctx)
}

func (b WrappedBackend) SubscribeFilterLogs(ctx context.Context, query ethereum.FilterQuery, ch chan<- types.Log) (ethereum.Subscription, error) {
	return b.Backend.SubscribeFilterLogs(ctx, query, ch)
}
