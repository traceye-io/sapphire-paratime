package sapphire

import (
	"context"
	"crypto/ecdsa"
	"io"
	"math/big"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

const DefaultGasLimit = 30_000_000      // Default gas params are assigned in the web3 gateway.
const DefaultGasPrice = 100_000_000_000 // 1 * 100_000_000_000
const DefaultBlockRange = 15

type WrappedBackend struct {
	Backend      bind.ContractBackend
	ChainID      big.Int
	Key          ecdsa.PrivateKey
	TransactOpts bind.TransactOpts
	Signer       WrappedSigner
}

type WrappedSigner struct {
	SignFn func(digest [32]byte) ([]byte, error)
}

func addressToByte(addr *common.Address) []byte {
	if addr != nil {
		return addr[:]
	}

	return nil
}

func NewWrappedBackend(backend bind.ContractBackend, transactOpts *bind.TransactOpts, chainID *big.Int, privateKey *ecdsa.PrivateKey, signerFn func(digest [32]byte) ([]byte, error)) WrappedBackend {
	return WrappedBackend{
		Backend:      backend,
		ChainID:      *chainID,
		Key:          *privateKey,
		TransactOpts: *transactOpts,
		Signer:       NewSigner(signerFn),
	}
}

func (w WrappedSigner) Sign(digest [32]byte) ([]byte, error) {
	return w.SignFn(digest)
}

func (b WrappedBackend) SendTransaction(ctx context.Context, tx *types.Transaction) error {
	header, err := b.Backend.HeaderByNumber(ctx, nil)
	if err != nil {
		return err
	}

	blockHash := header.Hash()
	leash := NewLeash(header.Nonce.Uint64(), header.Number.Uint64(), blockHash[:], DefaultBlockRange)

	cipher := NewPlainCipher()
	dataPack, _ := NewDataPack(b.Signer, tx.ChainId().Uint64(), b.TransactOpts.From[:], addressToByte(tx.To()), tx.Gas(), tx.GasPrice(), tx.Value(), tx.Data(), leash)

	legacyTx := &types.LegacyTx{
		To:       tx.To(),
		Nonce:    tx.Nonce(),
		GasPrice: tx.GasPrice(),
		Gas:      DefaultGasLimit,
		Value:    tx.Value(),
		Data:     dataPack.EncryptEncode(cipher),
	}

	baseTx := *types.NewTx(legacyTx)

	signer := types.LatestSignerForChainID(tx.ChainId())
	signature, _ := crypto.Sign(signer.Hash(&baseTx).Bytes(), &b.Key)
	signedTx, _ := baseTx.WithSignature(signer, signature)

	return b.Backend.SendTransaction(ctx, signedTx)
}

// TODO:
func (b WrappedBackend) CallContract(ctx context.Context, call ethereum.CallMsg, blockNumber *big.Int) ([]byte, error) {
	return b.Backend.CallContract(ctx, call, blockNumber)
}

func (b WrappedBackend) CodeAt(ctx context.Context, contract common.Address, blockNumber *big.Int) ([]byte, error) {
	return b.Backend.CodeAt(ctx, contract, blockNumber)
}

func (b WrappedBackend) EstimateGas(ctx context.Context, call ethereum.CallMsg) (gas uint64, err error) {
	header, err := b.Backend.HeaderByNumber(ctx, nil)
	if err != nil {
		return 0, err
	}

	blockHash := header.Hash()
	leash := NewLeash(header.Nonce.Uint64(), header.Number.Uint64(), blockHash[:], DefaultBlockRange)

	dataPack, _ := NewDataPack(b.Signer, b.ChainID.Uint64(), call.From[:], addressToByte(call.To), DefaultGasLimit, call.GasPrice, call.Value, call.Data, leash)
	call.Data = dataPack.Encode()

	return b.Backend.EstimateGas(ctx, call)
}

// TODO: check this
func (b WrappedBackend) FilterLogs(ctx context.Context, query ethereum.FilterQuery) ([]types.Log, error) {
	return b.Backend.FilterLogs(ctx, query)
}

func (b WrappedBackend) HeaderByNumber(ctx context.Context, number *big.Int) (*types.Header, error) {
	return b.Backend.HeaderByNumber(ctx, number)
}

func (b WrappedBackend) PendingCodeAt(ctx context.Context, account common.Address) ([]byte, error) {
	return b.Backend.PendingCodeAt(ctx, account)
}

func (b WrappedBackend) PendingNonceAt(ctx context.Context, account common.Address) (uint64, error) {
	return b.Backend.PendingNonceAt(ctx, account)
}

func (b WrappedBackend) SuggestGasPrice(ctx context.Context) (*big.Int, error) {
	return b.Backend.SuggestGasPrice(ctx)
}

func (b WrappedBackend) SuggestGasTipCap(ctx context.Context) (*big.Int, error) {
	return b.Backend.SuggestGasTipCap(ctx)
}

func (b WrappedBackend) SubscribeFilterLogs(ctx context.Context, query ethereum.FilterQuery, ch chan<- types.Log) (ethereum.Subscription, error) {
	return b.Backend.SubscribeFilterLogs(ctx, query, ch)
}

func NewSigner(signerFn func(digest [32]byte) ([]byte, error)) WrappedSigner {
	return WrappedSigner{
		SignFn: signerFn,
	}
}

// NewKeyedTransactorWithChainID is a utility method to easily create a transaction signer
// from a single private key.
func NewKeyedTransactorWithChainID(key *ecdsa.PrivateKey, chainID *big.Int) (*bind.TransactOpts, error) {
	if chainID == nil {
		return nil, bind.ErrNoChainID
	}
	signer := types.LatestSignerForChainID(chainID)
	from := crypto.PubkeyToAddress(key.PublicKey)
	return &bind.TransactOpts{
		GasPrice: big.NewInt(DefaultGasPrice),
		GasLimit: DefaultGasLimit,
		From:     from,
		Signer: func(address common.Address, tx *types.Transaction) (*types.Transaction, error) {
			if address != from {
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

// NewKeyStoreTransactorWithChainID is a utility method to easily create a transaction signer from
// an decrypted key from a keystore.
func NewKeyStoreTransactorWithChainID(keystore *keystore.KeyStore, account accounts.Account, chainID *big.Int) (*bind.TransactOpts, error) {
	if chainID == nil {
		return nil, bind.ErrNoChainID
	}
	signer := types.LatestSignerForChainID(chainID)
	return &bind.TransactOpts{
		GasPrice: big.NewInt(DefaultGasPrice),
		GasLimit: DefaultGasLimit,
		From:     account.Address,
		Signer: func(address common.Address, tx *types.Transaction) (*types.Transaction, error) {
			if address != account.Address {
				return nil, bind.ErrNotAuthorized
			}
			signature, err := keystore.SignHash(account, signer.Hash(tx).Bytes())
			if err != nil {
				return nil, err
			}
			return tx.WithSignature(signer, signature)
		},
		Context: context.Background(),
	}, nil
}

// NewTransactorWithChainID is a utility method to easily create a transaction signer from
// an encrypted json key stream and the associated passphrase.
func NewTransactorWithChainID(keyin io.Reader, passphrase string, chainID *big.Int) (*bind.TransactOpts, error) {
	json, err := io.ReadAll(keyin)
	if err != nil {
		return nil, err
	}
	key, err := keystore.DecryptKey(json, passphrase)
	if err != nil {
		return nil, err
	}
	return NewKeyedTransactorWithChainID(key.PrivateKey, chainID)
}
