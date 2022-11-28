package sapphire

import (
	"crypto/cipher"
	"errors"
	"fmt"
	"math/rand"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/oasisprotocol/deoxysii"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/twystd/tweetnacl-go/tweetnacl"
)

type Kind uint64

const (
	Plain          = iota
	X25519DeoxysII = 1
)

var (
	ErrCallFailed       = errors.New("call failed in module")
	ErrCallResultDecode = errors.New("could not decode call result")
)

type CallResult struct {
	Fail    *Failure `cbor:"failure,omitempty"`
	OK      []byte   `cbor:"ok,omitempty"`
	Unknown *Unknown `cbor:"unknown,omitempty"`
}

type Failure struct {
	Module  []byte `cbor:"module"`
	Code    uint64 `cbor:"code"`
	Message []byte `cbor:"message,omitempty"`
}

type Unknown struct {
	Nonce []byte `cbor:"nonce"`
	Data  []byte `cbor:"data"`
}

type Cipher interface {
	Kind() uint64
	PublicKey() []byte
	Encrypt(plaintext []byte) (ciphertext []byte, nonce []byte)
	Decrypt(nonce []byte, ciphertext []byte) (plaintext []byte)
	EncryptEncode(plaintext []byte) []byte
	EncryptEnvelope(plaintext []byte) *DataEnvelope
	DecryptEncoded(result []byte) ([]byte, error)
	DecryptCallResult(result []byte) ([]byte, error)
}

type PlainCipher struct {
}

func NewPlainCipher() PlainCipher {
	return PlainCipher{}
}

func (p PlainCipher) Kind() uint64 {
	return Plain
}

func (p PlainCipher) PublicKey() []byte {
	return make([]byte, 0)
}

func (p PlainCipher) Encrypt(plaintext []byte) (ciphertext []byte, nonce []byte) {
	nonce = make([]byte, 0)
	return plaintext, nonce
}

func (p PlainCipher) Decrypt(nonce []byte, ciphertext []byte) (plaintext []byte) {
	return ciphertext
}

func (p PlainCipher) DecryptCallResult(response []byte) ([]byte, error) {
	var callResult CallResult
	cbor.MustUnmarshal(response, &callResult)

	// TODO: actually decode and return failure
	if callResult.Fail != nil {
		return nil, ErrCallFailed
	}

	if callResult.Unknown != nil {
		return callResult.Unknown.Data, nil
	}

	if callResult.OK != nil {
		return callResult.OK, nil
	}

	return nil, ErrCallResultDecode
}

func (p PlainCipher) DecryptEncoded(response []byte) ([]byte, error) {
	return p.DecryptCallResult(response)
}

func (p PlainCipher) encryptCallData(plaintext []byte) (ciphertext []byte, nonce []byte) {
	return plaintext, make([]byte, 0)
}

func (p PlainCipher) EncryptEnvelope(plaintext []byte) *DataEnvelope {
	// Txs without data are just balance transfers, and all data in those is public.
	if len(plaintext) == 0 {
		return nil
	}

	data, nonce := p.encryptCallData(plaintext)

	if len(nonce) == 0 {
		return &DataEnvelope{
			Body:   data,
			Format: p.Kind(),
		}
	}

	return &DataEnvelope{
		Body: cbor.Marshal(Body{
			PK:    p.PublicKey(),
			Nonce: nonce,
			Data:  data,
		}),
		Format: p.Kind(),
	}
}

func (p PlainCipher) EncryptEncode(plaintext []byte) []byte {
	envelope := p.EncryptEnvelope(plaintext)

	return hexutil.Bytes(cbor.Marshal(envelope))
}

// This is the default cipher.
type X25519DeoxysIICipher struct {
	Cipher     cipher.AEAD
	PublicKey  []byte
	PrivateKey []byte
}

func NewX255919DeoxysIICipher(keypair tweetnacl.KeyPair, peerPublicKey []byte) (*X25519DeoxysIICipher, error) {
	// TODO: (followed by hashing to remove ECDH bias).?
	key, err := tweetnacl.ScalarMult(keypair.SecretKey, peerPublicKey)

	if err != nil {
		return nil, err
	}

	cipher, err := deoxysii.New(key)

	if err != nil {
		return nil, err
	}

	return &X25519DeoxysIICipher{
		PublicKey:  keypair.PublicKey,
		PrivateKey: key,
		Cipher:     cipher,
	}, nil
}

func (p X25519DeoxysIICipher) Kind() uint64 {
	return X25519DeoxysII
}

func (p X25519DeoxysIICipher) Encrypt(plaintext []byte) (ciphertext []byte, nonce []byte) {
	nonce = make([]byte, deoxysii.NonceSize)
	copy(nonce, []byte(fmt.Sprint(rand.Int())))
	meta := make([]byte, 0)
	res := p.Cipher.Seal(ciphertext, nonce, plaintext, meta)
	return res, nonce
}

func (p X25519DeoxysIICipher) Decrypt(nonce []byte, ciphertext []byte) ([]byte, error) {
	meta := make([]byte, 0)
	return p.Cipher.Open(ciphertext[:0], nonce, ciphertext, meta)
}

func (p X25519DeoxysIICipher) encryptCallData(plaintext []byte) (ciphertext []byte, nonce []byte) {
	return p.Encrypt(cbor.Marshal(Data{
		Body: plaintext,
	}))
}

func (p X25519DeoxysIICipher) EncryptEnvelope(plaintext []byte) *DataEnvelope {
	// Txs without data are just balance transfers, and all data in those is public.
	if len(plaintext) == 0 {
		return nil
	}

	data, nonce := p.encryptCallData(plaintext)

	return &DataEnvelope{
		Body: cbor.Marshal(Body{
			Nonce: nonce,
			Data:  data,
			PK:    p.PublicKey,
		}),
		Format: p.Kind(),
	}
}

func (p X25519DeoxysIICipher) EncryptEncode(plaintext []byte) []byte {
	envelope := p.EncryptEnvelope(plaintext)

	return hexutil.Bytes(cbor.Marshal(envelope))
}

func (p X25519DeoxysIICipher) DecryptCallResult(response []byte) ([]byte, error) {
	var callResult CallResult
	cbor.MustUnmarshal(response, &callResult)

	// TODO: actually decode and return failure
	if callResult.Fail != nil {
		return nil, ErrCallFailed
	}

	if callResult.Unknown != nil {
		return callResult.Unknown.Data, nil
	}

	if callResult.OK != nil {
		return callResult.OK, nil
	}

	return nil, ErrCallResultDecode
}

func (p X25519DeoxysIICipher) DecryptEncoded(response []byte) ([]byte, error) {
	return p.DecryptCallResult(response)
}
