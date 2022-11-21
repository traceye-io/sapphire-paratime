package sapphire

import (
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
)

type Kind uint64

const (
	Plain          = iota
	X25519DeoxysII = 1
)

type Cipher interface {
	Kind() uint64
	PublicKey() []byte
	// Encrypt(plaintext []byte) (ciphertext []byte, nonce []byte)
	// Decrypt(nonce []byte, ciphertext []byte) (plaintext []byte)
	EncryptEncode(plaintext []byte) []byte
	EncryptEnvelope(plaintext []byte) *DataEnvelope
	// DecryptEncoded([]byte) string
	// DecryptCallResult(string) string
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

func (p PlainCipher) encryptCallData(plaintext []byte) (ciphertext []byte, nonce []byte) {
	return plaintext, make([]byte, 0)
}

func (p PlainCipher) EncryptEnvelope(plaintext []byte) *DataEnvelope {
	// Txs without data are just balance transfers, and all data in those is public.
	if len(plaintext) == 0 {
		return nil
	}

	data, _ := p.encryptCallData(plaintext)

	return &DataEnvelope{
		Body:   data,
		Format: p.Kind(),
	}
}

func (p PlainCipher) EncryptEncode(plaintext []byte) []byte {
	envelope := p.EncryptEnvelope(plaintext)

	return hexutil.Bytes(cbor.Marshal(envelope))
}
