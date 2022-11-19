package sapphire

import "github.com/oasisprotocol/oasis-core/go/common/cbor"

type Kind uint8

const (
	Plain          = iota
	X25519DeoxysII = 1
)

type Cipher interface {
	Kind() string
	PublicKey() []byte
	Encrypt(plaintext []byte) (ciphertext []byte, nonce []byte)
	Decrypt(nonce []byte, ciphertext []byte) (plaintext []byte)
	EncryptEncode(string) []byte
	EncryptEnvelope(data []byte) []byte
	// DecryptEncoded(string) string
	// DecryptCallResult(string) string
}

type PlainCipher struct {
}

func NewPlainCipher() PlainCipher {
	return PlainCipher{}
}

func (p *PlainCipher) Kind() string {
	return "plain"
}

func (p *PlainCipher) PublicKey() []byte {
	return make([]byte, 0)
}

func (p *PlainCipher) Encrypt(plaintext []byte) (ciphertext []byte, nonce []byte) {
	return plaintext, make([]byte, 0)
}

func (p *PlainCipher) Decrypt(nonce []byte, ciphertext []byte) (plaintext []byte) {
	return ciphertext
}

func (p *PlainCipher) encryptCallData(plaintext []byte) (ciphertext []byte, nonce []byte) {
	return plaintext, make([]byte, 0)
}

func (p *PlainCipher) EncryptEnvelope(plaintext []byte) []byte {
	if len(plaintext) == 0 {
		return make([]byte, 0)
	}

	data, _ := p.encryptCallData(plaintext)

	return data
}

func (p *PlainCipher) EncryptEncode(plaintext []byte) []byte {
	encryptedText := p.EncryptEnvelope(plaintext)

	if len(encryptedText) == 0 {
		return make([]byte, 0)
	}

	return cbor.Marshal(encryptedText)
}
