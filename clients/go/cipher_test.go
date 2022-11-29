package sapphire

import (
	"encoding/hex"
	"testing"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/oasisprotocol/deoxysii"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/twystd/tweetnacl-go/tweetnacl"
)

var TestData []byte = []byte{1, 2, 3, 4, 5}

func TestPlainCipher(t *testing.T) {
	cipher := NewPlainCipher()

	if len(cipher.PublicKey()) != 0 {
		t.Fatalf("received public key for plain cipher: %s", cipher.PublicKey()[:])
	}

	if cipher.Kind() != 0 {
		t.Fatalf("received wrong kind for plain cipher: %d", cipher.Kind())
	}

	// Encrypt
	ciphertext, nonce := cipher.Encrypt(TestData)

	if len(nonce) != 0 {
		t.Fatalf("plain cipher nonce should be empty: %v", nonce)
	}

	if string(ciphertext) != string(TestData) {
		t.Fatalf("cipher text should be plain: %v", ciphertext)
	}

	// EncryptEnvelope
	envelope := cipher.EncryptEnvelope(TestData)

	if envelope == nil {
		t.Fatalf("envelope should be created for data")
	}

	if hex.EncodeToString(envelope.Body) == string(TestData) {
		t.Fatalf("envelope should match data: %v", envelope.Body)
	}

	if envelope.Format != Plain {
		t.Fatalf("envelope format should match data: %d", envelope.Format)
	}

	// EncryptEncode
	hexifiedString := string(hexutil.Bytes(cbor.Marshal(envelope)))
	if string(cipher.EncryptEncode(TestData)) != hexifiedString {
		t.Fatalf("encrypt encoded data should be in hex: %d", cipher.EncryptEncode(TestData)[:])
	}

	// Decrypt
	plaintext, err := cipher.Decrypt(nonce, ciphertext)
	if err != nil {
		t.Fatalf("err while decrypting")
	}

	if string(plaintext) != string(TestData) {
		t.Fatalf("decrypting data failed")
	}

	// DecryptEncoded
	response := hexutil.Bytes(cbor.Marshal(CallResult{
		OK: hexutil.Bytes(hexutil.Encode(TestData)),
	}))
	decrypted, err := cipher.DecryptEncoded(response)

	if err != nil {
		t.Fatalf("err while decrypting")
	}

	if string(decrypted) != hexutil.Bytes(TestData).String() {
		t.Fatalf("decrypting encoded data failed")
	}
}

func TestDeoxysIICipher(t *testing.T) {
	// private key is 64 bit
	privateKey, err := crypto.HexToECDSA("c07b151fbc1e7a11dff926111188f8d872f62eba0396da97c0a24adb75161750")
	if err != nil {
		t.Fatalf("could not init decode private key: %v", err)
	}
	pubKey, _ := tweetnacl.ScalarMultBase(crypto.FromECDSA(privateKey))
	pair := tweetnacl.KeyPair{
		PublicKey: pubKey,
		SecretKey: crypto.FromECDSA(privateKey),
	}

	cipher, err := NewX255919DeoxysIICipher(pair, pubKey)

	if err != nil {
		t.Fatalf("could not init deoxysii cipher: %v", err)
	}

	if string(cipher.PublicKey) != string(pair.PublicKey) {
		t.Fatalf("deoxysii cipher public key does not match")
	}

	if hex.EncodeToString(cipher.PublicKey) != "3046db3fa70ce605457dc47c48837ebd8bd0a26abfde5994d033e1ced68e2576" {
		t.Fatalf("deoxysii cipher public key does not match")
	}

	if hex.EncodeToString(cipher.PrivateKey) != "e69ac21066a8c2284e8fdc690e579af4513547b9b31dd144792c1904b45cf586" {
		t.Fatalf("deoxysii cipher private key does not match: %v", hex.EncodeToString(cipher.PrivateKey))
	}

	// Encrypt
	ciphertext, nonce := cipher.Encrypt([]byte("keep building anyway"))

	plaintext, err := cipher.Decrypt(nonce, ciphertext)

	if err != nil {
		t.Fatalf("could not decrypt cipher data: %v", err)
	}

	if string(plaintext) != "keep building anyway" {
		t.Fatalf("decrypted data does not match: %v", plaintext)
	}

	// EncryptEnvelope
	envelope := cipher.EncryptEnvelope(TestData)

	if envelope.Format != X25519DeoxysII {
		t.Fatalf("deoxysii envelope format does not match: %v", envelope.Format)
	}

	if envelope.Body.Nonce == nil {
		t.Fatalf("nonce should not be nil")
	}

	if string(envelope.Body.PK) != string(cipher.PublicKey) {
		t.Fatalf("pk enveloped incorrectly: %v %v", envelope.Body.PK, cipher.PublicKey)
	}

	// EncryptEncode
	encrypted, nonce := cipher.Encrypt(cbor.Marshal(CallResult{
		OK: TestData,
	}))

	if len(encrypted) == 0 {
		t.Fatalf("encrypt failed")
	}

	if len(nonce) != deoxysii.NonceSize {
		t.Fatalf("nonce size wrong: %v", nonce)
	}

	decrypted, err := cipher.Decrypt(nonce, encrypted)

	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}

	data, err := cipher.DecryptCallResult(decrypted)

	if err != nil {
		t.Fatalf("call result parsing failed: %v", err)
	}

	if string(data) != string(TestData) {
		t.Fatalf("decrypt failed: %v", decrypted)
	}
}
