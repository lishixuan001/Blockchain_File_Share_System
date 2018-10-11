package userlib

import (
	"fmt"
	"os"
	"strings"
	"time"

	"io"

	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"hash"

	"crypto/aes"
	"crypto/cipher"
	// Need to run go get to get this
	"golang.org/x/crypto/argon2"
)

// RSA private key's type
type PrivateKey = rsa.PrivateKey

// AES blocksize.
var BlockSize = aes.BlockSize

// Hash/MAC size
var HashSize = sha256.Size

// AES keysize
var AESKeySize = 16

// RSA keysize
var RSAKeySize = 2048

var DebugPrint = false

// Helper function: Does formatted printing to stderr if
// the DebugPrint global is set.  All our testing ignores stderr,
// so feel free to use this for any sort of testing you want
func DebugMsg(format string, args ...interface{}) {
	if DebugPrint {
		msg := fmt.Sprintf("%v ", time.Now().Format("15:04:05.00000"))
		fmt.Fprintf(os.Stderr,
			msg+strings.Trim(format, "\r\n ")+"\n", args...)
	}
}

// Helper function: Returns a byte slice of the specificed
// size filled with random data
func RandomBytes(bytes int) (data []byte) {
	data = make([]byte, bytes)
	if _, err := io.ReadFull(rand.Reader, data); err != nil {
		panic(err)
	}
	return
}

var datastore = make(map[string][]byte)
var keystore = make(map[string]rsa.PublicKey)

// Sets the value in the datastore
// Changed it to be copying
func DatastoreSet(key string, value []byte) {
	foo := make([]byte, len(value))
	copy(foo, value)
	datastore[key] = foo
}

// Returns the value if it exists
func DatastoreGet(key string) (value []byte, ok bool) {
	value, ok = datastore[key]
	if ok && value != nil {
		foo := make([]byte, len(value))
		copy(foo, value)
		return foo, ok
	}
	return
}

// Deletes a key
func DatastoreDelete(key string) {
	delete(datastore, key)
}

// Use this in testing to reset the datastore to empty
func DatastoreClear() {
	datastore = make(map[string][]byte)
}

func KeystoreClear() {
	keystore = make(map[string]rsa.PublicKey)
}

func KeystoreSet(key string, value rsa.PublicKey) {
	keystore[key] = value
}

func KeystoreGet(key string) (value rsa.PublicKey, ok bool) {
	value, ok = keystore[key]
	return
}

// Use this in testing to get the underlying map if you want
// to f with the storage...  After all, the datastore is adversarial

func DatastoreGetMap() map[string][]byte {
	return datastore
}

// Use this in testing to get the underlying map of the keystore.
// But note the keystore is NOT considered adversarial
func KeystoreGetMap() map[string]rsa.PublicKey {
	return keystore
}

// Generates an RSA private key by calling the crypto random function
// and calling rsa.Generate()
func GenerateRSAKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, RSAKeySize)
}

// Public key encryption using RSA-OAEP, using sha256 as the hash
// and the label is nil
func RSAEncrypt(pub *rsa.PublicKey, msg []byte, tag []byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(),
		rand.Reader,
		pub,
		msg, tag)
}

// Public key decryption...
func RSADecrypt(priv *rsa.PrivateKey, msg []byte, tag []byte) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(),
		rand.Reader,
		priv,
		msg, tag)
}

// Signature generation
func RSASign(priv *rsa.PrivateKey, msg []byte) ([]byte, error) {
	hashed := sha256.Sum256(msg)
	return rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hashed[:])
}

// Signature verification
func RSAVerify(pub *rsa.PublicKey, msg []byte, sig []byte) error {
	hashed := sha256.Sum256(msg)
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, hashed[:], sig)
}

// HMAC
func NewHMAC(key []byte) hash.Hash {
	return hmac.New(sha256.New, key)
}

// Equals comparison for hashes/MACs
// Does NOT leak timing.
func Equal(a []byte, b []byte) bool {
	return hmac.Equal(a, b)
}

// SHA256 MAC
func NewSHA256() hash.Hash {
	return sha256.New()
}

// Argon2:  Automatically choses a decent combination of iterations and memory
func Argon2Key(password []byte, salt []byte,
	keyLen uint32) []byte {
	return argon2.IDKey(password, salt,
		1,
		64*1024,
		4,
		keyLen)

}

// Gets a stream cipher object for AES
// Length of iv should be == BlockSize
func CFBEncrypter(key []byte, iv []byte) cipher.Stream {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	return cipher.NewCFBEncrypter(block, iv)
}

func CFBDecrypter(key []byte, iv []byte) cipher.Stream {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	return cipher.NewCFBDecrypter(block, iv)
}
