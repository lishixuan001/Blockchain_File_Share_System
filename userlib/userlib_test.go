package userlib

import "testing"
import "encoding/hex"

// Golang has a very powerful routine for building tests.

// Run with "go test" to run the tests

// And "go test -v" to run verbosely so you see all the logging and
// what tests pass/fail individually.

// And "go test -cover" to check your code coverage in your tests

func TestDatastore(t *testing.T) {
	DatastoreSet("foo", []byte("bar"))
	data, valid := DatastoreGet("bar")
	if valid {
		t.Error("Improper fetch")
	}
	data, valid = DatastoreGet("foo")
	if !valid || string(data) != "bar" {
		t.Error("Improper fetch")
	}
	_, valid = DatastoreGet("bar")
	if valid {
		t.Error("Returned when nothing, oops")
	}
	t.Log("Datastore fetch", data)
	t.Log("Datastore map", DatastoreGetMap())
	DatastoreClear()
	t.Log("Datastore map", DatastoreGetMap())

}

func TestRSA(t *testing.T) {
	key, err := GenerateRSAKey()
	if err != nil {
		t.Error("Got RSA error", err)
	}
	pubkey := key.PublicKey
	KeystoreSet("foo", pubkey)
	val, ok := KeystoreGet("foo")
	if !ok || val != pubkey {
		t.Error("Didn't fetch right")
	}
	_, ok = KeystoreGet("Bar")
	if ok {
		t.Error("Got a key when I shouldn't")
	}
	KeystoreClear()
	KeystoreGetMap()

	bytes, err := RSAEncrypt(&pubkey,
		[]byte("Squeamish Ossifrage"),
		[]byte("Tag"))
	if err != nil {
		t.Error("got error", err)
	}
	decrypt, err := RSADecrypt(key,
		bytes, []byte("Tag"))
	if err != nil || (string(decrypt) != "Squeamish Ossifrage") {
		t.Error("Decryption failure", err)
	}

	bytes = []byte("Squeamish Ossifrage")
	sign, err := RSASign(key, bytes)
	if err != nil {
		t.Error("RSA sign failure")
	}
	err = RSAVerify(&key.PublicKey, bytes, sign)
	if err != nil {
		t.Error("RSA verification failure")
	}
	bytes[0] = 3
	err = RSAVerify(&key.PublicKey, bytes, sign)
	if err == nil {
		t.Error("RSA verification worked when it shouldn't")
	}
	t.Log("Error return", err)

}

func TestHMAC(t *testing.T) {
	msga := []byte("foo")
	msgb := []byte("bar")
	keya := []byte("baz")
	keyb := []byte("boop")

	mac := NewHMAC(keya)
	mac.Write(msga)
	maca := mac.Sum(nil)
	mac = NewHMAC(keya)
	mac.Write(msgb)
	macb := mac.Sum(nil)
	if Equal(maca, macb) {
		t.Error("MACs are equal for different data")
	}
	mac = NewHMAC(keyb)
	mac.Write(msga)
	macc := mac.Sum(nil)
	if Equal(maca, macc) {
		t.Error("MACs are equal for different key")
	}
	mac = NewHMAC(keya)
	mac.Write(msga)
	macd := mac.Sum(nil)
	if !Equal(maca, macd) {
		t.Error("Macs are not equal when they should be")
	}
}

func TestArgon2(t *testing.T) {
	val1 := Argon2Key([]byte("Password"),
		[]byte("nosalt"),
		32)

	val2 := Argon2Key([]byte("Password"),
		[]byte("nosalt"),
		64)

	val3 := Argon2Key([]byte("password"),
		[]byte("nosalt"),
		32)

	if Equal(val1, val2) || Equal(val1, val3) || Equal(val2, val3) {
		t.Error("Argon2 problem")
	}
	t.Log(hex.EncodeToString(val1))
	t.Log(hex.EncodeToString(val2))
	t.Log(hex.EncodeToString(val3))

}

func TestStreamCipher(t *testing.T) {
	key := []byte("example key 1234")
	msg := "This is a Test"
	ciphertext := make([]byte, BlockSize+len(msg))
	iv := ciphertext[:BlockSize]
	// Load random data
	copy(iv, RandomBytes(BlockSize))

	t.Log("Random IV", hex.EncodeToString(iv))
	cipher := CFBEncrypter(key, iv)
	cipher.XORKeyStream(ciphertext[BlockSize:], []byte(msg))
	t.Log("Message  ", hex.EncodeToString(ciphertext))

	cipher = CFBDecrypter(key, iv)
	// Yes you can do this in-place
	cipher.XORKeyStream(ciphertext[BlockSize:], ciphertext[BlockSize:])
	t.Log("Decrypted messagege", string(ciphertext[BlockSize:]))
	if string(ciphertext[BlockSize:]) != msg {
		t.Error("Decryption failure")
	}
}

// Deliberate fail example
// func TestFailure(t *testing.T){
//	t.Log("This test will fail")
//	t.Error("Test of failure")
//}
