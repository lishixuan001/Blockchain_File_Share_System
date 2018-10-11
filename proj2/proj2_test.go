package proj2

import "github.com/nweaver/cs161-p2/userlib"
import "testing"
import "reflect"

// You can actually import other stuff if you want IN YOUR TEST
// HARNESS ONLY.  Note that this is NOT considered part of your
// solution, but is how you make sure your solution is correct.

// Check init user
func TestInit(t *testing.T) {
	t.Log("Initialization test")
	userlib.DebugPrint = true
	someUsefulThings()

	userlib.DebugPrint = false
	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
	}
	// t.Log() only produces output if you run with "go test -v"
	t.Log("Got user", u)
	// You probably want many more tests here.
}

// Check get user
func TestGetUser(t *testing.T) {
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}
	t.Log("Loaded user", u)
}

// Check store and load
func TestStorage(t *testing.T) {
	// And some more tests, because

	// Get user Alice
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}
	t.Log("Loaded user", u)

	// Alice stores some text in file1
	v := []byte("This is a test")
	u.StoreFile("file1", v)
	t.Log("Alice stores 'This is a test; ' to 'file1' ")

	// Alice loads from file1
	v2, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
	}
	t.Log("Alice loads 'file1'")

	// Compare Alice's stored and loaded content
	if !reflect.DeepEqual(v, v2) {
		t.Error("Downloaded file is not the same", v, v2)
	}
	t.Log("Alice's load got same content as stored -- Correct!")
}

// Includes iterative appending and checking
func TestAppend(t *testing.T) {
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}
	t.Log("Loaded user", u)

	text := []byte("This is Msg; ")
	u.StoreFile("fileAppend", text)
	t.Log("Alice stores 'This is Msg; ' to 'fileAppend' ")

	// Create the message to be appended
	appendText := []byte("This is append; ")

	// Call AppendFile by byte for appendText
	for _, letter := range appendText {
		errAppend := u.AppendFile("fileAppend", []byte(string(letter)))
		if errAppend != nil {
			t.Error("Failed to append message", errAppend)
		}
	}
	t.Log("Alice appended 'This is append; ' to 'fileAppend'")

	// Load for check
	loadText, errLoad := u.LoadFile("fileAppend")
	if errLoad != nil {
		t.Error("Failed to upload and download 1", errLoad)
	}
	t.Log("Alice loads 'file1'")

	// Check correctness
	newText := append(text, appendText...)
	if !reflect.DeepEqual(loadText, newText) {
		t.Error("Downloaded file is not the same: \n", newText, "\n", loadText)
	}
	t.Log("Alice got correct result for appending -- Correct!")

}

// Includes two-level sharing test
func TestShare(t *testing.T) {
	// Users
	// Alice : Creator
	// Bob : Shared by Alice
	// Carl : Shared by Bob
	u1, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
	}
	t.Log("Loaded user", u1)
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
	}
	t.Log("Inited user", u2)
	u3, err3 := InitUser("carl", "fallbar")
	if err3 != nil {
		t.Error("Failed to initialize bob", err3)
	}
	t.Log("Inited user", u3)

	var v, v2, v3 []byte
	var msgid string

	// Alice load file
	v, err = u1.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
	}
	t.Log("Alice loaded 'file1'")

	// Alice share the file to Bob
	msgid, err = u1.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
	}
	t.Log("Alice shares 'file1' as file to Bob")

	// Bob receive the file
	err = u2.ReceiveFile("file2", "alice", msgid)
	if err != nil {
		t.Error("Failed to receive the share message", err)
	}
	t.Log("Bob receives file as 'file2' from Alice" )

	// Bob loads file
	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
	}
	t.Log("Bob loads 'file2'")

	// Compare file of Alice's and Bob's
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
	}
	t.Log("Alice's 'file1' and Bob's 'file2' are equal -- Correct!")

	// Bob share to Carl
	msgid, err = u2.ShareFile("file2", "carl")
	if err != nil {
		t.Error("Failed to share the a file", err)
	}
	t.Log("Bob shares 'file2' as file to Carl")

	// Carl receives the file
	err = u3.ReceiveFile("file3", "bob", msgid)
	if err != nil {
		t.Error("Failed to receive the share message", err)
	}
	t.Log("Carl receives file as 'file3' from Bob" )

	// Carl loads file
	v3, err = u3.LoadFile("file3")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
	}
	t.Log("Carl loads 'file3'")

	// Compare file of Bob's and Carl's
	if !reflect.DeepEqual(v2, v3) {
		t.Error("Shared file is not the same", v2, v3)
	}
	t.Log("Bob's 'file2' and Carl's 'file3' are equal -- Correct!")
}

// Check revoke and re-share
func TestRevoke(t *testing.T) {
	// Users
	// Alice : Creator
	// Bob : Shared by Alice
	// Carl : Shared by Bob
	u1, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
	}
	t.Log("Loaded user", u1)
	u2, err := GetUser("bob", "foobar")
	if err != nil {
		t.Error("Failed to reload user", err)
	}
	t.Log("Loaded user", u2)
	u3, err := GetUser("carl", "fallbar")
	if err != nil {
		t.Error("Failed to reload user", err)
	}
	t.Log("Loaded user", u3)

	// Init variables
	var v1, v2, v3 []byte
	var originText []byte
	var msgid string

	// Alice load file
	v1, err = u1.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
	}
	originText = v1
	t.Log("Alice loaded 'file1'")

	// Bob load file
	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
	}
	t.Log("Bob loads 'file2'")

	// Compare file of Alice's and Bob's
	if !reflect.DeepEqual(v1, v2) {
		t.Error("Shared file is not the same", v1, v2)
	}
	t.Log("Alice's 'file1' and Bob's 'file2' are equal -- Correct!")

	// Carl load file
	v3, err = u3.LoadFile("file3")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
	}
	t.Log("Carl loads 'file3'")

	// Compare file of Bob's and Carl's
	if !reflect.DeepEqual(v2, v3) {
		t.Error("Shared file is not the same", v2, v3)
	}
	t.Log("Bob's 'file2' and Carl's 'file3' are equal -- Correct!")

	// Bob try revoke (should not work since not creator)
	err = u2.RevokeFile("file2")
	if err == nil {
		t.Error("Non-Creator should not be able to Revoke File", err)
	}
	t.Log("Bob tries to revoke his 'file2' but failed -- Correct!")

	// Carl try revoke (should not work since not creator)
	err = u3.RevokeFile("file3")
	if err == nil {
		t.Error("Non-Creator should not be able to Revoke File", err)
	}
	t.Log("Carl tries to revoke her 'file3' but failed -- Correct!")

	// Alice try revoke (should work since creator)
	err = u1.RevokeFile("file1")
	if err != nil {
		t.Error("Creator should be able to Revoke File", err)
	}
	t.Log("Alice successfully revoked her 'file1' -- Correct!")

	// Test Alice load file
	v1, err = u1.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
	}
	t.Log("Alice loaded 'file1'")

	// Compare the file with the one before revoke
	if !reflect.DeepEqual(originText, v1) {
		t.Error("File is not the same for creator after revoke", originText, v1)
	}
	t.Log("Alice got same content as that before revoke -- Correct!")

	// Test Bob load file (should return nil)
	v2, err = u2.LoadFile("file2")
	if v2 != nil  {
		t.Error("Non-Creator should not be able to access the file after Revoke", err)
	}
	t.Log("Bob loads 'file2'")

	// Test Carl load file (should return nil)
	v3, err = u3.LoadFile("file3")
	if v3 != nil  {
		t.Error("Non-Creator should not be able to access the file after Revoke", err)
	}
	t.Log("Carl loads 'file3'")

	// Alice do some append again
	// Create the message to be appended
	appendText := []byte("This is append; ")

	// Call AppendFile by byte for appendText
	for _, letter := range appendText {
		err = u1.AppendFile("file1", []byte(string(letter)))
		if err != nil {
			t.Error("Failed to append message", err)
		}
	}
	t.Log("Alice appended 'This is append; ' to 'file1'")

	// Load for check
	v1, err = u1.LoadFile("file1")
	if err != nil {
		t.Error("Failed to upload and download 1", err)
	}
	t.Log("Alice loads 'file1'")

	// Check correctness
	newText := append(originText, appendText...)
	if !reflect.DeepEqual(v1, newText) {
		t.Error("Downloaded file is not the same: \n", newText, "\n", v1)
	}
	t.Log("Alice got correct result for appending -- Correct!")


	// Alice share file to Bob
	msgid, err = u1.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
	}
	t.Log("Alice shares 'file1' as file to Bob")

	// Bob receive the share from Alice
	err = u2.ReceiveFile("file2", "alice", msgid)
	if err != nil {
		t.Error("Failed to receive the share message", err)
	}
	t.Log("Bob receives file as 'file2' from Alice" )

	// Bob loads file
	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
	}
	t.Log("Bob loads 'file2'")

	// Compare file of Alice's and Bob's
	if !reflect.DeepEqual(v1, v2) {
		t.Error("Shared file is not the same", v1, v2)
	}
	t.Log("Alice's 'file1' and Bob's 'file2' are equal -- Correct!")

	// Bob share to Carl
	msgid, err = u2.ShareFile("file2", "carl")
	if err != nil {
		t.Error("Failed to share the a file", err)
	}
	t.Log("Bob shares 'file2' as file to Carl")

	// Carl receives the file
	err = u3.ReceiveFile("file3", "bob", msgid)
	if err != nil {
		t.Error("Failed to receive the share message", err)
	}
	t.Log("Carl receives file as 'file3' from Bob" )

	// Carl loads file
	v3, err = u3.LoadFile("file3")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
	}
	t.Log("Carl loads 'file3'")

	// Compare file of Bob's and Carl's
	if !reflect.DeepEqual(v2, v3) {
		t.Error("Shared file is not the same", v2, v3)
	}
	t.Log("Bob's 'file2' and Carl's 'file3' are equal -- Correct!")

}





























