package proj2

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (
	// You neet to add with
	// go get github.com/nweaver/cs161-p2/userlib
	"github.com/nweaver/cs161-p2/userlib"

	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...
	"encoding/json"

	// Likewise useful for debugging etc
	"encoding/hex"

	// UUIDs are generated right based on the crypto RNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys
	"strings"

	// Want to import errors
	"errors"
)

// This serves two purposes: It shows you some useful primitives and
// it suppresses warnings for items not being imported
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var key *userlib.PrivateKey
	key, _ = userlib.GenerateRSAKey()
	userlib.DebugMsg("Key is %v", key)
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

// The structure definition for a user record
// You can add other fields here if you want...
// Note for JSON to marshal/unmarshal, the fields need to
// be public (start with a capital letter)
type User struct {
	// User Info
	Username string
	Password string
	PrivateKey *userlib.PrivateKey
}

// The UserData struct is used to store the encrypted and hmac data in
// one single struct and upload it through DatastoreSet
type UserData struct {
	// Encrypted Info
	EncryptedValue []byte
	// HMAC info
	HMACValue []byte
}

// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored
// User data: the name used in the datastore should not be guessable
// without also knowing the password and username.

// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the user has a STRONG password
func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdata.Username = username
	userdata.Password = password

	// Generate Functional (Location - Keys) pair in DataStorage
	keyString := userlib.Argon2Key([]byte(password), []byte(username), 64)
	// Locations
	storageLocation := string(keyString[0:16])
	// Keys
	encryptKey := keyString[16:32]
	hmacKey := keyString[32:48]
	nonce := keyString[48:64]

	// Generate Private Key
	userdata.PrivateKey, err = userlib.GenerateRSAKey()
	if err != nil {
		return nil, err
	}

	// Store PublicKey on Keystore which is believed to be secure
	publicKey := userdata.PrivateKey.PublicKey
	userlib.KeystoreSet(userdata.Username, publicKey)

	// Marshal the user -- []byte
	marshaluser, err := json.Marshal(userdata)
	if err != nil {
		return nil, err
	}

	// Encrypt the user's data
	var encryptedValue = make([]byte, len(marshaluser))
	encryptor := userlib.CFBEncrypter(encryptKey, nonce)
	encryptor.XORKeyStream(encryptedValue, marshaluser)

	// HMAC the encrypted data
	hmac := userlib.NewHMAC(hmacKey)
	hmac.Write(encryptedValue)
	hmacValue := hmac.Sum([]byte(""))

	// Store Encrypted and HMAC values into Data struct
	var uploadedData UserData
	uploadedData.EncryptedValue = encryptedValue
	uploadedData.HMACValue = hmacValue

	// Marshal the uploadedData
	marshalUploadedData, err := json.Marshal(uploadedData)
	if err != nil {
		return nil, err
	}

	userlib.DatastoreSet(storageLocation, marshalUploadedData)

	// Here err only represents private key creation error
	return &userdata, err
}

// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error) {
	// Calculate the storage location
	keyString := userlib.Argon2Key([]byte(password), []byte(username), 64)
	storageLocation := string(keyString[0:16])
	encryptKey := keyString[16:32]
	hmacKey := keyString[32:48]
	nonce := keyString[48:64]

	// Get user's data through DatastoreGet
	marshalDownloadedData, ok := userlib.DatastoreGet(storageLocation)
	if !ok {
		return nil, err
	}

	// UnMarshal the data for EncryptedValue and HMACValue
	var downloadedData UserData
	err = json.Unmarshal(marshalDownloadedData, &downloadedData)
	if err != nil {
		return nil, err
	}
	encryptedValue := downloadedData.EncryptedValue
	hmacValue := downloadedData.HMACValue

	// Re-Calculate HMAC tag from EncryptedValue and compare with HMACValue
	hmac := userlib.NewHMAC(hmacKey)
	hmac.Write(encryptedValue)
	hmacValueCheck := hmac.Sum([]byte(""))
	if !userlib.Equal(hmacValue, hmacValueCheck) {
		return nil, err
	}

	// Decrypt User Info from EncryptedValue
	decryptedValue := make([]byte, len(encryptedValue))
	decryptor := userlib.CFBDecrypter(encryptKey, nonce)
	decryptor.XORKeyStream(decryptedValue, encryptedValue)

	// UnMarshal the User Info
	var userdata User
	err = json.Unmarshal(decryptedValue, &userdata)
	if err != nil {
		return nil, err
	}

	return &userdata, err
}

// The FileData struct is designed for storing information of a file.
// It stores the content of the file and a hmac for owners to check whenever they read files for Integrity
type FileData struct {
	// File Content
	FileContent []byte
	// HMAC info
	FileHMAC []byte
}

// The FileMeta struct is used by users storing the metadata including the location and keys for the file.
// It stores the address of the file, keyFile(pub), keyNonce(pub), and keyHMAC(pub)
type FileMeta struct {
	// FileDirect Address
	FileDirectAddr []byte
	// File's Encryption Key
	FileKey []byte
	// File's Encryption Nonce
	FileNonce []byte
	// File's HMAC Key
	FileHMAC []byte
	// Denote if the metadata is owned by the creator
	IsCreator bool
}

// The FileLink struct contains by sequence the addresses of the file with the root file and its appended contents
type FileLink struct {
	// Address of the current file
	CurrAddr []byte
	// Child node of the next FileLink
	NextFileLink *FileLink
}

// This stores a file in the datastore.
// For example, Alice created the file and try to store it
// - The idea is that we should create the fixed address for the file and store the file content in that address,
// - Then we should create a middle where points to the location and keys for Alice to the Datastore. The values should be stored are
// 1. The pointer to the address where the file is stored; 2. The key to open the file which is encrypted with Alice's public key
// 3. The HMAC key to check the integrity of the file which is encrypted by Alice's public key
// - Then, we create an separate address for Alice as the key and the value to be the middle layer address.
// - Note that as the creator of the file, Alice should have locations of all middle layers including others' she shared the file to.
// The name of the file should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {
	// Note that here we name the user Alice

	// =========================================== //
	// The FIRST task is to store the file content //
	// =========================================== //

	// Generate keys to encrypt (& nonce), hash, and hmac the file
	keyString := userlib.RandomBytes(64)
	fileAddr := keyString[0:16]
	keyFile := keyString[16:32] // Encryption Key
	keyNonce := keyString[32:48] // Encryption Nonce
	keyHMAC := keyString[48:64] // HMAC Key
	// Encrypt the file content
	var encryptedFile = make([]byte, len(data))
	encryptor := userlib.CFBEncrypter(keyFile, keyNonce)
	encryptor.XORKeyStream(encryptedFile, data)
	// Calculate the HMAC tag for the file
	hmac := userlib.NewHMAC(keyHMAC)
	hmac.Write(encryptedFile)
	hmacFile := hmac.Sum([]byte(""))
	// Store information about the file in a FileData struct
	var fileData FileData
	fileData.FileContent = encryptedFile
	fileData.FileHMAC = hmacFile
	// Marshal the fileData info
	marshalFileData, _ := json.Marshal(fileData)
	// Store the file's data to the Datastore
	userlib.DatastoreSet(string(fileAddr), marshalFileData)

	// ================================================ //
	// The SECOND task is to create FileLink (Next=nil) //
	// ================================================ //

	// We Create an address to store the FileLink information
	fileLinkAddr := userlib.RandomBytes(16)
	// We create an FileLink to store the address info
	var fileLink FileLink
	fileLink.CurrAddr = fileAddr
	fileLink.NextFileLink = nil
	// Marshal and encrypt the fileLink using keyFile (encryption)
	marshalFileLink, _ := json.Marshal(fileLink)
	var encryptMarFileLink = make([]byte, len(marshalFileLink))
	encryptorMFL := userlib.CFBEncrypter(keyFile, keyNonce)
	encryptorMFL.XORKeyStream(encryptMarFileLink, marshalFileLink)
	// Store the fileLink info to the Datastore
	userlib.DatastoreSet(string(fileLinkAddr), encryptMarFileLink)

	// ======================================================= //
	// The THIRD task is to create a middle node -- FileDirect //
	// to store the fileLinkAddr -- create indirect access     //
	// ======================================================= //

	// Create the address for fileDirect
	fileDirectAddr := userlib.RandomBytes(16)
	// Encrypt the fileLinkAddr using keyFile (encryption)
	var encryptFileLinkAddr = make([]byte, len(fileLinkAddr))
	encryptorFLA := userlib.CFBEncrypter(keyFile, keyNonce)
	encryptorFLA.XORKeyStream(encryptFileLinkAddr, fileLinkAddr)
	// Store the (fileDirectAddr, encryptFileLinkAddr) to the Datastore
	userlib.DatastoreSet(string(fileDirectAddr), encryptFileLinkAddr)

	// ========================================================= //
	// The FOURTH task is to store the fileDirect infomation and //
	// the keys for opening the files as metadata for the user   //
	// ========================================================= //

	// Create a middle layer with address encoded by Alice's filename and Alice's username
	// 1. Create the middle layer address
	userMetaAddr := userlib.Argon2Key([]byte(filename), []byte(userdata.Username), 16)
	// 2. Generate the file info Alice need to find and open the file
	// The materials needed are (fileAddr, keyFile, keyNonce, keyHMAC) <- (pubA)
	// (1) Store the metadata of file info for Alice in FileMeta struct
	var fileMeta FileMeta
	fileMeta.FileDirectAddr = fileDirectAddr
	fileMeta.FileKey = keyFile
	fileMeta.FileNonce = keyNonce
	fileMeta.FileHMAC = keyHMAC
	fileMeta.IsCreator = true
	// (2) Marshal the fileMeta
	marshalFileMeta, _ := json.Marshal(fileMeta)
	// (3) Encrypt the marshalFileMeta with Alice's public key
	userPublicKey := userdata.PrivateKey.PublicKey
	pubEryMarFileMeta, _ := userlib.RSAEncrypt(&userPublicKey, marshalFileMeta, nil)
	// Store the middle layer which let Alice access information about the file
	// Store (userMetaAddr, pubEryMarFileMeta)
	userlib.DatastoreSet(string(userMetaAddr), pubEryMarFileMeta)

	// =========================================================== //
	// The FIFTH part is to create the entry for Alice to access   //
	// the metadata. The one more layer to the metadata is because //
	// that its for Alice to control the middle for access of all  //
	// others the file is shared to                                //
	// =========================================================== //

	// Create the address Alice can access the address where the metadata is stored
	userAccessAddr := userlib.Argon2Key([]byte(userdata.Password), []byte(filename), 16)
	// Encrypt the userMetaAddr with Alice's public key
	pubEryMetaAddr, _ := userlib.RSAEncrypt(&userPublicKey, userMetaAddr, nil)
	// Store the (userAccessAddr, userMetaAddress) into DataStore
	userlib.DatastoreSet(string(userAccessAddr), pubEryMetaAddr)

}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.

func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	// Here we assume Alice is appending to the file

	// ========================================================= //
	// The FIRST part is to calcualte the user entry address and //
	// get the address of the metadata for the file              //
	// ========================================================= //

	// Calculate the address storing the address for Bob's metadata for the file
	userAccessAddr := string(userlib.Argon2Key([]byte(userdata.Password), []byte(filename), 16))
	// Get the pubEryMetaAddr where stores the metadata and decript it with privateKey
	pubEryMetaAddr, ok := userlib.DatastoreGet(userAccessAddr)
	if !ok {
		return errors.New("Error accessing data from Datastore! [Address: " + userAccessAddr + "]")
	}
	userMetaAddr, err := userlib.RSADecrypt(userdata.PrivateKey, pubEryMetaAddr, nil)
	if err != nil {
		return err
	}

	// ======================================================== //
	// The SECOND part is to get metadata and extract all infos //
	// including the keys and the address of the fileLink       //
	// ======================================================== //

	// 1. Get the pubEryMarFileMeta stored at the userMetaAddr and decrypt it  with privateKey
	pubEryMarFileMeta, ok := userlib.DatastoreGet(string(userMetaAddr))
	if !ok {
		return errors.New("Error accessing data from Datastore! [Address: " + string(userMetaAddr) + "]")
	}
	marshalFileMeta, err := userlib.RSADecrypt(userdata.PrivateKey, pubEryMarFileMeta, nil)
	if err != nil {
		return err
	}
	// 2. UnMarshal to get fileMeta
	var fileMeta FileMeta
	err = json.Unmarshal(marshalFileMeta, &fileMeta)
	if err != nil {
		return err
	}
	// 3. Get the fileAddr and the keys (requires decryption with user's private key)
	fileDirectAddr := fileMeta.FileDirectAddr
	keyFile := fileMeta.FileKey
	keyNonce := fileMeta.FileNonce
	keyHMAC := fileMeta.FileHMAC

	// ========================================================= //
	// The THIRD part is to get fileLinkAddr from fileDirectAddr //
	// ========================================================= //

	// Get encryptFileLinkAddr from fileDirectAddr
	encryptFileLinkAddr, ok := userlib.DatastoreGet(string(fileDirectAddr))
	if !ok {
		return errors.New("Error accessing data from Datastore! [Address: " + string(fileDirectAddr) + "]")
	}
	// Decrypt for fileLinkAddr using keyFile
	fileLinkAddr := make([]byte, len(encryptFileLinkAddr))
	decryptorLA := userlib.CFBDecrypter(keyFile, keyNonce)
	decryptorLA.XORKeyStream(fileLinkAddr, encryptFileLinkAddr)


	// ======================================================================= //
	// The FOURTH part is to save the appended content somewhere in Datastore, //
	// the address is later added to the fileLink of the file frame. 	       //
	// ======================================================================= //

	// Create an random address to store the file
	appendedFileAddr := userlib.RandomBytes(16)
	// Encrypt the file content
	var encryptedFile = make([]byte, len(data))
	encryptor := userlib.CFBEncrypter(keyFile, keyNonce)
	encryptor.XORKeyStream(encryptedFile, data)
	// Calculate the HMAC tag for the file
	hmac := userlib.NewHMAC(keyHMAC)
	hmac.Write(encryptedFile)
	hmacFile := hmac.Sum([]byte(""))
	// Store information about the file in a FileData struct
	var fileData FileData
	fileData.FileContent = encryptedFile
	fileData.FileHMAC = hmacFile
	// Marshal the fileData info
	marshalFileData, err := json.Marshal(fileData)
	if err != nil {
		return err
	}
	// Store the file's data to the Datastore
	userlib.DatastoreSet(string(appendedFileAddr), marshalFileData)

	// ==================================================== //
	// The FIFTH part is to append the address of the newly //
	// appended content to the fileLink frame of the file   //
	// ==================================================== //

	// Get the encryptMarFileLink from the fileAddr and decrypt it with
	// keyFile (encryption key) to get the marshalFileLink
	encryptMarFileLink, ok := userlib.DatastoreGet(string(fileLinkAddr))
	if !ok {
		return errors.New("Error accessing data from Datastore! [Address: " + string(fileLinkAddr) + "]")
	}
	marshalFileLink := make([]byte, len(encryptMarFileLink))
	decryptorMFL := userlib.CFBDecrypter(keyFile, keyNonce)
	decryptorMFL.XORKeyStream(marshalFileLink, encryptMarFileLink)
	// UnMarshal to get fileLink
	var fileLink FileLink
	err = json.Unmarshal(marshalFileLink, &fileLink)
	if err != nil {
		return err
	}
	// Create a new FileLink to store the address of the appended content
	var appendedFileLink FileLink
	appendedFileLink.CurrAddr = appendedFileAddr
	appendedFileLink.NextFileLink = nil
	// Add the appendedFileLink to the end of the file FileLink
	var fileLinkFrame *FileLink
	fileLinkFrame = &fileLink
	for fileLinkFrame.NextFileLink != nil {
		fileLinkFrame = fileLinkFrame.NextFileLink
	}
	fileLinkFrame.NextFileLink = &appendedFileLink

	// ========================================================= //
	// The SIXTH part is to upload the new fileLink to the frame //
	// ========================================================= //

	// Marshal and encrypt (keyFile) the new fileLink
	marshalNewFileLink, err := json.Marshal(fileLink)
	if err != nil {
		return err
	}
	var encryptMarNewFileLink = make([]byte, len(marshalNewFileLink))
	encryptorMFL := userlib.CFBEncrypter(keyFile, keyNonce)
	encryptorMFL.XORKeyStream(encryptMarNewFileLink, marshalNewFileLink)
	// Upload the new fileLink to the frame
	userlib.DatastoreSet(string(fileLinkAddr), encryptMarNewFileLink)

	return err
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {
	// In this part we call the user Bob

	// ========================================================= //
	// The FIRST part is to calcualte the user entry address and //
	// get the address of the metadata for the file              //
	// ========================================================= //

	// Calculate the address storing the address for Bob's metadata for the file
	userAccessAddr := string(userlib.Argon2Key([]byte(userdata.Password), []byte(filename), 16))
	// Get the pubEryMetaAddr where stores the metadata and decript it with privateKey
	pubEryMetaAddr, ok := userlib.DatastoreGet(userAccessAddr)
	if !ok {
		return nil, errors.New("Error accessing data from Datastore! [Address: " + userAccessAddr + "]")
	}
	userMetaAddr, err := userlib.RSADecrypt(userdata.PrivateKey, pubEryMetaAddr, nil)


	// ======================================================== //
	// The SECOND part is to get metadata and extract all infos //
	// including the keys and the address of the fileLink       //
	// ======================================================== //

	// 1. Get the pubEryMarFileMeta stored at the userMetaAddr and decrypt it  with privateKey
	pubEryMarFileMeta, ok := userlib.DatastoreGet(string(userMetaAddr))
	if !ok {
		return nil, errors.New("Error accessing data from Datastore! [Address: " + string(userMetaAddr) + "]")
	}
	marshalFileMeta, err := userlib.RSADecrypt(userdata.PrivateKey, pubEryMarFileMeta, nil)
	if err != nil {
		return nil, err
	}
	// 2. UnMarshal to get fileMeta
	var fileMeta FileMeta
	err = json.Unmarshal(marshalFileMeta, &fileMeta)
	if err != nil {
		return nil, err
	}
	// 3. Get the fileAddr and the keys (requires decryption with user's private key)
	fileDirectAddr := fileMeta.FileDirectAddr
	keyFile := fileMeta.FileKey
	keyNonce := fileMeta.FileNonce
	keyHMAC := fileMeta.FileHMAC

	// ========================================================= //
	// The THIRD part is to get fileLinkAddr from fileDirectAddr //
	// ========================================================= //

	// Get encryptFileLinkAddr from fileDirectAddr
	encryptFileLinkAddr, ok := userlib.DatastoreGet(string(fileDirectAddr))
	if !ok {
		return nil, errors.New("Error accessing data from Datastore! [Address: " + string(fileDirectAddr) + "]")
	}
	// Decrypt for fileLinkAddr using keyFile
	fileLinkAddr := make([]byte, len(encryptFileLinkAddr))
	decryptorLA := userlib.CFBDecrypter(keyFile, keyNonce)
	decryptorLA.XORKeyStream(fileLinkAddr, encryptFileLinkAddr)

	// ================================================== //
	// The FOURTH part is to get the FileLink information //
	// ================================================== //

	// Get the encryptMarFileLink from the fileAddrm and decrypt it with
	// keyFile (encryption key) to get the marshalFileLink
	encryptMarFileLink, ok := userlib.DatastoreGet(string(fileLinkAddr))
	if !ok {
		return nil, errors.New("Error accessing data from Datastore! [Address: " + string(fileLinkAddr) + "]")
	}
	marshalFileLink := make([]byte, len(encryptMarFileLink))
	decryptorMFL := userlib.CFBDecrypter(keyFile, keyNonce)
	decryptorMFL.XORKeyStream(marshalFileLink, encryptMarFileLink)
	// UnMarshal to get fileLink
	var fileLink FileLink
	err = json.Unmarshal(marshalFileLink, &fileLink)
	if err != nil {
		return nil, err
	}

	// ========================================================= //
	// The FIFTH part is to read content of the file iteratively //
	// according to the addresses in fileLink                    //
	// ========================================================= //

	// 1. Firstly we read the current content of the file

	// Get address of the current file address
	currentAddr := fileLink.CurrAddr
	// Get the marshaLFileData for current address
	marshalFileData, ok := userlib.DatastoreGet(string(currentAddr))
	if !ok {
		return nil, errors.New("Error accessing data from Datastore! [Address: " + string(currentAddr) + "]")
	}
	// UnMarshal to get currFileData
	var currFileData FileData
	err = json.Unmarshal(marshalFileData, &currFileData)
	if err != nil {
		return nil, err
	}
	// Get the encrypted currFile content and hmac
	encryptedFile := currFileData.FileContent
	hmacFile := currFileData.FileHMAC
	// Re-Calculate and check for the HMAC tag to check Integrity
	hmac := userlib.NewHMAC(keyHMAC)
	hmac.Write(encryptedFile)
	hmacValueCheck := hmac.Sum([]byte(""))
	if !userlib.Equal(hmacFile, hmacValueCheck) {
		return nil, err
	}
	// Decrypt the currFile content
	currFileContent := make([]byte, len(encryptedFile))
	decryptor := userlib.CFBDecrypter(keyFile, keyNonce)
	decryptor.XORKeyStream(currFileContent, encryptedFile)

	// 2. Then we iteratively load all appended content of the file

	// Set a variable as the constriant variable for the "while" loop
	// condition checking if the filelink has next (if the file loading
	// reaches the end)
	nextFileLink := fileLink.NextFileLink
	// Create an empty total content for iterative adding to
	var appendedContent []byte
	// Then we start the iteration (double check the variable names)
	for nextFileLink != nil {
		nextCurrAddr := nextFileLink.CurrAddr
		marshalNextFileData, ok := userlib.DatastoreGet(string(nextCurrAddr))
		if !ok {
			return nil, errors.New("Error accessing data from Datastore! [Address: " + string(nextCurrAddr) + "]")
		}
		var nextCurrFileData FileData
		err = json.Unmarshal(marshalNextFileData, &nextCurrFileData)
		if err != nil {
			return nil, err
		}
		encryptedNextFile := nextCurrFileData.FileContent
		hmacNextFile := nextCurrFileData.FileHMAC
		hmac := userlib.NewHMAC(keyHMAC)
		hmac.Write(encryptedNextFile)
		hmacValueCheck := hmac.Sum([]byte(""))
		if !userlib.Equal(hmacNextFile, hmacValueCheck) {
			return nil, errors.New("Error: HMAC Integrity Check Failed! ")
		}
		nextCurrFileContent := make([]byte, len(encryptedNextFile))
		decryptor := userlib.CFBDecrypter(keyFile, keyNonce)
		decryptor.XORKeyStream(nextCurrFileContent, encryptedNextFile)
		// Append the content to the total appendedContent
		appendedContent = append(appendedContent, nextCurrFileContent...)
		// Update the nextFileLink value
		nextFileLink = nextFileLink.NextFileLink
	}

	// ========================================================= //
	// The SIXTH part is to concat current and appended contents //
	// ========================================================= //

	// Concat all content for a full content
	fullContent := append(currFileContent, appendedContent...)

	data = fullContent
	return data, err
}

// You may want to define what you actually want to pass as a
// sharingRecord to serialized/deserialize in the data store.
type sharingRecord struct {
}

// The ShareMsg struct is used as the message shared by an owner of
// a file to another user. I contains (1) an encrypted (revPubKey) address
// where stores the recipient's metadata and (2) an sender's signature on (1)
type ShareMsg struct {
	// Encrypted address where stores the recipient's metadata
	Address []byte
	// Sender's signiture
	Signature []byte
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.

func (userdata *User) ShareFile(filename string, recipient string) (msgid string, err error) {
	// Here we assume Alice is sharing the file and Bob is receiving

	// ========================================================= //
	// The FIRST part is to calcualte the user entry address and //
	// get the address of the metadata for the file              //
	// ========================================================= //

	// Calculate the address storing the address for Bob's metadata for the file
	userAccessAddr := string(userlib.Argon2Key([]byte(userdata.Password), []byte(filename), 16))
	// Get the pubEryMetaAddr where stores the metadata and decript it with privateKey
	pubEryMetaAddr, ok := userlib.DatastoreGet(userAccessAddr)
	if !ok {
		return "", err
	}
	userMetaAddr, err := userlib.RSADecrypt(userdata.PrivateKey, pubEryMetaAddr, nil)


	// ======================================================== //
	// The SECOND part is to get metadata and extract all infos //
	// including the keys and the address of the fileLink       //
	// ======================================================== //

	// 1. Get the pubEryMarFileMeta stored at the userMetaAddr and decrypt it  with privateKey
	pubEryMarFileMeta, ok := userlib.DatastoreGet(string(userMetaAddr))
	if !ok {
		return "", errors.New("Error accessing data from Datastore! [Address: " + string(userMetaAddr) + "]")
	}
	marshalFileMeta, err := userlib.RSADecrypt(userdata.PrivateKey, pubEryMarFileMeta, nil)
	if err != nil {
		return "", err
	}
	// 2. UnMarshal to get fileMeta
	var fileMeta FileMeta
	err = json.Unmarshal(marshalFileMeta, &fileMeta)
	if err != nil {
		return "", err
	}
	// 3. Get the fileAddr and the keys (requires decryption with user's private key)
	fileDirectAddr := fileMeta.FileDirectAddr
	keyFile := fileMeta.FileKey
	keyNonce := fileMeta.FileNonce
	keyHMAC := fileMeta.FileHMAC

	// =================================================================== //
	// The THIRD part is to create the middle layer (metadata for Bob) for //
	// the recipient, the address and value (metadata info) should be enc- //
	// rypted with Bob's public key.                                       //
	// =================================================================== //

	// 1. Create the address to store Bob's metadata
	revMetaAddr := userlib.RandomBytes(16)

	// 2. Generate the file info Bob need to find and open the file
	// The materials needed are (fileAddr, keyFile, keyNonce, keyHMAC) <- (pubB)
	// (1) Store the metadata of file info for Bob in FileMeta struct
	var revFileMeta FileMeta
	revFileMeta.FileDirectAddr = fileDirectAddr
	revFileMeta.FileKey = keyFile
	revFileMeta.FileNonce = keyNonce
	revFileMeta.FileHMAC = keyHMAC
	// (2) Marshal the revFileMeta
	marshalRevFileMeta, _ := json.Marshal(revFileMeta)
	// (3) Encrypt the marshalRevFileMeta with Bob's public key
	revPublicKey, ok := userlib.KeystoreGet(recipient)
	if !ok {
		return "", errors.New("Error accessing data from Keystore! [Address: " + recipient + "]")
	}
	pubEryMarRevFileMeta, err := userlib.RSAEncrypt(&revPublicKey, marshalRevFileMeta, nil)
	if err != nil {
		return "", err
	}
	// Store the middle layer which let Bob access information about the file
	// Store (userMetaAddress, marshalFileMeta)
	userlib.DatastoreSet(string(revMetaAddr), pubEryMarRevFileMeta)

	// ============================================================ //
	// The FOURTH part is to encrypt the address where stores Bob's //
	// metadata. Then we send the encrypted address with Alice's    //
	// signiture, so that Bob can check the authentication          //
	// ============================================================ //

	// 1. Encrypt the revMetaAddr where stores Bob's metadata using Bob's public key
	pubEryRevMetaAddr, err := userlib.RSAEncrypt(&revPublicKey, revMetaAddr, nil)
	if err != nil {
		return "", err
	}
	// 2. Sign the pubEryRevMetaAddr by Alice's signiture
	userSignature, err := userlib.RSASign(userdata.PrivateKey, pubEryRevMetaAddr)
	if err != nil {
		return "", err
	}
	// 3. Form the pubEryRevMetaAddr and userSigniture into one ShareMsg
	var shareMsg ShareMsg
	shareMsg.Address = pubEryRevMetaAddr
	shareMsg.Signature = userSignature
	// Marshal the shareMsg
	marshalShareMsg, err := json.Marshal(shareMsg)
	if err != nil {
		return "", err
	}

	return string(marshalShareMsg), err
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string, msgid string) error {
	// Here we assume Bob is receiving the file sent from Alice
	var err error

	// ================================================================== //
	// The FIRST part is to UnMarshal the message and check the Signature //
	// ================================================================== //

	// 1. UnMarshal the message and get info
	var shareMsg ShareMsg
	err = json.Unmarshal([]byte(msgid), &shareMsg)
	if err != nil {
		return err
	}
	pubEryMetaAddr := shareMsg.Address
	senderSignature := shareMsg.Signature
	// 2. Check sender's signature
	senderPublicKey, ok := userlib.KeystoreGet(sender)
	if !ok {
		return errors.New("Error accessing data from Keystore! [Address: " + sender + "]")
	}
	err = userlib.RSAVerify(&senderPublicKey, pubEryMetaAddr, senderSignature)
	if err != nil {
		return err
	}

	// ======================================================== //
	// The SECOND part is to create Bob's own entry to the file //
	// which points to Bob's metadata address                   //
	// ======================================================== //

	// 1. Create entry address code
	userAccessAddr := string(userlib.Argon2Key([]byte(userdata.Password), []byte(filename), 16))
	// 2. Store (userAccessAddr, userMetaAddr) to DataStore
	userlib.DatastoreSet(userAccessAddr, pubEryMetaAddr)

	return nil
}

// Removes access for all others.
func (userdata *User) RevokeFile(filename string) (err error) {
	// Here we assume Alice do the revoke

	// ========================================================= //
	// The FIRST part is to calcualte the user entry address and //
	// get the address of the metadata for the file              //
	// ========================================================= //

	// Calculate the address storing the address for Bob's metadata for the file
	userAccessAddr := string(userlib.Argon2Key([]byte(userdata.Password), []byte(filename), 16))
	// Get the pubEryMetaAddr where stores the metadata and decript it with privateKey
	pubEryMetaAddr, ok := userlib.DatastoreGet(userAccessAddr)
	if !ok {
		return errors.New("Error accessing data from Datastore! [Address: " + userAccessAddr + "]")
	}
	userMetaAddr, err := userlib.RSADecrypt(userdata.PrivateKey, pubEryMetaAddr, nil)

	// ======================================================== //
	// The SECOND part is to get metadata and extract all infos //
	// including the keys and the address of the fileLink       //
	// ======================================================== //

	// 1. Get the pubEryMarFileMeta stored at the userMetaAddr and decrypt it  with privateKey
	pubEryMarFileMeta, ok := userlib.DatastoreGet(string(userMetaAddr))
	if !ok {
		return err
	}
	marshalFileMeta, err := userlib.RSADecrypt(userdata.PrivateKey, pubEryMarFileMeta, nil)
	if err != nil {
		return err
	}
	// 2. UnMarshal to get fileMeta
	var fileMeta FileMeta
	err = json.Unmarshal(marshalFileMeta, &fileMeta)
	if err != nil {
		return err
	}
	// 3. Get the fileDirectAddr and isCreator factor to determine if is creator
	fileDirectAddr := fileMeta.FileDirectAddr
	isCreator := fileMeta.IsCreator

	// ======================================================== //
	// The THIRD part is to check if is creator. If so, get the //
	// encryptFileLinkAddr, create a newFileDirectAddr to store //
	// that, then delete information of the olad fileDirectAddr //
	// on the Datastore, forbidding other owners' access        //
	// ======================================================== //

	// Check if creator
	if !isCreator {
		return errors.New("Not the creator of the file, cannot revoke! ")
	}
	// Get encryptFileLinkAddr from fileDirectAddr
	encryptFileLinkAddr, ok := userlib.DatastoreGet(string(fileDirectAddr))
	if !ok {
		return errors.New("Error accessing data from Datastore! [Address: " + string(fileDirectAddr) + "]")
	}
	// Create a newFileDirectAddr and store the encryptFileLinkAddr
	newFileDirectAddr := userlib.RandomBytes(16)
	userlib.DatastoreSet(string(newFileDirectAddr), encryptFileLinkAddr)
	// Delete the information stored in original fileDirectAddr
	userlib.DatastoreDelete(string(fileDirectAddr))

	// ===================================================================== //
	// The FOURTH part is to update the fileMeta and upload the new fileMeta //
	// ===================================================================== //

	// 1. Update the FileDirectAddr in fileMeta
	fileMeta.FileDirectAddr = newFileDirectAddr
	// 2. Marshal the fileMeta
	marshalNewFileMeta, err := json.Marshal(fileMeta)
	if err != nil {
		return err
	}
	// 3. Encrypt the marshalFileMeta with Alice's public key
	userPublicKey := userdata.PrivateKey.PublicKey
	pubEryMarNewFileMeta, err := userlib.RSAEncrypt(&userPublicKey, marshalNewFileMeta, nil)
	if err != nil {
		return err
	}
	// Update information stored in userMetaAddr to be pubEryMarNewFileMeta
	userlib.DatastoreSet(string(userMetaAddr), pubEryMarNewFileMeta)

	return nil
}
