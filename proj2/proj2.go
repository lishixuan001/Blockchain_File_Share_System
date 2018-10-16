package proj2

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (
	"fmt"
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
	KeyEncrypt []byte
	KeyNonce []byte
	KeyHMAC []byte
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

	// Store the Keys
	userdata.KeyEncrypt = encryptKey
	userdata.KeyNonce = nonce
	userdata.KeyHMAC = hmacKey

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


// The FileMetaStorage stores the encryptedMarFileMeta info and its HMAC checking
type FileMetaStorage struct {
	// The encrypted marshal FileLink
	EryMarFileMeta []byte
	// The HMAC tag for EryMarFileLink
	TagHMAC []byte
}

// The FileMeta struct is used by users storing the metadata including the location and keys for the file.
// It stores the address of the file, keyFile(pub), keyNonce(pub), and keyHMAC(pub)
type FileMeta struct {
	// FileDirect Address
	FileLinkStorageAddr []byte
	// File's Encryption Key
	FileKey []byte
	// File's Encryption Nonce
	FileNonce []byte
	// File's HMAC Key
	FileHMAC []byte
}

// The FileLinkStorage stores the encryptedMarFileLInk info and its HMAC checking
type FileLinkStorage struct {
	// The encrypted marshal FileLink
	EryMarFileLink []byte
	// The HMAC tag for EryMarFileLink
	TagHMAC []byte
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

	// We Create an address to store the FileLinkStorage information
	// Information about FileLink and its HMAC are stored in FileLinkStorage
	fileLinkStorageAddr := userlib.RandomBytes(16)
	// We create an FileLink to store the address info
	var fileLink FileLink
	fileLink.CurrAddr = fileAddr
	fileLink.NextFileLink = nil
	// Marshal and encrypt the fileLink using keyFile (encryption)
	marshalFileLink, _ := json.Marshal(fileLink)
	var encryptMarFileLink = make([]byte, len(marshalFileLink))
	encryptorMFL := userlib.CFBEncrypter(keyFile, keyNonce)
	encryptorMFL.XORKeyStream(encryptMarFileLink, marshalFileLink)

	// Create an HMAC validation to the encryptMarFileLink
	hmacLink := userlib.NewHMAC(keyHMAC)
	hmacLink.Write(encryptMarFileLink)
	hmacFileLink := hmacLink.Sum([]byte(""))
	// Store all info about FileLink into FileLinkStorage
	var fileLinkStorage FileLinkStorage
	fileLinkStorage.EryMarFileLink = encryptMarFileLink
	fileLinkStorage.TagHMAC = hmacFileLink
	// Marshal the fileLinkStorage
	marshalFileLinkStorage, _ := json.Marshal(fileLinkStorage)
	// Store the fileLinkStorage info to the Datastore
	userlib.DatastoreSet(string(fileLinkStorageAddr), marshalFileLinkStorage)

	// ========================================================= //
	// The THIRD task is to store the fileDirect infomation and //
	// the keys for opening the files as metadata for the user   //
	// ========================================================= //

	// Create the access address encoded by Alice's password and Alice's filename
	// 1. Create the access address
	userAccessAddr := userlib.Argon2Key([]byte(filename), []byte(userdata.Password), 16)
	// 2. Generate the file info Alice need to find and open the file
	// The materials needed are fileMetaStorage -> [(fileLinkStorageAddr, keyFile, keyNonce, keyHMAC) <- (eryA), hmacA]
	// (1) Store the metadata of file info for Alice in FileMeta struct
	var fileMeta FileMeta
	fileMeta.FileLinkStorageAddr = fileLinkStorageAddr
	fileMeta.FileKey = keyFile
	fileMeta.FileNonce = keyNonce
	fileMeta.FileHMAC = keyHMAC
	// (2) Marshal the fileMeta
	marshalFileMeta, _ := json.Marshal(fileMeta)
	// (3) Encrypt the marshalFileMeta with Alice's encryption key
	var encryptedMarFileMeta = make([]byte, len(marshalFileMeta))
	encryptorFM := userlib.CFBEncrypter(userdata.KeyEncrypt, userdata.KeyNonce)
	encryptorFM.XORKeyStream(encryptedMarFileMeta, marshalFileMeta)
	// Create an HMAC tag for encryotedMarFileMeta
	userKeyHMAC := userdata.KeyHMAC
	hmacMeta := userlib.NewHMAC(userKeyHMAC)
	hmacMeta.Write(encryptedMarFileMeta)
	hmacFileMeta := hmacMeta.Sum([]byte(""))
	// Create an FileMetaStorage struct to store the encryotedMarFileMeta and its HMAC tag
	var fileMetaStorage FileMetaStorage
	fileMetaStorage.EryMarFileMeta = encryptedMarFileMeta
	fileMetaStorage.TagHMAC = hmacFileMeta
	// Marshal the fileMetaStorage
	marshalFileMetaStorage, _ := json.Marshal(fileMetaStorage)
	// Store the fileMetaStorage info to the Datastore
	userlib.DatastoreSet(string(userAccessAddr), marshalFileMetaStorage)

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
	// get the the metadata for the file                         //
	// ========================================================= //

	// Calculate the address storing the address for Bob's metadata for the file
	userAccessAddr := userlib.Argon2Key([]byte(filename), []byte(userdata.Password), 16)
	// Get the marshalFileMetaStorage where stores the FileMetaStorage
	marshalFileMetaStorage, ok := userlib.DatastoreGet(string(userAccessAddr))
	if !ok {
		return errors.New("Error accessing data from Datastore! [Address: " + string(userAccessAddr) + "]")
	}
	// Unmarshal for fileMetaStorage
	var fileMetaStorage FileMetaStorage
	err = json.Unmarshal(marshalFileMetaStorage, &fileMetaStorage)
	if err != nil {
		return err
	}
	// Extract encryptedMarFileMeta and hmacFileMeta
	encryptedMarFileMeta := fileMetaStorage.EryMarFileMeta
	hmacFileMeta := fileMetaStorage.TagHMAC
	// Validate the HMAC tag
	hmacMeta := userlib.NewHMAC(userdata.KeyHMAC)
	hmacMeta.Write(encryptedMarFileMeta)
	hmacFileMetaCheck := hmacMeta.Sum([]byte(""))
	if !userlib.Equal(hmacFileMeta, hmacFileMetaCheck) {
		return err
	}
	// Decrypt for marshalFileMeta
	marshalFileMeta := make([]byte, len(encryptedMarFileMeta))
	decryptorFM := userlib.CFBDecrypter(userdata.KeyEncrypt, userdata.KeyNonce)
	decryptorFM.XORKeyStream(marshalFileMeta, encryptedMarFileMeta)
	// UnMarshal for fileMeta
	var fileMeta FileMeta
	err = json.Unmarshal(marshalFileMeta, &fileMeta)
	if err != nil {
		return err
	}
	// Get the FileLinkStorageAddr and keys
	fileLinkStorageAddr := fileMeta.FileLinkStorageAddr
	keyFile := fileMeta.FileKey
	keyNonce := fileMeta.FileNonce
	keyHMAC := fileMeta.FileHMAC

	// ======================================================================= //
	// The SECOND part is to save the appended content somewhere in Datastore, //
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
	// The THIRD part is to append the address of the newly //
	// appended content to the fileLink frame of the file   //
	// ==================================================== //

	// Get the marshalFileLinkStorage from fileLinkStorageAddr
	marshalFileLinkStorage, ok := userlib.DatastoreGet(string(fileLinkStorageAddr))
	if !ok {
		return errors.New("Error accessing data from Datastore! [Address: " + string(fileLinkStorageAddr) + "]")
	}
	// Unmarshal for fileLinkStorage
	var fileLinkStorage FileLinkStorage
	err = json.Unmarshal(marshalFileLinkStorage, &fileLinkStorage)
	if err != nil {
		return err
	}
	// Extract encryptedMarFileLink and hmacFileLink
	encryptedMarFileLink := fileLinkStorage.EryMarFileLink
	hmacFileLink := fileLinkStorage.TagHMAC
	// Validate the HMAC tag
	hmacLink := userlib.NewHMAC(keyHMAC)
	hmacLink.Write(encryptedMarFileLink)
	hmacFileLinkCheck := hmacLink.Sum([]byte(""))
	if !userlib.Equal(hmacFileLink, hmacFileLinkCheck) {
		return err
	}
	// Decrypt for marshalFileLink
	marshalFileLink := make([]byte, len(encryptedMarFileLink))
	decryptorFL := userlib.CFBDecrypter(keyFile, keyNonce)
	decryptorFL.XORKeyStream(marshalFileLink, encryptedMarFileLink)
	// UnMarshal for fileLink
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

	// ========================================================== //
	// The FOURTH part is to upload the new fileLink to the frame //
	// ========================================================== //

	// Marshal and encrypt the fileLink using keyFile (encryption)
	marshalNewFileLink, err := json.Marshal(fileLink)
	if err != nil {
		return err
	}
	var encryptMarNewFileLink = make([]byte, len(marshalNewFileLink))
	encryptorMFL := userlib.CFBEncrypter(keyFile, keyNonce)
	encryptorMFL.XORKeyStream(encryptMarNewFileLink, marshalNewFileLink)
	// Create an HMAC validation to the encryptMarFileLink
	hmacNewLink := userlib.NewHMAC(keyHMAC)
	hmacNewLink.Write(encryptMarNewFileLink)
	hmacNewFileLink := hmacNewLink.Sum([]byte(""))
	// Store all info about FileLink into FileLinkStorage
	var newFileLinkStorage FileLinkStorage
	newFileLinkStorage.EryMarFileLink = encryptMarNewFileLink
	newFileLinkStorage.TagHMAC = hmacNewFileLink
	// Marshal the fileLinkStorage
	marshalNewFileLinkStorage, err := json.Marshal(newFileLinkStorage)
	if err != nil {
		return err
	}
	// Store the fileLinkStorage info to the Datastore
	userlib.DatastoreSet(string(fileLinkStorageAddr), marshalNewFileLinkStorage)

	return err
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {
	// In this part we call the user Bob

	// ========================================================= //
	// The FIRST part is to calcualte the user entry address and //
	// get the the metadata for the file                         //
	// ========================================================= //

	// Calculate the address storing the address for Bob's metadata for the file
	userAccessAddr := userlib.Argon2Key([]byte(filename), []byte(userdata.Password), 16)
	// Get the marshalFileMetaStorage where stores the FileMetaStorage
	marshalFileMetaStorage, ok := userlib.DatastoreGet(string(userAccessAddr))
	if !ok {
		return nil, errors.New("Error accessing data from Datastore! [Address: " + string(userAccessAddr) + "]")
	}
	// Unmarshal for fileMetaStorage
	var fileMetaStorage FileMetaStorage
	err = json.Unmarshal(marshalFileMetaStorage, &fileMetaStorage)
	if err != nil {
		return nil, err
	}
	// Extract encryptedMarFileMeta and hmacFileMeta
	encryptedMarFileMeta := fileMetaStorage.EryMarFileMeta
	hmacFileMeta := fileMetaStorage.TagHMAC
	// Validate the HMAC tag
	hmacMeta := userlib.NewHMAC(userdata.KeyHMAC)
	hmacMeta.Write(encryptedMarFileMeta)
	hmacFileMetaCheck := hmacMeta.Sum([]byte(""))
	if !userlib.Equal(hmacFileMeta, hmacFileMetaCheck) {
		return nil, err
	}
	// Decrypt for marshalFileMeta
	marshalFileMeta := make([]byte, len(encryptedMarFileMeta))
	decryptorFM := userlib.CFBDecrypter(userdata.KeyEncrypt, userdata.KeyNonce)
	decryptorFM.XORKeyStream(marshalFileMeta, encryptedMarFileMeta)
	// UnMarshal for fileMeta
	var fileMeta FileMeta
	err = json.Unmarshal(marshalFileMeta, &fileMeta)
	if err != nil {
		return nil, err
	}
	// Get the FileLinkStorageAddr and keys
	fileLinkStorageAddr := fileMeta.FileLinkStorageAddr
	keyFile := fileMeta.FileKey
	keyNonce := fileMeta.FileNonce
	keyHMAC := fileMeta.FileHMAC

	// FIXME
	fmt.Println("fileLSA -- Load")
	fmt.Println(fileLinkStorageAddr)
	fmt.Println()

	// ================================================== //
	// The SECOND part is to get the FileLink information //
	// ================================================== //

	// Get the marshalFileLinkStorage from fileLinkStorageAddr
	marshalFileLinkStorage, ok := userlib.DatastoreGet(string(fileLinkStorageAddr))
	if !ok {
		return nil, errors.New("Error accessing data from Datastore! [Address: " + string(fileLinkStorageAddr) + "]")
	}
	// Unmarshal for fileLinkStorage
	var fileLinkStorage FileLinkStorage
	err = json.Unmarshal(marshalFileLinkStorage, &fileLinkStorage)
	if err != nil {
		return nil, err
	}
	// Extract encryptedMarFileLink and hmacFileLink
	encryptedMarFileLink := fileLinkStorage.EryMarFileLink
	hmacFileLink := fileLinkStorage.TagHMAC
	// Validate the HMAC tag
	hmacLink := userlib.NewHMAC(keyHMAC)
	hmacLink.Write(encryptedMarFileLink)
	hmacFileLinkCheck := hmacLink.Sum([]byte(""))
	if !userlib.Equal(hmacFileLink, hmacFileLinkCheck) {
		return nil, err
	}
	// Decrypt for marshalFileLink
	marshalFileLink := make([]byte, len(encryptedMarFileLink))
	decryptorFL := userlib.CFBDecrypter(keyFile, keyNonce)
	decryptorFL.XORKeyStream(marshalFileLink, encryptedMarFileLink)
	// UnMarshal for fileLink
	var fileLink FileLink
	err = json.Unmarshal(marshalFileLink, &fileLink)
	if err != nil {
		return nil, err
	}

	// ========================================================= //
	// The THIRD part is to read content of the file iteratively //
	// according to the addresses in fileLink                    //
	// ========================================================= //

	// 1. Firstly we read the current content of the file

	// Get address of the current file address
	currentAddr := fileLink.CurrAddr

	// FIXME
	fmt.Println("currAddr -- Load")
	fmt.Println(currentAddr)
	fmt.Println()

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
	hmacFileCheck := hmac.Sum([]byte(""))
	if !userlib.Equal(hmacFile, hmacFileCheck) {
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

	// ========================================================== //
	// The FOURTH part is to concat current and appended contents //
	// ========================================================== //

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
	// Encrypted metadata using recipient's public key
	MetaData []byte
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
	// get the the metadata for the file                         //
	// ========================================================= //

	// Calculate the address storing the address for Bob's metadata for the file
	userAccessAddr := userlib.Argon2Key([]byte(filename), []byte(userdata.Password), 16)
	// Get the marshalFileMetaStorage where stores the FileMetaStorage
	marshalFileMetaStorage, ok := userlib.DatastoreGet(string(userAccessAddr))
	if !ok {
		return "", errors.New("Error accessing data from Datastore! [Address: " + string(userAccessAddr) + "]")
	}
	// Unmarshal for fileMetaStorage
	var fileMetaStorage FileMetaStorage
	err = json.Unmarshal(marshalFileMetaStorage, &fileMetaStorage)
	if err != nil {
		return "", err
	}
	// Extract encryptedMarFileMeta and hmacFileMeta
	encryptedMarFileMeta := fileMetaStorage.EryMarFileMeta
	hmacFileMeta := fileMetaStorage.TagHMAC
	// Validate the HMAC tag
	hmacMeta := userlib.NewHMAC(userdata.KeyHMAC)
	hmacMeta.Write(encryptedMarFileMeta)
	hmacFileMetaCheck := hmacMeta.Sum([]byte(""))
	if !userlib.Equal(hmacFileMeta, hmacFileMetaCheck) {
		return "", err
	}
	// Decrypt for marshalFileMeta
	marshalFileMeta := make([]byte, len(encryptedMarFileMeta))
	decryptorFM := userlib.CFBDecrypter(userdata.KeyEncrypt, userdata.KeyNonce)
	decryptorFM.XORKeyStream(marshalFileMeta, encryptedMarFileMeta)
	// UnMarshal for fileMeta
	var fileMeta FileMeta
	err = json.Unmarshal(marshalFileMeta, &fileMeta)
	if err != nil {
		return "", err
	}
	// Get the FileLinkStorageAddr and keys
	fileLinkStorageAddr := fileMeta.FileLinkStorageAddr
	keyFile := fileMeta.FileKey
	keyNonce := fileMeta.FileNonce
	keyHMAC := fileMeta.FileHMAC

	// ================================================================ //
	// The SECOND part is to encrypt the metadata with Bob's public key //
	// ================================================================ //

	// Generate the file info Bob need to find and open the file
	// The materials needed are (fileAddr, keyFile, keyNonce, keyHMAC) <- (pubB)
	// (1) Store the metadata of file info for Bob in FileMeta struct
	var revFileMeta FileMeta
	revFileMeta.FileLinkStorageAddr = fileLinkStorageAddr
	revFileMeta.FileKey = keyFile
	revFileMeta.FileNonce = keyNonce
	revFileMeta.FileHMAC = keyHMAC
	// (2) Marshal the revFileMeta
	marshalRevFileMeta, err := json.Marshal(revFileMeta)
	if err != nil {
		return "", err
	}
	// (3) Encrypt the marshalRevFileMeta with Bob's public key
	revPublicKey, ok := userlib.KeystoreGet(recipient)
	if !ok {
		return "", errors.New("Error accessing data from Keystore! [Address: " + recipient + "]")
	}
	pubEryMarRevFileMeta, err := userlib.RSAEncrypt(&revPublicKey, marshalRevFileMeta, nil)
	if err != nil {
		return "", err
	}

	// ========================================================= //
	// The THIRD part is to add Alice's signature to the message //
	// ========================================================= //

	// 1. Sign the pubEryMarRevFileMeta by Alice's signiture
	userSignature, err := userlib.RSASign(userdata.PrivateKey, pubEryMarRevFileMeta)
	if err != nil {
		return "", err
	}
	// 2. Form the pubEryMarRevFileMeta and userSigniture into one ShareMsg
	var shareMsg ShareMsg
	shareMsg.MetaData = pubEryMarRevFileMeta
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
	pubEryMarRevFileMeta := shareMsg.MetaData
	senderSignature := shareMsg.Signature
	// 2. Check sender's signature
	senderPublicKey, ok := userlib.KeystoreGet(sender)
	if !ok {
		return errors.New("Error accessing data from Keystore! [Address: " + sender + "]")
	}
	err = userlib.RSAVerify(&senderPublicKey, pubEryMarRevFileMeta, senderSignature)
	if err != nil {
		return err
	}

	// ========================================== //
	// The SECOND part is to decrypt for metadata //
	// ========================================== //

	// Decrypt the message using Bob's private key
	privateKey := *userdata.PrivateKey
	marshalRevFileMeta, err := userlib.RSADecrypt(&privateKey, pubEryMarRevFileMeta, nil)
	if err != nil {
		return err
	}
	// UnMarshal for fileMeta
	var revFileMeta FileMeta
	err = json.Unmarshal(marshalRevFileMeta, &revFileMeta)
	if err != nil {
		return err
	}

	// ==================================================================== //
	// The THIRD part is to encrypt the metadata using Bob's encryption key //
	// create a HMAC tag, and then create Bob's access address to store the //
	// information														    //
	// ==================================================================== //

	// Create the access address encoded by Bob's password and Bob's filename
	// 1. Create the access address
	userAccessAddr := userlib.Argon2Key([]byte(filename), []byte(userdata.Password), 16)
	// 2. Generate the file info Bob need to find and open the file
	// The materials needed are fileMetaStorage -> [(fileLinkStorageAddr, keyFile, keyNonce, keyHMAC) <- (eryB), hmacB]
	// (1) Store the metadata of file info for Bob in FileMeta struct
	var fileMeta FileMeta
	fileMeta.FileLinkStorageAddr = revFileMeta.FileLinkStorageAddr
	fileMeta.FileKey = revFileMeta.FileKey
	fileMeta.FileNonce = revFileMeta.FileNonce
	fileMeta.FileHMAC = revFileMeta.FileHMAC
	// (2) Marshal the fileMeta
	marshalFileMeta, err := json.Marshal(fileMeta)
	if err != nil {
		return err
	}
	// (3) Encrypt the marshalFileMeta with Bob's encryption key
	var encryptedMarFileMeta = make([]byte, len(marshalFileMeta))
	encryptorFM := userlib.CFBEncrypter(userdata.KeyEncrypt, userdata.KeyNonce)
	encryptorFM.XORKeyStream(encryptedMarFileMeta, marshalFileMeta)
	// Create an HMAC tag for encryotedMarFileMeta
	userKeyHMAC := userdata.KeyHMAC
	hmacMeta := userlib.NewHMAC(userKeyHMAC)
	hmacMeta.Write(encryptedMarFileMeta)
	hmacFileMeta := hmacMeta.Sum([]byte(""))
	// Create an FileMetaStorage struct to store the encryotedMarFileMeta and its HMAC tag
	var fileMetaStorage FileMetaStorage
	fileMetaStorage.EryMarFileMeta = encryptedMarFileMeta
	fileMetaStorage.TagHMAC = hmacFileMeta
	// Marshal the fileMetaStorage
	marshalFileMetaStorage, err := json.Marshal(fileMetaStorage)
	if err != nil {
		return err
	}
	// Store the fileMetaStorage info to the Datastore
	userlib.DatastoreSet(string(userAccessAddr), marshalFileMetaStorage)

	return err
}

// Removes access for all others.
func (userdata *User) RevokeFile(filename string) (err error) {
	// Here we assume Alice do the revoke

	// ========================================================= //
	// The FIRST part is to calcualte the user entry address and //
	// get the the metadata for the file                         //
	// ========================================================= //

	// Calculate the address storing the address for Bob's metadata for the file
	userAccessAddr := userlib.Argon2Key([]byte(filename), []byte(userdata.Password), 16)
	// Get the marshalFileMetaStorage where stores the FileMetaStorage
	marshalFileMetaStorage, ok := userlib.DatastoreGet(string(userAccessAddr))
	if !ok {
		return errors.New("Error accessing data from Datastore! [Address: " + string(userAccessAddr) + "]")
	}
	// Unmarshal for fileMetaStorage
	var fileMetaStorage FileMetaStorage
	err = json.Unmarshal(marshalFileMetaStorage, &fileMetaStorage)
	if err != nil {
		return err
	}
	// Extract encryptedMarFileMeta and hmacFileMeta
	encryptedMarFileMeta := fileMetaStorage.EryMarFileMeta
	hmacFileMeta := fileMetaStorage.TagHMAC
	// Validate the HMAC tag
	hmacMeta := userlib.NewHMAC(userdata.KeyHMAC)
	hmacMeta.Write(encryptedMarFileMeta)
	hmacFileMetaCheck := hmacMeta.Sum([]byte(""))
	if !userlib.Equal(hmacFileMeta, hmacFileMetaCheck) {
		return err
	}
	// Decrypt for marshalFileMeta
	marshalFileMeta := make([]byte, len(encryptedMarFileMeta))
	decryptorFM := userlib.CFBDecrypter(userdata.KeyEncrypt, userdata.KeyNonce)
	decryptorFM.XORKeyStream(marshalFileMeta, encryptedMarFileMeta)
	// UnMarshal for fileMeta
	var fileMeta FileMeta
	err = json.Unmarshal(marshalFileMeta, &fileMeta)
	if err != nil {
		return err
	}
	// Get the FileLinkStorageAddr and keys
	fileLinkStorageAddr := fileMeta.FileLinkStorageAddr
	keyFile := fileMeta.FileKey
	keyNonce := fileMeta.FileNonce
	keyHMAC := fileMeta.FileHMAC

	// ================================================== //
	// The SECOND part is to get the FileLink information //
	// ================================================== //

	// Get the marshalFileLinkStorage from fileLinkStorageAddr
	marshalFileLinkStorage, ok := userlib.DatastoreGet(string(fileLinkStorageAddr))
	if !ok {
		return errors.New("Error accessing data from Datastore! [Address: " + string(fileLinkStorageAddr) + "]")
	}
	// Unmarshal for fileLinkStorage
	var fileLinkStorage FileLinkStorage
	err = json.Unmarshal(marshalFileLinkStorage, &fileLinkStorage)
	if err != nil {
		return err
	}
	// Extract encryptedMarFileLink and hmacFileLink
	encryptedMarFileLink := fileLinkStorage.EryMarFileLink
	hmacFileLink := fileLinkStorage.TagHMAC
	// Validate the HMAC tag
	hmacLink := userlib.NewHMAC(keyHMAC)
	hmacLink.Write(encryptedMarFileLink)
	hmacFileLinkCheck := hmacLink.Sum([]byte(""))
	if !userlib.Equal(hmacFileLink, hmacFileLinkCheck) {
		return err
	}
	// Decrypt for marshalFileLink
	marshalFileLink := make([]byte, len(encryptedMarFileLink))
	decryptorFL := userlib.CFBDecrypter(keyFile, keyNonce)
	decryptorFL.XORKeyStream(marshalFileLink, encryptedMarFileLink)
	// UnMarshal for fileLink
	var fileLink FileLink
	err = json.Unmarshal(marshalFileLink, &fileLink)
	if err != nil {
		return err
	}

	// ========================================================= //
	// The THIRD part is to read content of the file iteratively //
	// according to the addresses in fileLink                    //
	// ========================================================= //

	// Define the new keys
	// Generate keys to encrypt (& nonce), hash, and hmac the file
	keyString := userlib.RandomBytes(64)
	newFileAddr := keyString[0:16]
	newKeyFile := keyString[16:32] // Encryption Key
	newKeyNonce := keyString[32:48] // Encryption Nonce
	newKeyHMAC := keyString[48:64] // HMAC Key

	// Extract file contents and restore the files, start from the
	// current file content and iterate through every file content
	// Sum up the file content and store it in an integrity

	// Get address of the current file address
	currentAddr := fileLink.CurrAddr
	// Get the marshaLFileData for current address
	marshalFileData, ok := userlib.DatastoreGet(string(currentAddr))
	if !ok {
		return errors.New("Error accessing data from Datastore! [Address: " + string(currentAddr) + "]")
	}
	// UnMarshal to get currFileData
	var currFileData FileData
	err = json.Unmarshal(marshalFileData, &currFileData)
	if err != nil {
		return err
	}
	// Get the encrypted currFile content and hmac
	encryptedCurrFile := currFileData.FileContent
	hmacFile := currFileData.FileHMAC
	// Re-Calculate and check for the HMAC tag to check Integrity
	hmacCurr := userlib.NewHMAC(keyHMAC)
	hmacCurr.Write(encryptedCurrFile)
	hmacFileCheck := hmacCurr.Sum([]byte(""))
	if !userlib.Equal(hmacFile, hmacFileCheck) {
		return err
	}
	// Decrypt the currFile content
	currFileContent := make([]byte, len(encryptedCurrFile))
	decryptor := userlib.CFBDecrypter(keyFile, keyNonce)
	decryptor.XORKeyStream(currFileContent, encryptedCurrFile)

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
			return errors.New("Error accessing data from Datastore! [Address: " + string(nextCurrAddr) + "]")
		}
		var nextCurrFileData FileData
		err = json.Unmarshal(marshalNextFileData, &nextCurrFileData)
		if err != nil {
			return err
		}
		encryptedNextFile := nextCurrFileData.FileContent
		hmacNextFile := nextCurrFileData.FileHMAC
		hmac := userlib.NewHMAC(keyHMAC)
		hmac.Write(encryptedNextFile)
		hmacValueCheck := hmac.Sum([]byte(""))
		if !userlib.Equal(hmacNextFile, hmacValueCheck) {
			return errors.New("Error: HMAC Integrity Check Failed! ")
		}
		nextCurrFileContent := make([]byte, len(encryptedNextFile))
		decryptor := userlib.CFBDecrypter(keyFile, keyNonce)
		decryptor.XORKeyStream(nextCurrFileContent, encryptedNextFile)
		// Append the content to the total appendedContent
		appendedContent = append(appendedContent, nextCurrFileContent...)
		// Update the nextFileLink value
		nextFileLink = nextFileLink.NextFileLink
	}
	// Concat all content for a full content
	fullContent := append(currFileContent, appendedContent...)

	// ================================================================== //
	// The FOURTH part is to re-store the file content in the new address //
	// ================================================================== //

	// Encrypt the new file content
	var encryptedNewFile = make([]byte, len(fullContent))
	encryptor := userlib.CFBEncrypter(newKeyFile, newKeyNonce)
	encryptor.XORKeyStream(encryptedNewFile, fullContent)
	// Calculate the HMAC tag for the new file
	hmacNF := userlib.NewHMAC(newKeyHMAC)
	hmacNF.Write(encryptedNewFile)
	hmacNewFile := hmacNF.Sum([]byte(""))
	// Store information about the new file in a FileData struct
	var newFileData FileData
	newFileData.FileContent = encryptedNewFile
	newFileData.FileHMAC = hmacNewFile
	// Marshal the new fileData info
	marshalNewFileData, err := json.Marshal(newFileData)
	if err != nil {
		return err
	}
	// Store the new file's data to the Datastore
	userlib.DatastoreSet(string(newFileAddr), marshalNewFileData)

	fmt.Println("fileAddr -- Revoke")
	fmt.Println(newFileAddr)
	fmt.Println()

	// ======================================================== //
	// The FIFTH part is to create a new file link storage and  //
	// an address to store its information                      //
	// ======================================================== //

	// We Create an address to store the FileLinkStorage information
	// Information about FileLink and its HMAC are stored in FileLinkStorage
	newFileLinkStorageAddr := userlib.RandomBytes(16)
	// We create an new FileLink to store the address info
	var newFileLink FileLink
	newFileLink.CurrAddr = newFileAddr
	newFileLink.NextFileLink = nil
	// Marshal and encrypt the new fileLink using newKeyFile (encryption)
	marshalNewFileLink, err := json.Marshal(newFileLink)
	if err != nil {
		return err
	}
	var encryptMarNewFileLink = make([]byte, len(marshalNewFileLink))
	encryptorMNFL := userlib.CFBEncrypter(newKeyFile, newKeyNonce)
	encryptorMNFL.XORKeyStream(encryptMarNewFileLink, marshalNewFileLink)
	// Create an HMAC validation to the encryptMarNewFileLink
	hmacNewLink := userlib.NewHMAC(newKeyHMAC)
	hmacNewLink.Write(encryptMarNewFileLink)
	hmacNewFileLink := hmacNewLink.Sum([]byte(""))
	// Store all info about the new FileLink into a new FileLinkStorage
	var newFileLinkStorage FileLinkStorage
	newFileLinkStorage.EryMarFileLink = encryptMarNewFileLink
	newFileLinkStorage.TagHMAC = hmacNewFileLink
	// Marshal the newFileLinkStorage
	marshalNewFileLinkStorage, err := json.Marshal(newFileLinkStorage)
	if err != nil {
		return err
	}
	// Store the newFileLinkStorage info to the Datastore
	userlib.DatastoreSet(string(newFileLinkStorageAddr), marshalNewFileLinkStorage)

	// FIXME
	fmt.Println("fileLSA -- Revoke")
	fmt.Println(newFileLinkStorageAddr)
	fmt.Println()

	// ===================================================================== //
	// The SIXTH part is to modify and re-store the metadata info of Alice's //
	// ===================================================================== //

	// Note that the user access address does not change

	// 2. Generate the file info Alice need to find and open the file
	// The materials needed are fileMetaStorage -> [(fileLinkStorageAddr, keyFile, keyNonce, keyHMAC) <- (eryA), hmacA]
	// (1) Store the metadata of file info for Alice in FileMeta struct
	var newFileMeta FileMeta
	newFileMeta.FileLinkStorageAddr = newFileLinkStorageAddr
	newFileMeta.FileKey = newKeyFile
	newFileMeta.FileNonce = newKeyNonce
	newFileMeta.FileHMAC = newKeyHMAC
	// (2) Marshal the fileMeta
	marshalNewFileMeta, err := json.Marshal(newFileMeta)
	if err != nil {
		return err
	}
	// (3) Encrypt the marshalNewFileMeta with Alice's new encryption key
	var encryptedMarNewFileMeta = make([]byte, len(marshalNewFileMeta))
	encryptorMNFM := userlib.CFBEncrypter(userdata.KeyEncrypt, userdata.KeyNonce)
	encryptorMNFM.XORKeyStream(encryptedMarNewFileMeta, marshalNewFileMeta)
	// Create an HMAC tag for encryotedMarNewFileMeta using new HMAC key
	hmacNewMeta := userlib.NewHMAC(userdata.KeyHMAC)
	hmacNewMeta.Write(encryptedMarNewFileMeta)
	hmacNewFileMeta := hmacNewMeta.Sum([]byte(""))
	// Create an new FileMetaStorage struct to store the encryotedMarNewFileMeta and its HMAC tag
	var newFileMetaStorage FileMetaStorage
	newFileMetaStorage.EryMarFileMeta = encryptedMarNewFileMeta
	newFileMetaStorage.TagHMAC = hmacNewFileMeta
	// Marshal the newFileMetaStorage
	marshalNewFileMetaStorage, err := json.Marshal(newFileMetaStorage)
	if err != nil {
		return err
	}
	// Store the marshalNewFileMetaStorage info to the Datastore
	userlib.DatastoreSet(string(userAccessAddr), marshalNewFileMetaStorage)

	// ======================================================= //
	// The SEVENTH part is to delete the original file-related //
	// addresses and content 							       //
	// ======================================================= //


	return err
}



























// END