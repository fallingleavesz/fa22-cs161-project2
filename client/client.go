package client

// CS 161 Project 2

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
	"encoding/json"
	"strings"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// uuid.Parse()
	// uuid.New().String()

	// uuid.New().MarshalBinary()
	// uuid.FromBytes()

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

const defaultUUIDStr = "00000000-0000-0000-0000-000000000000"

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	Username string
	// uuid           uuid.UUID
	HashedPassword []byte
	SourceKey      []byte
	PKEEncKey      userlib.PKEEncKey
	PKEDecKey      userlib.PKEDecKey
	DSSignKey      userlib.DSSignKey
	DSVerifyKey    userlib.DSVerifyKey

	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

// datastore{ uuid: Enc(UserFileMap) }
// UserFileMap {"filename": UserFileMapEntry}
type UserFileMapEntry struct {
	Status       string // Own / Share
	FileMetaUUID uuid.UUID
	SymEncKey    []byte
	HMACKey      []byte
}

type FileMeta struct {
	Owner        string
	Status       string // FileMeta / Share
	Filename     string
	ShareList    uuid.UUID
	FileUuidList []uuid.UUID
	SymEncKey    []byte
	HMACKey      []byte
}

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdata.Username = username
	userdata.HashedPassword = userlib.Hash([]byte(password))[:]

	// UUID For User Struct
	HashedUsername := userlib.Hash([]byte(username))
	uuid, err := uuid.FromBytes(HashedUsername[:16])
	// userdata.uuid = uuid

	userdata.SourceKey = userlib.RandomBytes(16)

	// store username:publickey into keystore
	userdata.PKEEncKey, userdata.PKEDecKey, err = userlib.PKEKeyGen()
	userlib.KeystoreSet(userdata.Username+"_PKE", userdata.PKEEncKey)

	userdata.DSSignKey, userdata.DSVerifyKey, err = userlib.DSKeyGen()
	userlib.KeystoreSet(userdata.Username+"_DS", userdata.DSVerifyKey)

	// encrypt user struct with symmetric key and store user struct into datastore
	// for argon2key, password: hashedpassword, salt: hashedusername
	userBytes, err := json.Marshal(userdata)

	symKey := userlib.Argon2Key(userdata.HashedPassword, HashedUsername, 16)
	iv := userlib.RandomBytes(16)
	userBytesEnc := userlib.SymEnc(symKey, iv, userBytes)
	userBytesEncHash := userlib.Hash(userBytesEnc)
	userlib.DatastoreSet(uuid, append(userBytesEnc, userBytesEncHash...))

	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	HashedUsername := userlib.Hash([]byte(username))[:]
	HashedPassword := userlib.Hash([]byte(password))[:]

	uuid, err := uuid.FromBytes(HashedUsername[:16])

	userBytes, _ := userlib.DatastoreGet(uuid)
	userBytesEnc := userBytes[:len(userBytes)-64]
	userBytesEncHash := userBytes[len(userBytes)-64:]
	hashCal := userlib.Hash(userBytesEnc)

	if !Equal(userBytesEncHash, hashCal) {
		return
	}

	symKey := userlib.Argon2Key(HashedPassword, HashedUsername, 16)

	userBytes = userlib.SymDec(symKey, userBytesEnc)

	var userdata User
	err = json.Unmarshal(userBytes, &userdata)
	if err != nil {
		return
	}
	userdataptr = &userdata
	return userdataptr, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {

	// calculate deterministic UserFileMap encryption key
	symKey, err := userlib.HashKDF(userdata.SourceKey, []byte("UserFileMap-SymEnc"))
	symKey = symKey[:16]

	hMACKey, err := userlib.HashKDF(userdata.SourceKey, []byte("UserFileMap-HMAC"))
	hMACKey = hMACKey[:16]

	// init userFileMap & userFileMap Entry & FileMeta
	userFileMap := make(map[string]UserFileMapEntry)
	var userFileMapEntry UserFileMapEntry
	var fileMeta FileMeta

	var fileMetaBytes []byte
	var fileMetaBytesEnc []byte
	var fileMetaBytesHMAC []byte

	var iv []byte

	// get deterministic UserFileMap UUID and read userFileMapBytes
	userFileMapUUID, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + "UserFileMap"))[:16])
	userFileMapBytes, ok := userlib.DatastoreGet(userFileMapUUID)

	// UserFileMap exist, get userFileMap from datastore
	if ok {
		// auth and decrypt userFileMap
		userFileMapBytesEnc := userFileMapBytes[:len(userFileMapBytes)-64]
		userFileMapBytesHMAC := userFileMapBytes[len(userFileMapBytes)-64:]

		hMAC, _ := userlib.HMACEval(hMACKey, userFileMapBytesEnc)
		ok = userlib.HMACEqual(hMAC, userFileMapBytesHMAC)

		if !ok {
			return errors.New(strings.ToTitle("UserFileMap HMAC Verify Failure"))
		}

		// unmarshal bytes to userFileMap
		userFileMapBytes := userlib.SymDec(symKey, userFileMapBytesEnc)
		err = json.Unmarshal(userFileMapBytes, &userFileMap)
		if err != nil {
			return errors.New(strings.ToTitle("UserFileMap Unmarshal Failure"))
		}

	} else {
		// userFileMap does not exist, do nothing

	}

	userFileMapEntry, ok = userFileMap[filename]

	// First time to store the file, must be owner
	if !ok {
		// Init userFileMapEntry for that file
		userFileMapEntry.FileMetaUUID = uuid.New()
		userFileMapEntry.Status = "Own"
		userFileMapEntry.SymEncKey = userlib.RandomBytes(16)
		userFileMapEntry.HMACKey = userlib.RandomBytes(16)
		userFileMap[filename] = userFileMapEntry

		// Init fileMeta for that file
		fileMeta.Owner = userdata.Username
		fileMeta.Status = "FileMeta"
		fileMeta.ShareList = uuid.New()
		fileMeta.Filename = filename
		fileMeta.FileUuidList = append(fileMeta.FileUuidList, uuid.New())
		fileMeta.SymEncKey = userlib.RandomBytes(16)
		fileMeta.HMACKey = userlib.RandomBytes(16)
	} else {
		// Already have userFileMapEntry
		// iterate FileMeta nodes chain to get the last FileMeta node

		fileMetaUUID := userFileMapEntry.FileMetaUUID
		fileMetaSymKey := userFileMapEntry.SymEncKey
		fileMetaHMACKey := userFileMapEntry.HMACKey

		for {
			fileMetaBytes, ok = userlib.DatastoreGet(fileMetaUUID)
			if !ok {
				return errors.New(strings.ToTitle("StoreFile: FileMeta Node Not Found"))
			}

			fileMetaBytesEnc = fileMetaBytes[:len(userFileMapBytes)-64]
			fileMetaBytesHMAC = fileMetaBytes[len(userFileMapBytes)-64:]
			hMAC, _ := userlib.HMACEval(fileMetaHMACKey, fileMetaBytesEnc)
			ok = userlib.HMACEqual(hMAC, fileMetaBytesHMAC)

			if !ok {
				return errors.New(strings.ToTitle("StoreFile: FileMeta HMAC Verify Failure"))
			}

			// unmarshal fileMetaBytesEnc to fileMeta
			fileMetaBytes = userlib.SymDec(fileMetaSymKey, fileMetaBytesEnc)
			err = json.Unmarshal(fileMetaBytes, &fileMeta)
			if err != nil {
				return errors.New(strings.ToTitle("StoreFile: fileMeta Unmarshal Failure"))
			}

			if fileMeta.Status == "FileMeta" {
				break
			} else {
				fileMetaUUID = fileMeta.FileUuidList[0]
				fileMetaSymKey = fileMeta.SymEncKey
				fileMetaHMACKey = fileMeta.HMACKey
			}

		}

		// delete original files
		for _, uuid := range fileMeta.FileUuidList {
			userlib.DatastoreDelete(uuid)
			_, ok := userlib.DatastoreGet(uuid)
			if ok {
				panic("StoreFile: the data should have been deleted")
			}
		}
		// clear original fileUuidList
		// assign uuid to file

		fileMeta.FileUuidList = nil
		randomUUID := uuid.New()
		fileMeta.FileUuidList = append(fileMeta.FileUuidList, randomUUID)

	}

	// store fileUserMap to datastore
	userFileMapBytes, _ = json.Marshal(userFileMap)
	iv = userlib.RandomBytes(16)
	userFileMapBytesEnc := userlib.SymEnc(symKey, iv, userFileMapBytes)
	userFileMapBytesHMAC, _ := userlib.HMACEval(hMACKey, userFileMapBytesEnc)
	userlib.DatastoreSet(userFileMapUUID, append(userFileMapBytesEnc, userFileMapBytesHMAC...))

	// store fileMeta to datastore
	fileMetaBytes, _ = json.Marshal(fileMeta)
	iv = userlib.RandomBytes(16)
	fileMetaBytesEnc = userlib.SymEnc(userFileMapEntry.SymEncKey, iv, fileMetaBytes)
	fileMetaBytesHMAC, _ = userlib.HMACEval(userFileMapEntry.HMACKey, fileMetaBytesEnc)
	userlib.DatastoreSet(userFileMap[filename].FileMetaUUID, append(fileMetaBytesEnc, fileMetaBytesHMAC...))

	// store fileContent to datastore
	contentBytes, _ := json.Marshal(content)
	iv = userlib.RandomBytes(16)
	contentBytesEnc := userlib.SymEnc(fileMeta.SymEncKey, iv, contentBytes)
	contentBytesHMAC, _ := userlib.HMACEval(fileMeta.HMACKey, contentBytesEnc)
	userlib.DatastoreSet(fileMeta.FileUuidList[0], append(contentBytesEnc, contentBytesHMAC...))

	return

}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	// calculate deterministic UserFileMap encryption key
	symKey, err := userlib.HashKDF(userdata.SourceKey, []byte("UserFileMap-SymEnc"))
	symKey = symKey[:16]

	hMACKey, err := userlib.HashKDF(userdata.SourceKey, []byte("UserFileMap-HMAC"))
	hMACKey = hMACKey[:16]

	// init userFileMap & userFileMap Entry & FileMeta
	userFileMap := make(map[string]UserFileMapEntry)
	var userFileMapEntry UserFileMapEntry
	var fileMeta FileMeta

	var fileMetaBytes []byte
	var fileMetaBytesEnc []byte
	var fileMetaBytesHMAC []byte

	var iv []byte

	// get deterministic UserFileMap UUID and read userFileMapBytes
	userFileMapUUID, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + "UserFileMap"))[:16])
	userFileMapBytes, ok := userlib.DatastoreGet(userFileMapUUID)

	// UserFileMap exist, get userFileMap from datastore
	if ok {
		// auth and decrypt userFileMap
		userFileMapBytesEnc := userFileMapBytes[:len(userFileMapBytes)-64]
		userFileMapBytesHMAC := userFileMapBytes[len(userFileMapBytes)-64:]

		hMAC, _ := userlib.HMACEval(hMACKey, userFileMapBytesEnc)
		ok = userlib.HMACEqual(hMAC, userFileMapBytesHMAC)

		if !ok {
			return errors.New(strings.ToTitle("AppendToFile: UserFileMap HMAC Verify Failure"))
		}

		// unmarshal bytes to userFileMap
		userFileMapBytes := userlib.SymDec(symKey, userFileMapBytesEnc)
		err = json.Unmarshal(userFileMapBytes, &userFileMap)
		if err != nil {
			return errors.New(strings.ToTitle("AppendToFile: UserFileMap Unmarshal Failure"))
		}

	} else {
		// userFileMap does not exist, do nothing

	}

	userFileMapEntry, ok = userFileMap[filename]
	if !ok {
		return errors.New(strings.ToTitle("AppendToFile: UserFileMapEntry Not Exist"))
	}

	// iterate fileMeta Node chain to find the true fileMeta Node
	fileMetaUUID := userFileMapEntry.FileMetaUUID
	fileMetaSymKey := userFileMapEntry.SymEncKey
	fileMetaHMACKey := userFileMapEntry.HMACKey

	for {
		fileMetaBytes, ok = userlib.DatastoreGet(fileMetaUUID)
		if !ok {
			return errors.New(strings.ToTitle("AppendToFile: FileMeta Node Not Found"))
		}

		fileMetaBytesEnc = fileMetaBytes[:len(fileMetaBytes)-64]
		fileMetaBytesHMAC = fileMetaBytes[len(fileMetaBytes)-64:]
		hMAC, _ := userlib.HMACEval(fileMetaHMACKey, fileMetaBytesEnc)
		ok = userlib.HMACEqual(hMAC, fileMetaBytesHMAC)

		if !ok {
			return errors.New(strings.ToTitle("AppendToFile: FileMeta HMAC Verify Failure"))
		}

		// unmarshal fileMetaBytesEnc to fileMeta
		fileMetaBytes = userlib.SymDec(fileMetaSymKey, fileMetaBytesEnc)
		err = json.Unmarshal(fileMetaBytes, &fileMeta)
		if err != nil {
			return errors.New(strings.ToTitle("AppendToFile: fileMeta Unmarshal Failure"))
		}

		if fileMeta.Status == "FileMeta" {
			break
		} else {
			fileMetaUUID = fileMeta.FileUuidList[0]
			fileMetaSymKey = fileMeta.SymEncKey
			fileMetaHMACKey = fileMeta.HMACKey
		}

	}
	randomUUID := uuid.New()
	fileMeta.FileUuidList = append(fileMeta.FileUuidList, randomUUID)
	userlib.DebugMsg("%s append File: fileUuidList: %v", userdata.Username, fileMeta.FileUuidList)
	// store fileMeta to datastore
	fileMetaBytes, _ = json.Marshal(fileMeta)
	iv = userlib.RandomBytes(16)
	fileMetaBytesEnc = userlib.SymEnc(fileMetaSymKey, iv, fileMetaBytes)
	fileMetaBytesHMAC, _ = userlib.HMACEval(fileMetaHMACKey, fileMetaBytesEnc)
	userlib.DatastoreSet(fileMetaUUID, append(fileMetaBytesEnc, fileMetaBytesHMAC...))

	// store fileContent to datastore
	contentBytes, _ := json.Marshal(content)
	iv = userlib.RandomBytes(16)
	contentBytesEnc := userlib.SymEnc(fileMeta.SymEncKey, iv, contentBytes)
	contentBytesHMAC, _ := userlib.HMACEval(fileMeta.HMACKey, contentBytesEnc)
	userlib.DatastoreSet(randomUUID, append(contentBytesEnc, contentBytesHMAC...))

	return nil

}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	// calculate deterministic UserFileMap encryption key
	symKey, err := userlib.HashKDF(userdata.SourceKey, []byte("UserFileMap-SymEnc"))
	symKey = symKey[:16]

	hMACKey, err := userlib.HashKDF(userdata.SourceKey, []byte("UserFileMap-HMAC"))
	hMACKey = hMACKey[:16]

	// init userFileMap & userFileMap Entry & FileMeta
	var userFileMapEntry UserFileMapEntry
	userFileMap := make(map[string]UserFileMapEntry)
	var userFileMapBytes, userFileMapBytesEnc, userFileMapBytesHMAC []byte

	var fileMeta FileMeta
	var fileMetaBytes, fileMetaBytesEnc, fileMetaBytesHMAC []byte

	// var iv []byte

	// get deterministic UserFileMap UUID and read userFileMapBytes
	userFileMapUUID, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + "UserFileMap"))[:16])
	userFileMapBytes, ok := userlib.DatastoreGet(userFileMapUUID)

	if !ok {
		return nil, errors.New(strings.ToTitle("LoadFile: UserFileMpap Not Found"))
	}

	userFileMapBytesEnc = userFileMapBytes[:len(userFileMapBytes)-64]
	userFileMapBytesHMAC = userFileMapBytes[len(userFileMapBytes)-64:]

	hMAC, _ := userlib.HMACEval(hMACKey, userFileMapBytesEnc)
	ok = userlib.HMACEqual(hMAC, userFileMapBytesHMAC)

	if !ok {
		return nil, errors.New(strings.ToTitle("LoadFile HMAC Verify Failure"))
	}

	// unmarshaljib bytes to userFileMap
	userFileMapBytes = userlib.SymDec(symKey, userFileMapBytesEnc)
	err = json.Unmarshal(userFileMapBytes, &userFileMap)
	if err != nil {
		return nil, errors.New(strings.ToTitle("LoadFile: UserFileMap Unmarshal Failure"))
	}

	userFileMapEntry, ok = userFileMap[filename]

	if !ok {

		return nil, errors.New(strings.ToTitle("LoadFile: UserFileMapEntry Load Failure"))
	}

	fileMetaUUID := userFileMapEntry.FileMetaUUID
	fileMetaSymKey := userFileMapEntry.SymEncKey
	fileMetaHMACKey := userFileMapEntry.HMACKey

	for {
		fileMetaBytes, ok = userlib.DatastoreGet(fileMetaUUID)
		if !ok {
			return nil, errors.New(strings.ToTitle("LoadFile: FileMeta Node Not Found"))
		}

		fileMetaBytesEnc = fileMetaBytes[:len(fileMetaBytes)-64]
		fileMetaBytesHMAC = fileMetaBytes[len(fileMetaBytes)-64:]
		hMAC, _ := userlib.HMACEval(fileMetaHMACKey, fileMetaBytesEnc)
		ok = userlib.HMACEqual(hMAC, fileMetaBytesHMAC)

		if !ok {
			return nil, errors.New(strings.ToTitle("LoadFile: FileMeta HMAC Verify Failure"))
		}

		// unmarshal fileMetaBytesEnc to fileMeta
		fileMetaBytes = userlib.SymDec(fileMetaSymKey, fileMetaBytesEnc)
		err = json.Unmarshal(fileMetaBytes, &fileMeta)
		if err != nil {
			return nil, errors.New(strings.ToTitle("LoadFile: fileMeta Unmarshal Failure"))
		}

		if fileMeta.Status == "FileMeta" {
			break
		} else {
			fileMetaUUID = fileMeta.FileUuidList[0]
			fileMetaSymKey = fileMeta.SymEncKey
			fileMetaHMACKey = fileMeta.HMACKey
		}

	}

	// iterate file uuid to read the content
	fileSymKey := fileMeta.SymEncKey
	fileHMACKey := fileMeta.HMACKey

	for _, uuid := range fileMeta.FileUuidList {
		var tmp []byte
		tmpBytes, _ := userlib.DatastoreGet(uuid)
		tmpBytesEnc := tmpBytes[:len(tmpBytes)-64]
		tmpBytesHMAC := tmpBytes[len(tmpBytes)-64:]
		signaCal, _ := userlib.HMACEval(fileHMACKey, tmpBytesEnc)

		ok := userlib.HMACEqual(signaCal, tmpBytesHMAC)
		if !ok {
			return nil, err
		}

		tmpBytesDec := userlib.SymDec(fileSymKey, tmpBytesEnc)
		err = json.Unmarshal(tmpBytesDec, &tmp)
		userlib.DebugMsg("Tmp: %s", tmp)

		content = append(content, tmp...)
	}

	return content, err

}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (invitationPtr uuid.UUID, err error) {
	invitationPtr = uuid.New()
	/*
	* 1. read userFileMap & userFileMapEntry
	* 2. read fileMeta
	* 3. Read shareRecord, and Modify ShareRecord
	* 4. Generate invitation info
	* 5. Store invitation
	* 6. Store ShareRecord
	* ***** don't need to iterate fileMeta node chain
	 */
	// ================================================================

	// init userFileMap & userFileMap Entry & FileMeta
	var userFileMapEntry UserFileMapEntry
	userFileMap := make(map[string]UserFileMapEntry)
	var userFileMapBytes, userFileMapBytesEnc, userFileMapBytesHMAC []byte

	var fileMeta FileMeta
	var fileMetaBytes, fileMetaBytesEnc, fileMetaBytesHMAC []byte

	var iv []byte

	// 1. read userFileMap & userFileMapEntry
	// ================================================================

	// calculate deterministic UserFileMap encryption key
	symKey, err := userlib.HashKDF(userdata.SourceKey, []byte("UserFileMap-SymEnc"))
	symKey = symKey[:16]

	hMACKey, err := userlib.HashKDF(userdata.SourceKey, []byte("UserFileMap-HMAC"))
	hMACKey = hMACKey[:16]

	// get deterministic UserFileMap UUID and read userFileMapBytes
	userFileMapUUID, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + "UserFileMap"))[:16])
	userFileMapBytes, ok := userlib.DatastoreGet(userFileMapUUID)

	if !ok {
		return invitationPtr, errors.New(strings.ToTitle("CreateInvitation: UserFileMpap Not Found"))
	}

	userFileMapBytesEnc = userFileMapBytes[:len(userFileMapBytes)-64]
	userFileMapBytesHMAC = userFileMapBytes[len(userFileMapBytes)-64:]

	hMAC, _ := userlib.HMACEval(hMACKey, userFileMapBytesEnc)
	ok = userlib.HMACEqual(hMAC, userFileMapBytesHMAC)

	if !ok {
		return invitationPtr, errors.New(strings.ToTitle("CreateInvitation HMAC Verify Failure"))
	}

	// unmarshaljib bytes to userFileMap
	userFileMapBytes = userlib.SymDec(symKey, userFileMapBytesEnc)
	err = json.Unmarshal(userFileMapBytes, &userFileMap)
	if err != nil {
		return invitationPtr, errors.New(strings.ToTitle("CreateInvitation: UserFileMap Unmarshal Failure"))
	}

	userFileMapEntry, ok = userFileMap[filename]

	if !ok {
		return invitationPtr, errors.New(strings.ToTitle("CreateInvitation: UserFileMapEntry Load Failure"))
	}

	userlib.DebugMsg("CreateInvitation read userFileMap & userFileMapEntry Finish")

	// 2. read fileMeta
	// ================================================================
	fileMetaUUID := userFileMapEntry.FileMetaUUID
	fileMetaSymKey := userFileMapEntry.SymEncKey
	fileMetaHMACKey := userFileMapEntry.HMACKey

	fileMetaBytes, ok = userlib.DatastoreGet(fileMetaUUID)
	if !ok {
		return invitationPtr, errors.New(strings.ToTitle("CreateInvitation: FileMeta Node Not Found"))
	}

	fileMetaBytesEnc = fileMetaBytes[:len(fileMetaBytes)-64]
	fileMetaBytesHMAC = fileMetaBytes[len(fileMetaBytes)-64:]
	hMAC, _ = userlib.HMACEval(fileMetaHMACKey, fileMetaBytesEnc)
	ok = userlib.HMACEqual(hMAC, fileMetaBytesHMAC)
	if !ok {
		return invitationPtr, errors.New(strings.ToTitle("CreateInvitation: FileMeta Node HMAC Verify Failure"))
	}
	fileMetaBytes = userlib.SymDec(fileMetaSymKey, fileMetaBytesEnc)
	err = json.Unmarshal(fileMetaBytes, &fileMeta)
	if err != nil {
		return invitationPtr, errors.New(strings.ToTitle("CreateInvitation: fileMeta Unmarshal Failure"))
	}

	// userlib.DebugMsg("CreateInvitation: fileMeta %v", fileMeta)
	userlib.DebugMsg("CreateInvitation: read fileMeta Finish")

	// 3. Read shareRecord, and Modify ShareRecord
	// ================================================================

	// shareMap record the status of user that has been shared the file with
	// shareMap {username : [uuid, shareFileMetaSymKey,shareFileMetaHMACKey]}
	// uuid is the inviation node
	// and also their metafile node about the file
	var shareRecords [][]byte

	shareMap := make(map[string][][]byte)
	shareMapSymKey, _ := userlib.HashKDF(userdata.SourceKey, []byte("ShareMap-SymEncKey"))
	shareMapSymKey = shareMapSymKey[:16]
	shareMapHMACKey, _ := userlib.HashKDF(userdata.SourceKey, []byte("ShareMap-HMACKey"))
	shareMapHMACKey = shareMapHMACKey[:16]

	// fileMeta always has a ShareList even if it does not share the file
	// if the file is not shared, not data is stored in the corresponding uuid
	// check ok var returned by datastoreGet

	shareMapBytes, ok := userlib.DatastoreGet(fileMeta.ShareList)
	if ok {
		// the file has been shared with others in the past
		shareMapBytesEnc := shareMapBytes[:len(shareMapBytes)-64]
		shareMapBytesHMAC := shareMapBytes[len(shareMapBytes)-64:]

		hMac, _ := userlib.HMACEval(shareMapHMACKey, shareMapBytesEnc)
		ok = userlib.HMACEqual(hMac, shareMapBytesHMAC)
		if !ok {
			return invitationPtr, errors.New(strings.ToTitle("CreateInvitation: ShareMap HMAC Verify Failure"))
		}

		shareMapBytes = userlib.SymDec(shareMapSymKey, shareMapBytesEnc)
		err = json.Unmarshal(shareMapBytes, &shareMap)
		if err != nil {
			return invitationPtr, errors.New(strings.ToTitle("CreateInvitation: ShareMap Unmarshal Failure"))
		}
	}
	shareFileMetaUUIDBytes, _ := invitationPtr.MarshalBinary()
	shareRecords = append(shareRecords, shareFileMetaUUIDBytes)
	shareRecords = append(shareRecords, fileMetaSymKey)
	shareRecords = append(shareRecords, fileMetaHMACKey)

	shareMap[recipientUsername] = shareRecords

	userlib.DebugMsg("CreateInvitation: Read shareRecord, and Modify ShareRecord Finish")
	// 4. Generate invitation info
	// ================================================================

	// create Invitation
	// [UUID, SymKey, HMACKey], all elements in the form of []byte
	var invitation [][]byte
	fileMetaUUIDBytes, _ := fileMetaUUID.MarshalBinary()
	invitation = append(invitation, fileMetaUUIDBytes)
	userlib.DebugMsg("CreateInvitation: Invitation: %s", invitation)

	invitation = append(invitation, fileMetaSymKey)
	userlib.DebugMsg("CreateInvitation: Invitation: %s", invitation)

	invitation = append(invitation, fileMetaHMACKey)
	userlib.DebugMsg("CreateInvitation: Invitation: %s", invitation)

	// 5. Store invitation
	// ================================================================

	// encrypt and sign the invitation
	// use receiverPublicKey to encrypt, use senderPrivateKey to sign
	receiverPublicKey, ok := userlib.KeystoreGet(recipientUsername + "_PKE")
	senderPrivateKey := userdata.DSSignKey

	if !ok {
		return invitationPtr, errors.New(strings.ToTitle("CreateInvitation: Receiver PublicKey Not Found"))
	}

	// store invitation in datastore
	invitationBytes, err := json.Marshal(invitation)
	invitationBytesEnc, err := userlib.PKEEnc(receiverPublicKey, invitationBytes)
	invitationDSign, err := userlib.DSSign(senderPrivateKey, invitationBytesEnc)
	userlib.DatastoreSet(invitationPtr, append(invitationBytesEnc, invitationDSign...))

	userlib.DebugMsg("CreateInvitation: Store invitation Finsih")

	// 6. Store ShareRecord
	// ================================================================

	// store shareMap back to datastore
	shareMapBytes, err = json.Marshal(shareMap)
	iv = userlib.RandomBytes(16)
	shareMapBytesEnc := userlib.SymEnc(shareMapSymKey, iv, shareMapBytes)
	shareMapBytesHMAC, _ := userlib.HMACEval(shareMapHMACKey, shareMapBytesEnc)
	userlib.DatastoreSet(fileMeta.ShareList, append(shareMapBytesEnc, shareMapBytesHMAC...))
	userlib.DebugMsg("CreateInvitation: Store ShareRecord Finsih")

	return invitationPtr, err
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	/*
	* 1. Read Invitation and Extract Info
	* 2. Read userFileMap
	* 3. Add one userFileMapEntry
	* 4. Generate corresponding fileMeta node (share node)
	* 5. store userFileMap back to datastore
	* 6. Store the fileMeta in where invitationPtr point to
	* --------------------------------------------------
	* fileMeta is encrypted and hmac with given keys
	* symkey and hmac key in fileMeta are the same key as what above has mentioned
	 */

	// 1. Read Invitation
	// -----------------------------------------------------
	invitationBytes, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		return errors.New(strings.ToTitle("AcceptInvitation: Invitation Read Failure"))
	}
	invitationBytesEnc := invitationBytes[:len(invitationBytes)-256]
	invitationBytesDSign := invitationBytes[len(invitationBytes)-256:]

	senderPublicKey, ok := userlib.KeystoreGet(senderUsername + "_DS")
	if !ok {
		return errors.New(strings.ToTitle("AcceptInvitation: Sender Publick Key Read Failure"))
	}

	err := userlib.DSVerify(senderPublicKey, invitationBytesEnc, invitationBytesDSign)
	if err != nil {
		return errors.New(strings.ToTitle("AcceptInvitation: Invitation DSign Verify Failure"))
	}

	invitationBytes, err = userlib.PKEDec(userdata.PKEDecKey, invitationBytesEnc)
	if err != nil {
		return errors.New(strings.ToTitle("AcceptInvitation: Invitation PKEDec Verify Failure"))
	}

	// invitation[0]: uuid in the bytes form
	// invitaition[1] & [2]: SymKey & HMACKey
	var invitationList [][]byte

	err = json.Unmarshal(invitationBytes, &invitationList)

	if err != nil {

		return errors.New(strings.ToTitle("AcceptInvitation: Invitation Unmarshal Failure"))
	}

	shareUUID, err := uuid.FromBytes(invitationList[0])
	if err != nil {
		return errors.New(strings.ToTitle("AcceptInvitation: Reform UUID Failure"))

	}

	userlib.DebugMsg("AcceptInvitation: 1. Read Invitation and Extract Info Finish")

	// init userFileMap & userFileMap Entry & FileMeta
	var userFileMapEntry UserFileMapEntry
	userFileMap := make(map[string]UserFileMapEntry)
	var userFileMapBytes, userFileMapBytesEnc, userFileMapBytesHMAC []byte

	var fileMeta FileMeta
	var fileMetaBytes, fileMetaBytesEnc, fileMetaBytesHMAC []byte

	var iv []byte

	// 2. read userFileMap
	// -----------------------------------------------------

	// calculate deterministic UserFileMap encryption key
	symKey, _ := userlib.HashKDF(userdata.SourceKey, []byte("UserFileMap-SymEnc"))
	symKey = symKey[:16]

	hMACKey, _ := userlib.HashKDF(userdata.SourceKey, []byte("UserFileMap-HMAC"))
	hMACKey = hMACKey[:16]

	// get deterministic UserFileMap UUID and read userFileMapBytes
	userFileMapUUID, _ := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + "UserFileMap"))[:16])
	userFileMapBytes, ok = userlib.DatastoreGet(userFileMapUUID)

	// ++++++++++++++++++++++++++++++++++++++++++

	// UserFileMap exist, get userFileMap from datastore
	if ok {
		// auth and decrypt userFileMap
		userFileMapBytesEnc := userFileMapBytes[:len(userFileMapBytes)-64]
		userFileMapBytesHMAC := userFileMapBytes[len(userFileMapBytes)-64:]

		hMAC, _ := userlib.HMACEval(hMACKey, userFileMapBytesEnc)
		ok = userlib.HMACEqual(hMAC, userFileMapBytesHMAC)

		if !ok {
			return errors.New(strings.ToTitle("AcceptInvitation: UserFileMpap HMAC Verify Failure"))
		}

		// unmarshal bytes to userFileMap
		userFileMapBytes := userlib.SymDec(symKey, userFileMapBytesEnc)
		err = json.Unmarshal(userFileMapBytes, &userFileMap)
		if err != nil {
			return errors.New(strings.ToTitle("AcceptInvitation: UserFileMap Unmarshal Failure"))
		}

	} else {
		// userFileMap does not exist, do nothing

	}

	userlib.DebugMsg("AcceptInvitation: 2. Read userFileMap Finish")

	// 3. Add one userFileMapEntry
	// -----------------------------------------------------
	userFileMapEntry.FileMetaUUID = invitationPtr
	userFileMapEntry.SymEncKey = invitationList[1]
	userFileMapEntry.HMACKey = invitationList[2]
	userFileMap[filename] = userFileMapEntry

	userlib.DebugMsg("AcceptInvitation: 3. Add one userFileMapEntry Finish")

	// 4. Generate corresponding fileMeta node (share node)
	// -----------------------------------------------------
	fileMeta.Status = "Share"
	fileMeta.Filename = filename
	fileMeta.ShareList = uuid.New()
	fileMeta.FileUuidList = append(fileMeta.FileUuidList, shareUUID)
	fileMeta.SymEncKey = invitationList[1]
	fileMeta.HMACKey = invitationList[2]

	userlib.DebugMsg("AcceptInvitation: 4. Generate corresponding fileMeta node (share node) Finish")

	// 5. store userFileMap back to datastore
	// -----------------------------------------------------
	userFileMapBytes, _ = json.Marshal(userFileMap)
	iv = userlib.RandomBytes(16)
	userFileMapBytesEnc = userlib.SymEnc(symKey, iv, userFileMapBytes)
	userFileMapBytesHMAC, _ = userlib.HMACEval(hMACKey, userFileMapBytesEnc)
	userlib.DatastoreSet(userFileMapUUID, append(userFileMapBytesEnc, userFileMapBytesHMAC...))

	userlib.DebugMsg("AcceptInvitation: 5. store userFileMap back to datastore Finish")

	// 6. Store the fileMeta in where invitationPtr point to
	// -----------------------------------------------------
	fileMetaBytes, _ = json.Marshal(fileMeta)
	iv = userlib.RandomBytes(16)
	fileMetaBytesEnc = userlib.SymEnc(userFileMapEntry.SymEncKey, iv, fileMetaBytes)
	fileMetaBytesHMAC, _ = userlib.HMACEval(userFileMapEntry.HMACKey, fileMetaBytesEnc)
	userlib.DatastoreSet(userFileMap[filename].FileMetaUUID, append(fileMetaBytesEnc, fileMetaBytesHMAC...))

	userlib.DebugMsg("AcceptInvitation: 6. Store the fileMeta in where invitationPtr point to Finish")

	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	/*
		* 1. Read userFileMap & corresponding userFileMapEntry
		* 2. Read fileMeta (delete original)
		* 3. Read shareMap
		* 4. Read fileContent (delete original)
		* 5. Generate a pair of symKey & hMACKey & UUID for fileMeta -> modify userFileMapEntry key part
			 Generate a pair of symKey & hMACKey & UUID for fileContent -> modify fileMeta key part
		* 6. For revoked user, delete key-value pair in datastore, pointed by shareMap[recipientUsername]
		     For rest of shared users, access shareMap[username] to change symKey & hMACKey
		* 7. store userFileMap
		* 8. store fileMeta with another symKey & hMACKey
		* 9. store shareMap with same key
		* 10. store fileContnet with another symKey & hMACKey
	*/
	// ==============================================================================================================
	// ==============================================================================================================
	// ==============================================================================================================

	// init userFileMap & userFileMap Entry & FileMeta
	var userFileMapEntry UserFileMapEntry
	userFileMap := make(map[string]UserFileMapEntry)
	var userFileMapBytes, userFileMapBytesEnc, userFileMapBytesHMAC []byte

	var fileMeta FileMeta
	var fileMetaBytes, fileMetaBytesEnc, fileMetaBytesHMAC []byte

	var iv []byte

	// 1. Read userFileMap & corresponding userFileMapEntry
	// -----------------------------------------------------------------------------------
	// calculate deterministic UserFileMap encryption key
	symKey, _ := userlib.HashKDF(userdata.SourceKey, []byte("UserFileMap-SymEnc"))
	symKey = symKey[:16]

	hMACKey, _ := userlib.HashKDF(userdata.SourceKey, []byte("UserFileMap-HMAC"))
	hMACKey = hMACKey[:16]

	// get deterministic UserFileMap UUID and read userFileMapBytes
	userFileMapUUID, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + "UserFileMap"))[:16])
	userFileMapBytes, ok := userlib.DatastoreGet(userFileMapUUID)

	if !ok {
		return errors.New(strings.ToTitle("RevokeAccess: UserFileMap Not Found"))
	}

	userFileMapBytesEnc = userFileMapBytes[:len(userFileMapBytes)-64]
	userFileMapBytesHMAC = userFileMapBytes[len(userFileMapBytes)-64:]

	hMAC, _ := userlib.HMACEval(hMACKey, userFileMapBytesEnc)
	ok = userlib.HMACEqual(hMAC, userFileMapBytesHMAC)

	if !ok {
		return errors.New(strings.ToTitle("RevokeAccess UserFileMap HMAC Verify Failure"))
	}

	// unmarshaljib bytes to userFileMap
	userFileMapBytes = userlib.SymDec(symKey, userFileMapBytesEnc)
	err = json.Unmarshal(userFileMapBytes, &userFileMap)
	if err != nil {
		return errors.New(strings.ToTitle("RevokeAccess: UserFileMap Unmarshal Failure"))
	}

	userFileMapEntry, ok = userFileMap[filename]
	if !ok {
		return errors.New(strings.ToTitle("RevokeAccess: UserFileMapEntry Load Failure"))
	}

	userlib.DebugMsg("1. RevokeAccess read userFileMap & userFileMapEntry Finish")

	// 2. Read fileMeta
	// -----------------------------------------------------------------------------------
	fileMetaUUID := userFileMapEntry.FileMetaUUID
	fileMetaSymKey := userFileMapEntry.SymEncKey
	fileMetaHMACKey := userFileMapEntry.HMACKey

	fileMetaBytes, ok = userlib.DatastoreGet(fileMetaUUID)
	if !ok {
		return errors.New(strings.ToTitle("RevokeAccess: FileMeta Node Not Found"))
	}

	fileMetaBytesEnc = fileMetaBytes[:len(fileMetaBytes)-64]
	fileMetaBytesHMAC = fileMetaBytes[len(fileMetaBytes)-64:]
	hMAC, _ = userlib.HMACEval(fileMetaHMACKey, fileMetaBytesEnc)
	ok = userlib.HMACEqual(hMAC, fileMetaBytesHMAC)
	if !ok {
		return errors.New(strings.ToTitle("RevokeAccess: FileMeta Node HMAC Verify Failure"))
	}
	fileMetaBytes = userlib.SymDec(fileMetaSymKey, fileMetaBytesEnc)
	err = json.Unmarshal(fileMetaBytes, &fileMeta)
	if err != nil {
		return errors.New(strings.ToTitle("RevokeAccess: fileMeta Unmarshal Failure"))
	}
	userlib.DatastoreDelete(fileMetaUUID)

	userlib.DebugMsg("2. RevokeAccess: read fileMeta Finish")

	// 3. Read shareMap
	// -----------------------------------------------------------------------------------
	shareMap := make(map[string][][]byte)
	shareMapSymKey, _ := userlib.HashKDF(userdata.SourceKey, []byte("ShareMap-SymEncKey"))
	shareMapSymKey = shareMapSymKey[:16]
	shareMapHMACKey, _ := userlib.HashKDF(userdata.SourceKey, []byte("ShareMap-HMACKey"))
	shareMapHMACKey = shareMapHMACKey[:16]

	shareMapBytes, ok := userlib.DatastoreGet(fileMeta.ShareList)
	if !ok {
		return errors.New(strings.ToTitle("RevokeAccess: ShareMap Not Found"))
	}

	shareMapBytesEnc := shareMapBytes[:len(shareMapBytes)-64]
	shareMapBytesHMAC := shareMapBytes[len(shareMapBytes)-64:]

	hMac, _ := userlib.HMACEval(shareMapHMACKey, shareMapBytesEnc)
	ok = userlib.HMACEqual(hMac, shareMapBytesHMAC)
	if !ok {
		return errors.New(strings.ToTitle("RevokeAccess: ShareMap HMAC Verify Failure"))
	}

	shareMapBytes = userlib.SymDec(shareMapSymKey, shareMapBytesEnc)
	err = json.Unmarshal(shareMapBytes, &shareMap)
	if err != nil {
		return errors.New(strings.ToTitle("RevokeAccess: ShareMap Unmarshal Failure"))
	}
	userlib.DebugMsg("3. Read shareMap Finish")

	// 4. Read fileContent
	// -----------------------------------------------------------------------------------
	// iterate file uuid to read the content
	// clear corresponding key-pair in datastore

	fileSymKey := fileMeta.SymEncKey
	fileHMACKey := fileMeta.HMACKey
	var fileContent []byte
	for _, uuid := range fileMeta.FileUuidList {
		var tmp []byte
		tmpBytes, _ := userlib.DatastoreGet(uuid)
		tmpBytesEnc := tmpBytes[:len(tmpBytes)-64]
		tmpBytesHMAC := tmpBytes[len(tmpBytes)-64:]
		signaCal, _ := userlib.HMACEval(fileHMACKey, tmpBytesEnc)

		ok := userlib.HMACEqual(signaCal, tmpBytesHMAC)
		if !ok {
			return errors.New(strings.ToTitle("RevokeAccess: fileContent HMAC Verify Failure"))
		}

		tmpBytesDec := userlib.SymDec(fileSymKey, tmpBytesEnc)
		err = json.Unmarshal(tmpBytesDec, &tmp)
		if err != nil {
			return errors.New(strings.ToTitle("RevokeAccess: fileContent Unmarshal Failure"))
		}
		fileContent = append(fileContent, tmp...)
		userlib.DatastoreDelete(uuid)
	}
	userlib.DebugMsg("4. Read fileContent Finish: %s", fileContent)

	// 5. Generate New Key-pair & UUID
	// -----------------------------------------------------------------------------------

	// Generate a pair of symKey & hMACKey for fileMeta -> modify userFileMapEntry key part
	fileMetaUUID = uuid.New()
	fileMetaSymKey = userlib.RandomBytes(16)
	fileMetaHMACKey = userlib.RandomBytes(16)

	userFileMapEntry.FileMetaUUID = fileMetaUUID
	userFileMapEntry.SymEncKey = fileMetaSymKey
	userFileMapEntry.HMACKey = fileMetaHMACKey

	userFileMap[filename] = userFileMapEntry

	//  Generate a pair of symKey & hMACKey for fileContent -> modify fileMeta key part
	fileUuiD := uuid.New()
	fileSymKey = userlib.RandomBytes(16)
	fileHMACKey = userlib.RandomBytes(16)

	fileMeta.FileUuidList = nil
	fileMeta.FileUuidList = append(fileMeta.FileUuidList, fileUuiD)
	fileMeta.SymEncKey = userlib.RandomBytes(16)
	fileMeta.HMACKey = userlib.RandomBytes(16)

	userlib.DebugMsg("5. Generate New Key-pair & UUID Finish")

	// 6. Revoke Access and change other users' key
	// -----------------------------------------------------------------------------------
	// For revoked user, delete key-value pair in datastore, pointed by shareMap[recipientUsername]
	// For rest of shared users, access shareMap[username] to change symKey & hMACKey
	var shareFileMeta FileMeta
	var shareFileMetaBytes, shareFileMetaBytesEnc, shareFileMetaBytesHMAC []byte
	var shareFileMetaUUID uuid.UUID
	for user, shareRecord := range shareMap {
		// for revoked user
		// delete key-value pair pointed by revokedUUID
		shareFileMetaUUID, err = uuid.FromBytes(shareRecord[0])
		if user == recipientUsername {
			userlib.DatastoreDelete(shareFileMetaUUID)
			_, ok = userlib.DatastoreGet(shareFileMetaUUID)
			if ok {
				panic("StoreFile: the data should have been deleted")
			}
		} else {
			// for other user
			// change symKey & hMACKey in their share fileMeta node
			shareFileMetaBytes, ok = userlib.DatastoreGet(shareFileMetaUUID)
			if !ok {
				return errors.New(strings.ToTitle("RevokeAccess: Revoked User FileMeta Not Found"))
			}
			shareFileMetaBytesEnc = shareFileMetaBytes[:len(shareFileMetaBytes)-64]
			shareFileMetaBytesHMAC = shareFileMetaBytes[len(shareFileMetaBytes)-64:]
			hMAC, _ := userlib.HMACEval(shareRecord[2], shareFileMetaBytesEnc)
			ok = userlib.HMACEqual(hMAC, shareFileMetaBytesHMAC)
			if !ok {
				return errors.New(strings.ToTitle("RevokeAccess: Revoked User FileMeta HMAC Verify Failure"))
			}
			shareFileMetaBytes = userlib.SymDec(shareRecord[1], shareFileMetaBytesEnc)
			err = json.Unmarshal(shareFileMetaBytes, &shareFileMeta)
			if err != nil {
				return errors.New(strings.ToTitle("RevokeAccess: Revoked User FileMeta Unmarshal Failure"))
			}

			shareFileMeta.SymEncKey = fileMetaSymKey
			shareFileMeta.HMACKey = fileMetaHMACKey
			shareFileMeta.FileUuidList = append(shareFileMeta.FileUuidList, fileMetaUUID)

			// store back
			shareFileMetaBytes, err = json.Marshal(shareFileMeta)
			if err != nil {
				return errors.New(strings.ToTitle("RevokeAccess: Share FileMeta Marshal Failure"))
			}
			iv = userlib.RandomBytes(16)
			shareFileMetaBytesEnc = userlib.SymEnc(shareRecord[1], iv, shareFileMetaBytes)
			shareFileMetaBytesHMAC, _ = userlib.HMACEval(shareRecord[2], shareFileMetaBytesEnc)
			userlib.DatastoreSet(shareFileMetaUUID, append(shareFileMetaBytesEnc, shareFileMetaBytesHMAC...))
		}
	}
	delete(shareMap, recipientUsername)
	userlib.DebugMsg("6. Revoke Access and change other users' key")

	// 7. store userFileMap
	// -----------------------------------------------------------------------------------
	userFileMapBytes, _ = json.Marshal(userFileMap)
	iv = userlib.RandomBytes(16)
	userFileMapBytesEnc = userlib.SymEnc(symKey, iv, userFileMapBytes)
	userFileMapBytesHMAC, _ = userlib.HMACEval(hMACKey, userFileMapBytesEnc)
	userlib.DatastoreSet(userFileMapUUID, append(userFileMapBytesEnc, userFileMapBytesHMAC...))
	userlib.DebugMsg("7. store userFileMap")

	// 8. store fileMeta with another symKey & hMACKey
	// -----------------------------------------------------------------------------------
	fileMetaBytes, _ = json.Marshal(fileMeta)
	iv = userlib.RandomBytes(16)
	fileMetaBytesEnc = userlib.SymEnc(userFileMapEntry.SymEncKey, iv, fileMetaBytes)
	fileMetaBytesHMAC, _ = userlib.HMACEval(userFileMapEntry.HMACKey, fileMetaBytesEnc)
	userlib.DatastoreSet(userFileMap[filename].FileMetaUUID, append(fileMetaBytesEnc, fileMetaBytesHMAC...))
	userlib.DebugMsg("8. store fileMeta with another symKey & hMACKey")

	// 9. store shareMap with same key
	// -----------------------------------------------------------------------------------
	shareMapBytes, err = json.Marshal(shareMap)
	iv = userlib.RandomBytes(16)
	shareMapBytesEnc = userlib.SymEnc(shareMapSymKey, iv, shareMapBytes)
	shareMapBytesHMAC, _ = userlib.HMACEval(shareMapHMACKey, shareMapBytesEnc)
	userlib.DatastoreSet(fileMeta.ShareList, append(shareMapBytesEnc, shareMapBytesHMAC...))
	userlib.DebugMsg("9. store shareMap with same key")

	// 10. store fileContnet with another symKey & hMACKey
	// -----------------------------------------------------------------------------------
	contentBytes, _ := json.Marshal(fileContent)
	iv = userlib.RandomBytes(16)
	contentBytesEnc := userlib.SymEnc(fileMeta.SymEncKey, iv, contentBytes)
	contentBytesHMAC, _ := userlib.HMACEval(fileMeta.HMACKey, contentBytesEnc)
	userlib.DatastoreSet(fileMeta.FileUuidList[0], append(contentBytesEnc, contentBytesHMAC...))
	userlib.DebugMsg(" 10. store fileContnet with another symKey & hMACKey")

	return nil
}

func Equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}
