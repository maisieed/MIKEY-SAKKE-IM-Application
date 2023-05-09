package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/coreos/mantle/network/ntp"
)

// EncryptedMessage is the structure of an encrypted message.
type EncryptedMessage struct {
	InitiatorURI string        // The URI of the initiator.
	Timestamp    ntp.Timestamp // NTP timestamp.
	Message      []byte        // The message encrypted with AES.
	Signature    []byte        // The signature of the message.
}

// sendEncryptedMessage encrypts the given message using the established key from the session with the Responder.
func (user *User) sendEncryptedMessage(message string, responderURI string) (err error) {

	// Check session exists with other user.
	key, ok := user.EstablishedKeys[responderURI]
	if !ok {
		err = fmt.Errorf("failed to find session with responder: %s", responderURI)
		return
	}
	// Create new instance of 'EncryptedMessage'.
	encryptedMessage := EncryptedMessage{InitiatorURI: user.URI}

	// Encrypt message using AES.
	encryptedMessage.Message, err = encryptMessage([]byte(message), key)
	if err != nil {
		return
	}
	// Add timestamp.
	encryptedMessage.Timestamp = ntp.Now()

	// Marshal 'EncryptedMessage' without signature.
	encodedMessage, err := json.Marshal(encryptedMessage)
	if err != nil {
		err = fmt.Errorf("failed to marshal encrypted message: %s", err.Error())
		return
	}
	// Sign 'EncryptedMessage' using ECCSI.
	encryptedMessage.Signature, err = user.Eccsi.signMessage(encodedMessage)
	if err != nil {
		return
	}
	// Marshal 'EncryptedMessage' with signature.
	encodedMessage, err = json.Marshal(encryptedMessage)
	if err != nil {
		err = fmt.Errorf("failed to marshal encrypted message: %s", err.Error())
		return
	}
	// Send message to responder.
	_, err = user.tcpClient(0x1, encodedMessage, CommunityUsers[responderURI])
	if err != nil {
		return
	}
	// Add to list of received messages.
	savedMessage := Message{Time: time.Now(), IsReceived: false, Content: message}
	user.Messages[responderURI] = append(user.Messages[responderURI], savedMessage)

	// Send signal to update GUI.
	user.UpdateWindow <- true
	return
}

// handleEncryptedMessage decrypts the given message using the established key from the session with the Initiator.
func (user *User) handleEncryptedMessage(encodedMessage []byte) (err error) {

	// Create new instance of 'EncryptedMessage'.
	var encryptedMessage EncryptedMessage

	// Unmarshal message into 'EncryptedMessage' struct.
	err = json.Unmarshal(encodedMessage, &encryptedMessage)
	if err != nil {
		err = fmt.Errorf("failed to unmarshal encrypted message: %s", err.Error())
		return
	}
	// Check timestamp is valid.
	if !validateNTPTimestamp(encryptedMessage.Timestamp, user.ReplayCache.clockSkew) {
		err = fmt.Errorf("invalid timestamp")
		return
	}
	// Check message has not already been authenticated within last tick.
	if user.ReplayCache.isInReplayCache(encodedMessage) {
		err = fmt.Errorf("message already received")
		return
	}
	// Check session exists with other user.
	key, ok := user.EstablishedKeys[encryptedMessage.InitiatorURI]
	if !ok {
		err = fmt.Errorf("failed to find session with initiator: %s", encryptedMessage.InitiatorURI)
		return
	}
	// Use the Initiator URI to create the Initiator's ID.
	initiatorID, err := generateIDInteger(encryptedMessage.InitiatorURI)
	if err != nil {
		return
	}
	// Remove signature from encrypted message.
	messageWOutSign := encryptedMessage
	messageWOutSign.Signature = nil

	// Marshal message without signature.
	messageToVerify, err := json.Marshal(messageWOutSign)
	if err != nil {
		err = fmt.Errorf("failed to marshal unsigned message: %s", err.Error())
		return
	}
	// Verify message without signature.
	err = user.Eccsi.verifySignature(encryptedMessage.Signature, initiatorID, string(messageToVerify))
	if err != nil {
		err = fmt.Errorf("invalid signature")
		return
	}
	// Decrypt message using AES.
	message, err := decryptMessage(encryptedMessage.Message, key)
	if err != nil {
		return
	}
	// Add message to list of successfully authenticated messages received since last tick.
	user.ReplayCache.addToReplayCache(encodedMessage)

	// Add to list of received messages.
	savedMessage := Message{Time: time.Now(), IsReceived: true, Content: string(message)}
	user.Messages[encryptedMessage.InitiatorURI] = append(user.Messages[encryptedMessage.InitiatorURI], savedMessage)

	// Send signal to update GUI.
	user.UpdateWindow <- true

	return
}

// encryptMessage encrypts the given message using AES with the given key and a random nonce.
// Returns the encrypted message.
func encryptMessage(message []byte, key []byte) (encryptedMessage []byte, err error) {

	// Create new AES cipher using given key.
	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		err = fmt.Errorf("failed to create AES cipher: %s", err.Error())
		return
	}
	// Create cipher with nonce.
	gcmCipher, err := cipher.NewGCM(aesCipher)
	if err != nil {
		err = fmt.Errorf("failed to create cipher with nonce: %s", err.Error())
		return
	}
	// Create nonce with random values.
	nonce := make([]byte, gcmCipher.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		err = fmt.Errorf("failed to create random nonce: %s", err.Error())
		return
	}
	// Encrypt message.
	encryptedMessage = gcmCipher.Seal(nonce, nonce, message, nil)

	return
}

// decryptMessage decrypts the given message using AES with the given key and a random nonce.
// Returns the decrypted message.
func decryptMessage(encryptedMessage []byte, key []byte) (message []byte, err error) {

	// Create new AES cipher using given key.
	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		err = fmt.Errorf("failed to create AES cipher: %s", err.Error())
		return
	}
	// Create cipher with nonce.
	gcmCipher, err := cipher.NewGCM(aesCipher)
	if err != nil {
		err = fmt.Errorf("failed to create cipher with nonce: %s", err.Error())
		return
	}
	// Check length of encrypted message is not less than expected nonce.
	if len(encryptedMessage) < gcmCipher.NonceSize() {
		err = fmt.Errorf("invalid encrypted message")
		return
	}
	// Find nonce and cipher text.
	nonce := encryptedMessage[:gcmCipher.NonceSize()]
	cipherText := encryptedMessage[gcmCipher.NonceSize():]

	// Decrypt message.
	message, err = gcmCipher.Open(nil, nonce, cipherText, nil)
	if err != nil {
		err = fmt.Errorf("failed to decrypt encrypted message: %s", err.Error())
	}
	return
}
