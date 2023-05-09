package main

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"github.com/coreos/mantle/network/ntp"
)

// I_Message contains the components of the MIKEY-SAKKE message needed to establish the shared key.
type I_Message struct {
	HDR   HDRPayload   // The MIKEY Common Header Payload.
	T     TPayload     // The Timestamp Payload.
	RAND  RANDPayload  // The RAND Payload.
	IDRi  IDRPayload   // ID role of Initiator.
	IDRr  IDRPayload   // ID role of the Responder.
	SAKKE SAKKEPayload // The SAKKE payload.
	SIGN  SIGNPayload  // The Signature Payload.
}

// HDRPayload contains the components for the Common Header Payload (HDR).
type HDRPayload struct {
	Version      byte   // The version number of MIKEY (8 bits).
	DataType     byte   // Describes the type of message (8 bits).
	NextPayload  byte   // Next payload (8 bits).
	V            byte   // Flag to indicate whether a verification message is expected or not (1 bit).
	PRFFunc      byte   // The PRF function that will used for key derivation (7 bits).
	CSB_ID       []byte // Identifies the CSB (Crypto Session Bundle) (32 bits).
	CS           byte   // The number of Crypto Sessions that will be handled within the CBS (8 bits).
	CS_IDMapType byte   // Specifies the method of uniquely mapping crypto sessions to the security protocol sessions (8 bits).
	CS_IDMapInfo []byte // The crypto session for which the SA should be created (16 bits).
}

// TPayload contains the components for the Timestamp Payload (T).
type TPayload struct {
	NextPayload byte          // Next payload (8 bits).
	TSType      byte          // Specifies the timestamp type used (8 bits).
	TS_Value    ntp.Timestamp // The timestamp value of the specified TS type (64 bits)
}

// RANDPayload contains the components for the RAND Payload (RAND).
type RANDPayload struct {
	NextPayload byte   // Next payload (8 bits).
	RandLen     byte   // Length of the RAND in bytes (8 bits).
	Rand        []byte // A pseudo-random bit-string used to derive session key.
}

// SAKKEPayload contains the components for the SAKKE Payload (SAKKE).
type SAKKEPayload struct {
	NextPayload byte   // Next payload (8 bits).
	SAKKEParams byte   // The SAKKE parameter set to be used (8 bits).
	IDScheme    byte   // The SAKKE identifier scheme to be used (8 bits).
	SakkeLen    []byte // The length of SAKKE data in bytes (16 bits).
	SakkeData   []byte // The SAKKE encapsulated data.
}

// IDRPayload contains the components for the ID Payload with Role Indicator (IDR).
type IDRPayload struct {
	NextPayload byte   // Next payload (8 bits).
	IDRole      byte   // Describes the role of the identity (8 bits).
	IDType      byte   // Specifies the identifier type used (8 bits).
	IDLen       []byte // The length of the ID data in bytes (16 bits).
	IDData      []byte // The ID data.
}

// SIGNPayload contains the components for the Signature payload (SIGN).
type SIGNPayload struct {
	SType        byte   // The signature algorithm applied by the signer (4 bits).
	SignatureLen []byte // The length of signature field in bytes.
	Signature    []byte // The signature.
}

// sendMIKEYRequest creates a new MIKEY-SAKKE request to the specified Responder.
// It encapsulates a random SSV (shared secret value) which it then sends in an 'I_Message' to the responder.
// If successful, derives a new key from the SSV and adds this to a new 'Session'.
func (user *User) sendMIKEYRequest(responderURI string) (err error) {

	// Check user is a member of the community.
	if _, ok := CommunityUsers[responderURI]; !ok {
		err = fmt.Errorf("user %s is not a member of the community", responderURI)
		return
	}
	// Checks if session already exists with responder.
	if _, ok := user.EstablishedKeys[responderURI]; ok {
		err = fmt.Errorf("session already exists with user: %s", responderURI)
		return
	}
	// Compute responder ID using URI.
	responderID, err := generateIDInteger(responderURI)
	if err != nil {
		return
	}
	// Encapsulate new SSV using responder ID.
	ssv, encapsulatedData, err := user.Sakke.encapsulateData(responderID)
	if err != nil {
		return
	}
	// Make initial I_Message.
	message, err := user.createMIKEYMessage([]byte(responderURI), encapsulatedData)
	if err != nil {
		return
	}
	// Marshal message.
	encodedMessage, err := json.Marshal(message)
	if err != nil {
		err = fmt.Errorf("failed to marshal I_Message: %s", err.Error())
		return
	}
	// Send message to responder.
	_, err = user.tcpClient(0x0, encodedMessage, CommunityUsers[responderURI])
	if err != nil {
		return
	}
	// Create key using SSV.
	key, err := generateKey(ssv, message.HDR.CS, message.HDR.CSB_ID, message.RAND.Rand, 256)
	if err != nil {
		return
	}
	// Add key to new session.
	user.EstablishedKeys[responderURI] = key

	// Print key to command line for test purposes.
	fmt.Printf("Session established with: %s\n", responderURI)
	fmt.Printf("Key: %b\n", key)

	return
}

// handleMIKEYRequest handles a received MIKEY-SAKKE request from an Initiator.
// It parses the 'I_Message' and then decapsulates the SSV (shared secret value).
// If successful, derives a new key from the SSV and adds this to a new 'Session'.
func (user *User) handleMIKEYRequest(encodedMessage []byte) (err error) {

	// Create new instance of I_Message.
	var message I_Message

	// Unmarshal encoded message.
	err = json.Unmarshal(encodedMessage, &message)
	if err != nil {
		err = fmt.Errorf("unsupported message type: %s", err.Error())
		return
	}
	// Validate received I_Message.
	err = user.validateMIKEYMessage(message, encodedMessage)
	if err != nil {
		return
	}
	// Decapsulate SSV using responder ID.
	ssv, err := user.Sakke.decapsulateData(user.ID, message.SAKKE.SakkeData)
	if err != nil {
		return
	}
	// Create key using SSV.
	key, err := generateKey(ssv, message.HDR.CS, message.HDR.CSB_ID, message.RAND.Rand, 256)
	if err != nil {
		return
	}
	// Add new session.
	user.EstablishedKeys[string(message.IDRi.IDData)] = key

	// Print key to command line for test purposes.
	fmt.Printf("Session established with: %s\n", string(message.IDRi.IDData))
	fmt.Printf("Key: %b\n", key)

	// Send signal to update GUI.
	user.UpdateWindow <- true
	return
}

// validateMIKEYMessage verifies the given JSON encoded MIKEY I_MESSAGE.
// It does this by checking the timestamp and signature is valid.
// If valid, returns the SAKKE encapsulated data and the Initiator's ID.
func (user *User) validateMIKEYMessage(message I_Message, encodedMessage []byte) (err error) {

	// Extract the timestamp and check it is within the allowable clock skew.
	if !validateNTPTimestamp(message.T.TS_Value, user.ReplayCache.clockSkew) {
		err = fmt.Errorf("invalid timestamp")
		return
	}
	// Check message has not already been authenticated within last tick.
	if user.ReplayCache.isInReplayCache(encodedMessage) {
		err = fmt.Errorf("auth failure")
		return
	}
	// Check type of message is '0x1A', which describes the initiator's SAKKE message.
	if message.HDR.DataType != 0x1A {
		err = fmt.Errorf("unsupported message type")
		return
	}
	// Check signature type is '0x2', which describes an ECCSI signature.
	if message.SIGN.SType != 0x2 {
		err = fmt.Errorf("unsupported message type")
		return
	}
	// Use the Initiator URI to create the Initiator's ID.
	initiatorID, err := generateIDInteger(string(message.IDRi.IDData))
	if err != nil {
		return
	}
	// Remove Signature Payload from message.
	messageWOutSign := message
	messageWOutSign.SIGN = SIGNPayload{}

	// Marshal message without signature.
	messageToVerify, err := json.Marshal(messageWOutSign)
	if err != nil {
		err = fmt.Errorf("failed to marshal unsigned message: %s", err.Error())
		return
	}
	// Verify message without Signature Payload filled in.
	err = user.Eccsi.verifySignature(message.SIGN.Signature, initiatorID, string(messageToVerify))
	if err != nil {
		err = fmt.Errorf("auth failure")
		return
	}
	// Add message to list of successfully authenticated messages received since last tick.
	user.ReplayCache.addToReplayCache(encodedMessage)
	return
}

// createMIKEYMessage creates a I_MESSAGE containing SAKKE Encapsulated Data and an ECCSI signature.
// The I_Message is constructed as I_MESSAGE = HDR, T, RAND, [IDRi], [IDRr], [IDRkmsi], [IDRkmsr], SAKKE, SIGN.
// Returns the JSON encoded I_MESSAGE.
func (user *User) createMIKEYMessage(responderURI []byte, sakkeEncapsulatedData []byte) (message I_Message, err error) {

	// Set Common Header Payload (HDR).
	err = message.HDR.setHDR()
	if err != nil {
		return
	}
	// Set Timestamp Payload (T).
	message.T.setT()

	// Set RAND Payload (RAND).
	err = message.RAND.setRAND()
	if err != nil {
		return
	}
	// Set ID Payload with Role Indicator for Initiator (IDRi).
	message.IDRi.setIDR(0x1, []byte(user.URI))

	// Set ID Payload with Role Indicator for Responder (IDRr).
	message.IDRr.setIDR(0x2, responderURI)

	// Set SAKKE Payload (SAKKE).
	message.SAKKE.setSAKKE(sakkeEncapsulatedData)

	// Marshal message at this point without Signature Payload filled in.
	messageToSign, err := json.Marshal(message)
	if err != nil {
		return
	}
	// Sign JSON encoded message.
	eccsiSignature, err := user.Eccsi.signMessage(messageToSign)
	if err != nil {
		err = fmt.Errorf("failed to marshal unsigned message: %s", err.Error())
		return
	}
	// Add signature to Signature Payload (SIGN).
	message.SIGN.setSIGN(eccsiSignature)

	return
}

// setHDR initializes the Common Header Payload (HDR) for the MIKEY message.
func (hdrPayload *HDRPayload) setHDR() (err error) {

	// Set version to '0x01'; this describes MIKEY defined in RFC 3830.
	hdrPayload.Version = 0x01

	// Set data type to '0x1A'; this describes Initiator's SAKKE msg.
	hdrPayload.DataType = 0x1A

	// Set next payload to '0x5'; this describes the T (timestamp) payload.
	hdrPayload.NextPayload = 0x5

	// Set V to '0x00'; this describes that a response message is not expected.
	hdrPayload.V = 0x00

	// Set PRF Func to '0x00'; this describes that the default MIKEY key derivation will be used.
	hdrPayload.PRFFunc = 0x00

	// Set CSB ID; this is randomly chosen by the Initiator.
	hdrPayload.CSB_ID, err = generateCSB_ID()
	if err != nil {
		return
	}
	// Set CS to '0x00'; this describes that no CS is included as it is an initial setup message.
	hdrPayload.CS = 0x00

	return
}

// setT initializes the Timestamp Payload (T) for the MIKEY message.
func (tPayload *TPayload) setT() {

	// Set next payload to '0xB'; this describes the RAND payload.
	tPayload.NextPayload = 0xB

	// Set TS type to '0x00'; this describes NTP-UTC timestamp.
	tPayload.TSType = 0x00

	// Set TS Value to NTP-UTC timestamp of current time.
	// Uses an external Go library which uses RFC 5905.
	tPayload.TS_Value = ntp.Now()
}

// setRAND initializes the RAND Payload (RAND) for the MIKEY message.
func (randPayload *RANDPayload) setRAND() (err error) {

	// Set next payload to '0x6'; this describes the IDR payload.
	randPayload.NextPayload = 0x6

	// Set RAND len to '0x10'; this describes that the RAND will be 16 bytes.
	randPayload.RandLen = 0x10

	// Set RAND; a 128-bit bit-string randomly chosen by the Initiator.
	randPayload.Rand, err = generateRAND()

	return
}

// setIDRi initializes the ID Payload with Role Indicator (IDR) for the MIKEY message,
// using the given role and URI.
func (idrPayload *IDRPayload) setIDR(role byte, URI []byte) {

	// Set ID Role to given role.
	idrPayload.IDRole = role

	// Set ID Type to '0x2'; this describes a byte string.
	idrPayload.IDRole = 0x2

	// Set ID Len to the length of the URI.
	idrPayload.IDLen = make([]byte, 2)
	binary.BigEndian.PutUint16(idrPayload.IDLen, uint16(len(URI)))

	// Set ID Data as the URI.
	idrPayload.IDData = URI
}

// setSAKKE initializes the SAKKE Payload (SAKKE) for the MIKEY message
// using the given SAKKE encapsulated data.
func (sakkePayload *SAKKEPayload) setSAKKE(sakkeEncapsulatedData []byte) {

	// Set next payload to '0x4'; this describes the SIGN payload.
	sakkePayload.NextPayload = 0x4

	// Set SAKKE params to '0x01'; this describes the SAKKE parameter set 1.
	sakkePayload.SAKKEParams = 0x01

	// Set SAKKE ID scheme to '0x01'; this describes the ID scheme URI with monthly keys.
	sakkePayload.IDScheme = 0x01

	// Set SAKKE len to the length of the encapsulated data.
	sakkePayload.SakkeLen = make([]byte, 2)
	binary.BigEndian.PutUint16(sakkePayload.SakkeLen, uint16(len(sakkeEncapsulatedData)))

	// Set SAKKE data as the SAKKE encapsulated data.
	sakkePayload.SakkeData = sakkeEncapsulatedData
}

// setSIGN initializes the Signature Payload (SIGN) for the MIKEY message
// using the given ECCSI signature.
func (signPayload *SIGNPayload) setSIGN(eccsiSignature []byte) {

	// Set S type to '0x2'; this describes an ECCSI signature.
	signPayload.SType = 0x2

	// Set signature len to the length of the ECCSI signature.
	signPayload.SignatureLen = make([]byte, 2)
	binary.BigEndian.PutUint16(signPayload.SignatureLen, uint16(len(eccsiSignature)))

	// Set signature as the ECCSI signature.
	signPayload.Signature = eccsiSignature
}

// generateRAND generates RAND; a 128-bit pseudo-random bit-string.
// This must be a fresh value for each session selected by the Initiator.
// Returns RAND.
func generateRAND() (RAND []byte, err error) {

	// Determine max value, a 128-bits integer.
	max := new(big.Int)
	max.Exp(big.NewInt(2), big.NewInt(128), nil).Sub(max, big.NewInt(1))

	// Generate random value using cryptographically secure random generator.
	randInt, err := rand.Int(rand.Reader, max)
	if err != nil {
		err = fmt.Errorf("failed to generate RAND: %s", err.Error())
		return
	}
	// Convert RAND to []byte.
	RAND = randInt.Bytes()

	// Return RAND.
	return
}

// generateCSB_ID generates a Crypto Session Bundle ID (CSB ID);
// a pseudo-random 32-bits unsigned integer.
// This must be unique between each Initiator-Responder pair and chosen by the Identifier.
// Returns the CSB ID as []byte.
func generateCSB_ID() (csb_id []byte, err error) {

	// Determine max value, a 32-bits integer.
	max := new(big.Int)
	max.Exp(big.NewInt(2), big.NewInt(32), nil).Sub(max, big.NewInt(1))

	// Generate random value using cryptographically secure random generator.
	csb_idInt, err := rand.Int(rand.Reader, max)
	if err != nil {
		err = fmt.Errorf("failed to generate CSB ID: %s", err.Error())
		return
	}
	// Convert CSB ID to []byte.
	csb_id = csb_idInt.Bytes()

	// Return CSB ID.
	return
}

// ValidateNTPTimestamp checks if the given NTP timestamp is within the allowable time.
// If valid, returns true, else returns false.
func validateNTPTimestamp(timestamp ntp.Timestamp, allowableTime time.Duration) bool {

	// Convert NTP timestamp to Unix.
	const ntpEpochOffset = 2208988800
	sec := float64(timestamp.Seconds) - ntpEpochOffset
	nsec := (int64(timestamp.Fraction) * 1e9) >> 32
	unixTime := time.Unix(int64(sec), nsec)

	// Check time since timestamp.
	timeSince := time.Since(unixTime)

	// Check if 'timeSince' is less than 'allowableTime', and so, if timestamp is valid.
	return timeSince <= allowableTime
}
