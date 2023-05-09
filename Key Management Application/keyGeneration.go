package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"math"
	"math/big"

	"github.com/lukechampine/fastxor"
)

// generateKey derives the TEK (Traffic-Encrypting Key) from the 'inkey' and 'label'.
// In SAKKE, the SSV (shared secret value) is used as the TGK (TEK Generation Key).
// Returns the TEK 'outkey' of desired length 'outKey_len'.
func generateKey(inkey *big.Int, cs_id byte, csb_id []byte, RAND []byte, outkey_len int) (outKey []byte, err error) {

	// Compute the length in bits of the input key.
	inkey_len := inkey.BitLen()

	// Generate label.
	label := generateLabel(cs_id, csb_id, RAND)

	// 1) Compute n = inkey_len / 256, rounded up to nearest integer.
	n := int(math.Ceil(float64(inkey_len) / float64(256)))

	// 2) Split the inkey into n blocks.
	s := make([][]byte, n)
	for i := range s {
		if ((i + 1) * 32) > len(inkey.Bytes()) {
			// If remaining bits are less than 256 bits, add remaining bits to block.
			s[i] = inkey.Bytes()[i*32 : len(inkey.Bytes())]
		} else {
			// If remaining bits are greater than 256 bits, add 256 bits to block.
			s[i] = inkey.Bytes()[i*32 : (i+1)*32]
		}
	}

	// 3) Compute m = outkey_len / 160, rounded up to nearest integer.
	m := int(math.Ceil(float64(outkey_len) / float64(160)))

	// 4) Calculate PRF(inkey, label) = P(s_1, label, m) XOR P(s_2, label, m) XOR ... XOR P(s_n, label, m).
	for i, s_i := range s {

		// Initialize result of P(s_i, label, m).
		var result []byte

		// Compute P(s_i, label, m).
		result, err = P(s_i, label, m)
		if err != nil {
			return
		}
		// If not P(s_1, label, m), XOR with P(s_(i-1), label, m).
		if i != 0 {
			fastxor.Bytes(outKey, outKey, result)
		} else {
			outKey = result
		}
	}

	// Check 'outKey_len' is less or equal to 'outKey'.
	if (outkey_len / 8) >= len(outKey) {
		err = fmt.Errorf("selected outKey_len is too big")
		return
	}
	// Return 'outKey' the length 'outKey_len'.
	outKey = outKey[:outkey_len/8]
	return
}

// generateLabel generates a label for generating a TEK (Traffic-Encrypting Key) from TGK (TEK Generation Key)
// using the cs_id (Crypto Session ID), csb_id (Crypto Session Bundle ID) and RAND.
// Returns the label.
func generateLabel(cs_id byte, csb_id []byte, RAND []byte) (label []byte) {

	// Define constant used to generate a TEK from TGK.
	constant := make([]byte, 4)
	binary.BigEndian.PutUint32(constant, 0x2AD01C64)

	// Compute constant || cs_id || csb_id || RAND.
	label = append(label, constant...)
	label = append(label, cs_id)
	label = append(label, csb_id...)
	label = append(label, RAND...)

	return
}

// P computes HMAC (s, A_1 || label) || HMAC (s, A_2 || label) || ... HMAC (s, A_m || label)
// where HMAC is a SHA-1 hash function.
// Returns the resulting hash value.
func P(s []byte, label []byte, m int) (result []byte, err error) {

	// Initialize 'A' which starts as 'label'.
	A := []byte{}
	copy(A, label)

	// For 'm', calculate HMAC.
	for i := 1; i <= m; i++ {

		// Initialize hash value of HMAC (s, A_i || label).
		var hashValue []byte

		// Compute A_i = HMAC(s, A_(i-1)).
		A, err = HMAC(s, A)
		if err != nil {
			return
		}
		// Concatenate A_i || label.
		message := append(A, label...)

		// Compute HMAC (s, A_i || label).
		hashValue, err = HMAC(s, message)
		if err != nil {
			return
		}
		// Concatenate 'hashValue' with previous 'hashValue's.
		result = append(result, hashValue...)
	}

	// Return resulting hash value.
	return
}

// HMAC signs message using HMAC SHA-1 hash function using given key.
func HMAC(key []byte, message []byte) (hashValue []byte, err error) {

	// Create new HMAC hash function using given key.
	mac := hmac.New(sha1.New, key)
	// Sign message using hash function.
	_, err = mac.Write(message)
	if err != nil {
		err = fmt.Errorf("failed to sign message using HMAC hash function: %s", err.Error())
		return
	}
	// Return hash value.
	hashValue = mac.Sum(nil)
	return
}
