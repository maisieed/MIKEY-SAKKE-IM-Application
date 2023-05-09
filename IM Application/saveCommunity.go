package main

import (
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"strings"

	"github.com/Nik-U/pbc"
)

// readUser reads the 'User' values from the specified JSON file.
func (user *User) readUser(filepath string) (err error) {

	// Initialize new map.
	encodedValues := map[string]interface{}{}

	// Read in specified JSON file.
	file, err := ioutil.ReadFile(filepath)
	if err != nil {
		err = fmt.Errorf("failed to read JSON file: %s: %s", filepath, err.Error())
		return
	}
	// Unmarshal file into map.
	err = json.Unmarshal(file, &encodedValues)
	if err != nil {
		err = fmt.Errorf("failed to unmarshal 'User' values: %s", err.Error())
		return
	}
	// Add SAKKE values to 'User'.
	err = user.Sakke.readSakkeUserValues(encodedValues["Sakke"].(map[string]interface{}))
	if err != nil {
		return
	}
	// Add ECCSI values to 'User'.
	err = user.Eccsi.readEccsiUserValues(encodedValues["Eccsi"].(map[string]interface{}))
	if err != nil {
		return
	}
	// Return updated 'User'.
	return
}

// readSakkeUserValues converts the SAKKE User values, including the community values, read from a JSON file
// to the valid type for the 'SakkeUser' struct.
// Adds the decoded values to 'SakkeUser'.
func (user *SakkeUser) readSakkeUserValues(encodedValues map[string]interface{}) (err error) {

	// Convert SAKKE community values.
	err = user.readSakkeCommunityValues(encodedValues)
	if err != nil {
		return
	}
	// Convert 'RSK' from base64 encoded []byte into PBC element if set.
	if RSKString, ok := encodedValues["RSK"].(string); ok {
		var RSK []byte
		RSK, err = base64.StdEncoding.DecodeString(RSKString)
		if err != nil {
			err = fmt.Errorf("failed to read 'RSK' from JSON file: %s", err.Error())
			return
		}
		user.RSK = user.pairing.NewG1().SetCompressedBytes(RSK)
	}

	return
}

// readSakkeCommunityValues converts the SAKKE community values read from a JSON file
// to the valid type for the 'SakkeCommunity' struct.
// Adds the decoded values to 'SakkeCommunity'.
func (community *SakkeCommunity) readSakkeCommunityValues(encodedValues map[string]interface{}) (err error) {

	var isSuccess bool // True if value converted successfully, else false.

	// Convert 'n' from Hex into big.Int.
	community.n, isSuccess = new(big.Int).SetString(encodedValues["n"].(string), 16)
	if !isSuccess {
		err = fmt.Errorf("failed to read 'n' from JSON file")
		return
	}
	// Convert 'pbits' from Hex into big.Int.
	community.pbits, isSuccess = new(big.Int).SetString(encodedValues["pbits"].(string), 16)
	if !isSuccess {
		err = fmt.Errorf("failed to read 'pbits' from JSON file")
		return
	}
	// Convert 'qbits' from Hex into big.Int.
	community.qbits, isSuccess = new(big.Int).SetString(encodedValues["qbits"].(string), 16)
	if !isSuccess {
		err = fmt.Errorf("failed to read 'qbits' from JSON file")
		return
	}
	// Convert 'params' from string into PBC params.
	stringParam := encodedValues["params"].(string)
	community.params, err = pbc.NewParamsFromString(stringParam)
	if err != nil {
		err = fmt.Errorf("failed to read 'params' from JSON file: %s", err.Error())
		return
	}
	// Extract 'q' from 'params'.
	startPosition := strings.Index(stringParam, "\nr ") + 3
	endPosition := strings.Index(stringParam[startPosition:], "\n") + startPosition
	// Convert 'q' from string into big.Int.
	community.q, isSuccess = new(big.Int).SetString(stringParam[startPosition:endPosition], 10)
	if !isSuccess {
		err = fmt.Errorf("failed to read 'q' from JSON file")
		return
	}
	// Compute pairing on curve using 'params'.
	community.pairing = community.params.NewPairing()

	// Convert 'P' from base64 encoded []byte into PBC element.
	p, err := base64.StdEncoding.DecodeString(encodedValues["P"].(string))
	if err != nil {
		err = fmt.Errorf("failed to read 'P' from JSON file: %s", err.Error())
		return
	}
	community.P = community.pairing.NewG1().SetCompressedBytes(p)

	// Convert 'ZT' from base64 encoded []byte into PBC element.
	ZT, err := base64.StdEncoding.DecodeString(encodedValues["ZT"].(string))
	if err != nil {
		err = fmt.Errorf("failed to read 'ZT' from JSON file: %s", err.Error())
		return
	}
	community.ZT = community.pairing.NewG1().SetCompressedBytes(ZT)

	// Compute pairing g = <P,P>.
	community.g = community.pairing.NewGT().Pair(community.P, community.P)

	return
}

// readEccsiUserValues converts the ECCSI User values, including the community values, read from a JSON file
// to the valid type for the 'EccsiUser' struct.
// Adds the decoded values to 'EccsiUser'.
func (user *EccsiUser) readEccsiUserValues(encodedValues map[string]interface{}) (err error) {

	var isSuccess bool // True if value converted successfully, else false.

	// Convert ECCSI community values.
	err = user.readEccsiCommunityValues(encodedValues)
	if err != nil {
		return
	}
	// If (SSK,PVT) pair has been set, convert values.
	if _, ok := encodedValues["SSK"].(string); ok {

		// Convert 'SSK' from Hex into big.Int.
		user.SSK, isSuccess = new(big.Int).SetString(encodedValues["SSK"].(string), 16)
		if !isSuccess {
			err = fmt.Errorf("failed to read 'SSK' from JSON file")
			return
		}
		// Convert 'HS' from Hex into big.Int.
		user.HS, isSuccess = new(big.Int).SetString(encodedValues["HS"].(string), 16)
		if !isSuccess {
			err = fmt.Errorf("failed to read 'HS' from JSON file")
			return
		}
		// Convert 'PVTx' from Hex into big.Int.
		user.PVTx, isSuccess = new(big.Int).SetString(encodedValues["PVTx"].(string), 16)
		if !isSuccess {
			err = fmt.Errorf("failed to read 'PVTx' from JSON file")
			return
		}
		// Convert 'PVTy' from Hex into big.Int.
		user.PVTy, isSuccess = new(big.Int).SetString(encodedValues["PVTy"].(string), 16)
		if !isSuccess {
			err = fmt.Errorf("failed to read 'PVTy' from JSON file")
			return
		}
		// Check 'PVT' is on the curve 'E'.
		if !user.E.IsOnCurve(user.PVTx, user.PVTy) {
			err = fmt.Errorf("point PVT is not on the elliptical curve NIST P256")
			return
		}
		// Find 'PVT' on curve.
		user.PVT = elliptic.Marshal(user.E, user.PVTx, user.PVTy)
	}
	return
}

// readEccsiCommunityValues converts the Eccsi community values read from a JSON file
// to the valid type for the 'EccsiCommunity' struct.
// Adds the decoded values to 'EccsiCommunity'.
func (community *EccsiCommunity) readEccsiCommunityValues(encodedValues map[string]interface{}) (err error) {

	var isSuccess bool // True if value converted successfully, else false.

	// Compute elliptical curve NIST P-256.
	community.E = elliptic.P256()
	// Add 'N'.
	community.N = int(encodedValues["N"].(float64))

	// Convert 'q' from Hex to big.Int.
	community.q, isSuccess = new(big.Int).SetString(encodedValues["q"].(string), 16)
	if !isSuccess {
		err = fmt.Errorf("failed to read 'q' from JSON file")
		return
	}
	// Convert 'Gx' from Hex to big.Int.
	community.Gx, isSuccess = new(big.Int).SetString(encodedValues["Gx"].(string), 16)
	if !isSuccess {
		err = fmt.Errorf("failed to read 'Gx' from JSON file")
		return
	}
	// Convert 'Gy' from Hex to big.Int.
	community.Gy, isSuccess = new(big.Int).SetString(encodedValues["Gy"].(string), 16)
	if !isSuccess {
		err = fmt.Errorf("failed to read 'Gx' from JSON file")
		return
	}
	// Convert 'KPAKx' from Hex to big.Int.
	community.KPAKx, isSuccess = new(big.Int).SetString(encodedValues["KPAKx"].(string), 16)
	if !isSuccess {
		err = fmt.Errorf("failed to read 'KPAKx' from JSON file")
		return
	}
	// Convert 'KPAKy' from Hex to big.Int.
	community.KPAKy, isSuccess = new(big.Int).SetString(encodedValues["KPAKy"].(string), 16)
	if !isSuccess {
		err = fmt.Errorf("failed to read 'KPAKy' from JSON file")
		return
	}
	// Check 'G' is on the curve 'E'.
	if !community.E.IsOnCurve(community.Gx, community.Gy) {
		err = fmt.Errorf("point G is not on the elliptical curve NIST P256")
		return
	}
	// Check 'KPAK' is on the curve 'E'.
	if !community.E.IsOnCurve(community.KPAKx, community.KPAKy) {
		err = fmt.Errorf("point KPAK is not on the elliptical curve NIST P256")
		return
	}
	// Find 'G' on curve.
	community.G = elliptic.Marshal(community.E, community.Gx, community.Gy)

	// Find KPAK on curve.
	community.KPAK = elliptic.Marshal(community.E, community.KPAKx, community.KPAKy)

	return
}
