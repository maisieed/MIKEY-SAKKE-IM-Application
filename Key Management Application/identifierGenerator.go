package main

import (
	"fmt"
	"math/big"
	"regexp"
	"time"
)

// Define regular expression for email.
// This could be made more specific for a work email, where users share a domain name.
var emailRegex = "^\\S+@\\S+$"

// generateIDInteger creates the identifier for a user from the given URI. It then converts this to
// an integer value which can be used by SAKKE and ECCSI.
func generateIDInteger(URI string) (ID *big.Int, err error) {

	// Create identifier using given URI.
	identifier, err := generateIdentifier(URI)
	if err != nil {
		return
	}
	// Convert identifier to Big.Int.
	// This does not use a hash function, in order to prevent collisions.
	ID = new(big.Int).SetBytes([]byte(identifier))

	return
}

// generateIdentifier creates the identifier for a user from the given 'email' URI.
// Returns the identifier in the format "YYYY-MM\0email:xxxxxxxxxxx\0" where \0 is the null ASCII character "0x00".
func generateIdentifier(emailURI string) (identifier string, err error) {

	// Create null byte.
	nullByte := "\x00"

	// Create regex for email.
	regex, err := regexp.Compile(emailRegex)
	if err != nil {
		err = fmt.Errorf("failed to create 'email' regexp: %s", err.Error())
		return
	}
	// Check the 'email' URI matchs the regex.
	if !regex.MatchString(emailURI) {
		err = fmt.Errorf("invalid 'email' URI")
		return
	}
	// Create current timestamp in format "YYYY-MM".
	timeParam := time.Now().Format("2006-01-02")[:7]

	// Create identifier.
	identifier = fmt.Sprintf("%s%semail:%s%s", timeParam, nullByte, emailURI, nullByte)

	return
}
