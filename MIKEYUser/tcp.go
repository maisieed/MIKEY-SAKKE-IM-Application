package main

import (
	"encoding/binary"
	"fmt"
	"math/big"
	"net"
)

// tcpServer starts listening for incoming TCP requests on the given address.
func (user *User) tcpServer(address string) (err error) {

	// Make TCP address from given address.
	tcpAddress, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		err = fmt.Errorf("failed to resolve tcp address: %s: %s", tcpAddress, err.Error())
		return
	}
	// Start listening for incoming requests.
	l, err := net.ListenTCP("tcp", tcpAddress)
	if err != nil {
		err = fmt.Errorf("failed to start listening for incoming requests: %s", err.Error())
		return
	}
	// Close connection if program ends.
	defer l.Close()

	// Go func to stop TCP server.
	go func() {
		<-user.StopServer
		l.Close()
	}()
	for {
		// Listen for incoming request.
		var conn net.Conn
		conn, err = l.Accept()
		if err != nil {
			err = fmt.Errorf("failed to accept tcp connection: %s", err.Error())
			return
		}
		// Handle request in a new goroutine.
		go user.handleTCPRequest(conn)

	}
}

// handleTCPRequest reads the message type, length and body from the tcp connection.
// It then handles the message according to the message type.
func (user *User) handleTCPRequest(conn net.Conn) {

	// Read message type.
	// Make buffer to store message type.
	messageTypeBuf := make([]byte, 1)
	// Read message type.
	_, err := conn.Read(messageTypeBuf)
	if err != nil {
		fmt.Printf("Failed to read message type: %s\n", err.Error())
		sendResponse(conn, err.Error())
	}
	// Convert message type to byte.
	messageType := messageTypeBuf[0]

	// Read messsage length.
	// Make buffer to store message length.
	messsageLenBuf := make([]byte, binary.MaxVarintLen32)
	// Read message length.
	_, err = conn.Read(messsageLenBuf)
	if err != nil {
		fmt.Printf("Failed to read message length: %s\n", err.Error())
		sendResponse(conn, err.Error())
	}
	// Convert message length to integer value.
	messageLen := new(big.Int).SetBytes(messsageLenBuf).Uint64()

	// Read message.
	// Make buffer to store message.
	message := make([]byte, messageLen)
	// Read message.
	_, err = conn.Read(message)
	if err != nil {
		fmt.Printf("Failed to read message: %s\n", err.Error())
		sendResponse(conn, err.Error())
	}

	// Handle message.
	switch messageType {
	case 0x0:
		// If message type '0', handle MIKEY request.
		err = user.handleMIKEYRequest(message)
		if err != nil {
			fmt.Println(err)
			sendResponse(conn, err.Error())
		}
	case 0x1:
		// If message type '1', handle encrypted message.
		err = user.handleEncryptedMessage(message)
		if err != nil {
			fmt.Println(err)
			sendResponse(conn, err.Error())
		}

	default:
		err = fmt.Errorf("invalid message type: %s", string(messageType))
		fmt.Println(err)
		sendResponse(conn, err.Error())
	}

	// Send back a response.
	sendResponse(conn, "ok")

	// Close the connection.
	err = conn.Close()
	if err != nil {
		fmt.Printf("Failed to close the connection: %s\n", err.Error())
	}
}

// tcpClient makes a TCP connection with the given address and sends the message type, length and body.
// If successful, returns response.
func (user *User) tcpClient(messageType byte, message []byte, address string) (response []byte, err error) {

	// Make TCP address from given address.
	tcpAddress, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		err = fmt.Errorf("failed to resolve tcp address: %s: %s", tcpAddress, err.Error())
		return
	}
	// Make TCP connection.
	conn, err := net.DialTCP("tcp", nil, tcpAddress)
	if err != nil {
		err = fmt.Errorf("failed to create tcp connection with: %s: %s", tcpAddress, err.Error())
		return
	}
	// Make byte array from message type.
	tmpMessageType := []byte{messageType}

	// Write message type to connection.
	_, err = conn.Write(tmpMessageType)
	if err != nil {
		err = fmt.Errorf("failed to write message type to tcp connection: %s", err.Error())
		return
	}
	// Find length of message.
	messageLen := make([]byte, binary.MaxVarintLen32)
	big.NewInt(int64(len(message))).FillBytes(messageLen)

	// Write message length to connection.
	_, err = conn.Write(messageLen)
	if err != nil {
		err = fmt.Errorf("failed to write message length to tcp connection: %s", err.Error())
		return
	}
	// Write message to connection.
	_, err = conn.Write(message)
	if err != nil {
		err = fmt.Errorf("failed to write message to tcp connection: %s", err.Error())
		return
	}
	// Read response.
	err = readResponse(conn)

	// Close connection.
	conn.Close()
	return
}

// sendResponse sends the given response back to the client with which the connection is made.
func sendResponse(conn net.Conn, response string) {

	// Convert response to []byte.
	responseBuf := []byte(response)

	// Find length of response.
	responseLen := make([]byte, binary.MaxVarintLen32)
	big.NewInt(int64(len(responseBuf))).FillBytes(responseLen)

	// Write response length to client.
	_, err := conn.Write(responseLen)
	if err != nil {
		fmt.Printf("Failed to send response length: %s\n", err.Error())
	}
	// Write response to client.
	_, err = conn.Write(responseBuf)
	if err != nil {
		fmt.Printf("Failed to send response: %s\n", err.Error())
	}
}

// readResponse reads the response from the server with which the connection is made.
// If response is not 'ok', returns response as an error.
func readResponse(conn net.Conn) (err error) {

	// Read response length.
	// Make buffer to store response length.
	responseLenBuf := make([]byte, binary.MaxVarintLen32)
	// Read response length.
	_, err = conn.Read(responseLenBuf)
	if err != nil {
		err = fmt.Errorf("failed to read response length: %s", err.Error())
		return
	}
	// Convert response length to integer value.
	responseLen := new(big.Int).SetBytes(responseLenBuf).Uint64()

	// Read response.
	// Make buffer to store response.
	responseBuf := make([]byte, responseLen)
	// Read response.
	_, err = conn.Read(responseBuf)
	if err != nil {
		err = fmt.Errorf("failed to read response: %s", err.Error())
		return
	}
	// Convert response to a string.
	response := string(responseBuf)

	// If response is not 'ok', return error.
	if response != "ok" {
		err = fmt.Errorf("%s", response)
	}
	return
}
