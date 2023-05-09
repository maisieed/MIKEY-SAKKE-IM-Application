package main

import (
	"math/big"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
)

// CommunityUsers maps URI to address of users of the community.
var CommunityUsers = map[string]string{
	"alice@workemail.com": "localhost:8080",
	"bob@workemail.com":   "localhost:8081",
}

// User contains the parameters for the user.
type User struct {
	URI             string               // The Uniform Resource Identifier (URI) of the user.
	ID              *big.Int             // The user ID.
	ReplayCache     ReplayCache          // The parameters to prevent replay attacks.
	Eccsi           EccsiUser            // The parameters for ECCSI.
	Sakke           SakkeUser            // The parameters for SAKKE.
	EstablishedKeys map[string][]byte    // The user's established keys, maps interlocutor URI to keys.
	Messages        map[string][]Message // The user's messages, maps interlocutor URI to messages.
	StopServer      chan bool            // Channel that will signal when to stop TCP server.
	W               fyne.Window          // The application GUI window.
	CurrentWindow   string               // The current window the user is viewing.
	UpdateWindow    chan bool            // Channel that will deliver signal when the window needs updating.
}

// Message contains the parameters for a received/sent encrypted message.
type Message struct {
	Time       time.Time // Time that message was received.
	IsReceived bool      // True if was received, false if it was sent.
	Content    string    // The content of the message.
}

func main() {

	// Initialize 'User'.
	var user User
	// Set new window.
	a := app.New()
	user.W = a.NewWindow("Workplace IM Application")
	// Set window as login page.
	user.loginPage()
	// Show window.
	user.W.Resize(fyne.NewSize(700, 700))
	user.W.ShowAndRun()
}

// initializeUser initializes the community values for a user and then computes
// the user's Secret Signing Key (SSK), Public Validation Token (PVT) and Receiver Secret Key (RSK).
func (user *User) initializeUser(URI string, filepath string) (err error) {

	// Set URI.
	user.URI = URI

	// Compute userID using URI.
	user.ID, err = generateIDInteger(user.URI)
	if err != nil {
		return
	}
	// Read in community values.
	err = user.readUser(filepath)
	if err != nil {
		return
	}
	// Validate (SSK,PVT) Pair.
	err = user.Eccsi.validateReceivedSSK(user.ID, user.Eccsi.SSK, user.Eccsi.PVT)
	if err != nil {
		return
	}
	// Validate RSK.
	err = user.Sakke.verifyRSK(user.ID, user.Sakke.RSK)
	if err != nil {
		return
	}
	// Initialize maps.
	user.EstablishedKeys = map[string][]byte{}
	user.Messages = map[string][]Message{}

	// Initialize clock skew ticker.
	user.ReplayCache.clockSkew = 1 * time.Second
	user.ReplayCache.tick = time.NewTicker(user.ReplayCache.clockSkew)
	// Start handling replay cache.
	go user.ReplayCache.resetReplayCache()

	// Initialize updating window channel.
	user.UpdateWindow = make(chan bool)
	// Start updating window.
	go user.refreshPage()

	// Initalize stop TCP server channel.
	user.StopServer = make(chan bool)

	// Start listening for incoming TCP requests.
	go func() {
		err = user.tcpServer(CommunityUsers[user.URI])
		if err != nil {
			return
		}
	}()

	return
}
