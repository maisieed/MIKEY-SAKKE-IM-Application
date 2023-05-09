package main

import (
	"fmt"
	"os"
	"path/filepath"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
)

// loginPage sets the GUI for the login page.
func (user *User) loginPage() {

	// Initalize login widgets.
	loginLabel := widget.NewLabelWithStyle("Login", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	// Entry widget for entering user URI.
	uriEntry := widget.NewEntry()
	uriEntry.SetPlaceHolder("Enter URI..")
	// Entry widget for entering the filepath to configuraton.
	filepathEntry := widget.NewEntry()
	filepathEntry.SetPlaceHolder("Enter configuration filepath..")
	// Open file button.
	openDirButton := widget.NewButton("Select directory", func() { user.selectFile(filepathEntry) })
	// Login button.
	loginButton := widget.NewButton("Login", func() { user.handleLoginPage(uriEntry.Text, filepathEntry.Text) })
	// Login page container.
	loginPage := container.New(
		layout.NewVBoxLayout(),
		loginLabel,
		uriEntry,
		container.New(layout.NewFormLayout(), openDirButton, filepathEntry),
		loginButton,
	)
	// Set window as login page.
	user.CurrentWindow = "login"
	user.W.SetContent(loginPage)
}

// menuPage sets the GUI for the menu page.
func (user *User) menuPage() {

	// Initialize menu.
	menuLabel := widget.NewLabelWithStyle(fmt.Sprintf("Welcome %s", user.URI), fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	// Log out button.
	logoutButton := widget.NewButton("Logout", func() {
		// Stop server.
		user.StopServer <- true
		// Reset 'User' data.
		user = &User{W: user.W}
		// Set window as login page.
		user.loginPage()
	})

	// Add session button.
	addSessionButton := widget.NewButton("Add session", func() { user.newSessionPage() })
	// Menu page container.
	menuPage := container.New(
		layout.NewVBoxLayout(),
		container.New(layout.NewFormLayout(), logoutButton, menuLabel),
		addSessionButton,
	)
	// Add chat buttons for each established sessions.
	for userURI := range user.EstablishedKeys {
		chatButton := widget.NewButton(fmt.Sprintf("Chat with %s", userURI), func() { user.chatPage(userURI) })
		menuPage.Add(chatButton)
	}
	// Set window as menu page.
	user.CurrentWindow = "menu"
	user.W.SetContent(menuPage)
}

// newSessionPage sets the GUI for the new session page.
func (user *User) newSessionPage() {

	// Initalize new session page.
	newSessionLabel := widget.NewLabelWithStyle("New session", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	// Back button.
	backButton := widget.NewButton("Back", func() { user.menuPage() })
	// Entry widget for entering interlocutor URI.
	interlocutorURIEntry := widget.NewEntry()
	interlocutorURIEntry.SetPlaceHolder("Enter URI of user..")
	// New session button.
	newSessionButton := widget.NewButton("Send request", func() { user.handleNewSessionPage(interlocutorURIEntry.Text) })
	// Session page container.
	sessionPage := container.New(
		layout.NewVBoxLayout(),
		container.New(layout.NewFormLayout(), backButton, newSessionLabel),
		interlocutorURIEntry,
		newSessionButton,
	)
	// Set window as new session page.
	user.CurrentWindow = "newSession"
	user.W.SetContent(sessionPage)
}

// chatPage sets the GUI for the chat page.
func (user *User) chatPage(interlocutorURI string) {

	// Initalize new chat page.
	chatLabel := widget.NewLabelWithStyle(fmt.Sprintf("Chat with %s", interlocutorURI), fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	// Back button.
	backButton := widget.NewButton("Back", func() { user.menuPage() })
	// Chat container.
	chatPage := container.New(
		layout.NewVBoxLayout(),
		container.New(layout.NewFormLayout(), backButton, chatLabel),
	)
	// Add labels for each message.
	for _, chat := range user.Messages[interlocutorURI] {
		// Initialize message.
		var message *widget.Label
		if chat.IsReceived {
			// If message was received, position left.
			message = widget.NewLabelWithStyle(chat.Content, fyne.TextAlignLeading, fyne.TextStyle{})
		} else {
			// If message was sent, position right.
			message = widget.NewLabelWithStyle(chat.Content, fyne.TextAlignTrailing, fyne.TextStyle{})
		}
		chatPage.Add(message)
	}
	// Add spacer to chat page.
	chatPage.Add(layout.NewSpacer())
	// Entry widget for entering new message.
	newMessageEntry := widget.NewEntry()
	newMessageEntry.SetPlaceHolder("Enter new message..")
	// Send button.
	sendButton := widget.NewButton("Send", func() { user.handleSendMessagePage(newMessageEntry, interlocutorURI) })
	chatPage.Add(container.New(layout.NewFormLayout(), sendButton, newMessageEntry))
	// Set window as new session page.
	user.CurrentWindow = interlocutorURI
	user.W.SetContent(chatPage)
}

// login validates the user entries and if successful, logs the user in.
func (user *User) handleLoginPage(uriEntry string, filepathEntry string) (err error) {

	// Check URI has been entered.
	if uriEntry == "" {
		dialog.ShowInformation("Error", "Error, must enter URI", user.W)
		return
	}
	// Check filepath has been entered.
	if filepathEntry == "" {
		dialog.ShowInformation("Error", "Error, must enter filepath", user.W)
		return
	}
	// Check filepath is valid.
	_, err = os.Stat(filepathEntry)
	if os.IsNotExist(err) {
		dialog.ShowInformation("Error", "Error, filepath does not exist", user.W)
		return
	} else if err != nil {
		dialog.ShowInformation("Error", "Error, invalid filepath", user.W)
		return
	}
	// Check file is a JSON file.
	if filepath.Ext(filepathEntry) != ".json" {
		dialog.ShowInformation("Error", "Error, file type must be JSON", user.W)
		return
	}
	// Use these values to initialize user.
	err = user.initializeUser(uriEntry, filepathEntry)
	if err != nil {
		dialog.ShowInformation("Error", err.Error(), user.W)
		return
	}
	// Set menu as window.
	user.menuPage()
	return
}

// newSession validates the user entries and if successful, initalizes new session.
func (user *User) handleNewSessionPage(interlocutorURI string) {

	// Check URI has been entered.
	if interlocutorURI == "" {
		dialog.ShowInformation("Error", "Error, must enter URI", user.W)
		return
	}
	// Initalize session.
	err := user.sendMIKEYRequest(interlocutorURI)
	if err != nil {
		dialog.ShowInformation("Error", err.Error(), user.W)
		return
	}
	// If session was initalized successful, show success message.
	dialog.ShowInformation("Success", fmt.Sprintf("Session with %s initalized successfully", interlocutorURI), user.W)

	// Set menu as window.
	user.menuPage()
}

// sendMessage validates the user entries and if successful, sends message.
func (user *User) handleSendMessagePage(message *widget.Entry, interlocutorURI string) {

	// Check message has been entered.
	if message.Text == "" {
		dialog.ShowInformation("Error", "Error, must enter message", user.W)
		return
	}
	// Send message.
	err := user.sendEncryptedMessage(message.Text, interlocutorURI)
	if err != nil {
		dialog.ShowInformation("Error", err.Error(), user.W)
		return
	}
	// Reset entry.
	message.SetText("")
}

// refreshPage recomputes the widgets shown on the currently displayed window.
func (user *User) refreshPage() {

	for {
		// Detect when page needs updating.
		<-user.UpdateWindow
		switch user.CurrentWindow {
		case "login":
			// If user is viewing login page, refresh login page.
			user.loginPage()

		case "menu":
			// If user is viewing the menu page, refresh menu page.
			user.menuPage()

		case "newSession":
			// If user is viewing the new session page, refresh new session page.
			user.newSessionPage()

		default:
			// If user is viewing a chat page, refresh chat page.
			user.chatPage(user.CurrentWindow)
		}
	}
}

// selectFile allows user to select file using file browser.
// Sets the filepath entry wiget as selected file.
func (user *User) selectFile(filepath *widget.Entry) {
	dialog.ShowFileOpen(func(file fyne.URIReadCloser, err error) {

		// Filepath of selected file.
		filePathName := ""

		// If error occurs, return error.
		if err != nil {
			dialog.ShowInformation("Error", "Error, invalid filepath", user.W)
			return
		}
		// Update filepath with selected file.
		if file != nil {
			filePathName = file.URI().Path()
		}
		// Sets entry as selected filepath.
		filepath.SetText(filePathName)
	}, user.W)
}
