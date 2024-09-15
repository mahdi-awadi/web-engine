package engine

const (
	FlashMessageDebugType   = "debug"
	FlashMessageSuccessType = "success"
	FlashMessageErrorType   = "error"
	FlashMessageWarningType = "warning"
)

// FlashMessages define types
type FlashMessages map[string][]string
type Flash struct {
	messages FlashMessages
}

// NewFlash creates a new Flash.
func NewFlash() *Flash {
	return &Flash{
		messages: FlashMessages{},
	}
}

// set sets flash messages in types.
func (f *Flash) set(messageType string, messageValue string) {
	if len(f.messages[messageType]) == 0 {
		f.messages[messageType] = []string{messageValue}
		return
	}

	f.messages[messageType] = append(f.messages[messageType], messageValue)
}

// Get flash messages by type.
func (f *Flash) Get(flashType string, remove bool) []string {
	var values []string
	if m, ok := f.messages[flashType]; ok {
		values = m
	}

	// if delete
	if remove {
		delete(f.messages, flashType)
	}

	return values
}

// Pull get flash by type and forget items.
func (f *Flash) Pull(flashType string) []string {
	return f.Get(flashType, true)
}

// Messages returns flash messages
func (f *Flash) Messages() FlashMessages {
	return f.messages
}

// Clear removes all messages from the Flash.
func (f *Flash) Clear() {
	f.messages = FlashMessages{}
}

// Len returns flash message count.
func (f *Flash) Len(flashType string) int {
	return len(f.Get(flashType, false))
}

// Debug set messages in debug type.
func (f *Flash) Debug(message string) {
	f.set(FlashMessageDebugType, message)
}

// Success set messages in success type.
func (f *Flash) Success(message string) {
	f.set(FlashMessageSuccessType, message)
}

// Error set messages in error type.
func (f *Flash) Error(message string) {
	f.set(FlashMessageErrorType, message)
}

// Warning set messages in warning type.
func (f *Flash) Warning(message string) {
	f.set(FlashMessageWarningType, message)
}

// HasError determine is flash messages includes error message
func (f *Flash) HasError() bool {
	return len(f.Get(FlashMessageErrorType, false)) > 0
}

// HasMessage returns is flash has messages
func (f *Flash) HasMessage() bool {
	return len(f.messages) > 0
}
