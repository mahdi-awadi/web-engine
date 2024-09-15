package engine

// ILanguage is the interface for language
type ILanguage interface {
	GetName() string   // English (US)
	GetCode() string   // en_US
	GetLocale() string // en
}

// Language is the language
type Language struct {
	Name   string `json:"name"`
	Code   string `json:"code"`
	Locale string `json:"locale"`
}

// GetName returns language Name
func (l Language) GetName() string {
	return l.Name
}

// GetCode returns language Code
func (l Language) GetCode() string {
	return l.Code
}

// GetLocale returns language Locale
func (l Language) GetLocale() string {
	return l.Locale
}
