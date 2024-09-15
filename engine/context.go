package engine

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

type ResponseFormat int

const (
	ResponseFormatJson ResponseFormat = iota
	ResponseFormatJsonp
	ResponseFormatString
	ResponseFormatHtml
	ResponseFormatNoContent
)

type (
	// Context represents the context of the current HTTP request. It holds request and
	// response objects, path, path parameters, messages and registered handler.
	Context interface {
		// Request returns `*http.Request`.
		Request() *http.Request

		// SetRequest sets `*http.Request`.
		SetRequest(r *http.Request)

		// SetResponse sets `*Response`.
		SetResponse(r *Response)

		// SetResponseFormat sets response type
		SetResponseFormat(format ResponseFormat)

		// Response returns `*Response`.
		Response() *Response

		// IsTLS returns true if HTTP connection is TLS otherwise false.
		IsTLS() bool

		// IsWebSocket returns true if HTTP connection is WebSocket otherwise false.
		IsWebSocket() bool

		// Scheme returns the HTTP app scheme, `engine` or `https`.
		Scheme() string

		// RealIP returns the client's network address based on `X-Forwarded-For`
		// or `X-Real-IP` request header.
		// The behavior can be configured using `Engine#IPExtractor`.
		RealIP() string

		// Path returns the registered path for the handler.
		Path() string

		// SetPath sets the registered path for the handler.
		SetPath(p string)

		// Param returns path parameter by Name.
		Param(name string) string

		// ParamNames returns path parameter names.
		ParamNames() []string

		// SetParamNames sets path parameter names.
		SetParamNames(names ...string)

		// ParamValues returns path parameter values.
		ParamValues() []string

		// SetParamValues sets path parameter values.
		SetParamValues(values ...string)

		// QueryParam returns the query param for the provided Name.
		QueryParam(name string) string

		// QueryParams returns the query parameters as `url.Values`.
		QueryParams() url.Values

		// QueryString returns the URL query string.
		QueryString() string

		// FormValue returns the form field value for the provided Name.
		FormValue(name string) string

		// FormParams returns the form parameters as `url.Values`.
		FormParams() (url.Values, error)

		// FormFile returns the multipart form file for the provided Name.
		FormFile(name string) (*multipart.FileHeader, error)

		// MultipartForm returns the multipart form.
		MultipartForm() (*multipart.Form, error)

		// Cookie returns the named cookie provided in the request.
		Cookie(name string) (*http.Cookie, error)

		// SetCookie adds a `Set-Cookie` header in HTTP response.
		SetCookie(cookie *http.Cookie)

		// Cookies returns the HTTP cookies sent with the request.
		Cookies() []*http.Cookie

		// Get retrieves messages from the context.
		Get(key string) interface{}

		// Set saves messages in the context.
		Set(key string, val interface{})

		// Bind binds the request body into provided type `i`. The default binder
		// does it based on Content-Type header.
		Bind(i interface{}) error

		// Validate validates provided `i`. It is usually called after `Context#Bind()`.
		// Validator must be registered using `Engine#Validator`.
		Validate(i interface{}) error

		// Render renders a template with messages and sends a text/html response with status
		// Code. Renderer must be registered using `Engine.Renderer`.
		Render(code int, name string, data interface{}) error

		// HTML sends an HTTP response with status Code.
		HTML(code int, html string) error

		// HTMLBlob sends an HTTP blob response with status Code.
		HTMLBlob(code int, b []byte) error

		// String sends a string response with status Code.
		String(code int, s string) error

		// JSON sends a JSON response with status Code.
		JSON(code int, i interface{}) error

		// JsonResponse send JSON response with default 200 status
		JsonResponse(i interface{}) error

		// JSONPretty sends a pretty-print JSON with status Code.
		JSONPretty(code int, i interface{}, indent string) error

		// JSONBlob sends a JSON blob response with status Code.
		JSONBlob(code int, b []byte) error

		// JSONP sends a JSONP response with status Code. It uses `callback` to construct
		// the JSONP payload.
		JSONP(code int, callback string, i interface{}) error

		// JSONPBlob sends a JSONP blob response with status Code. It uses `callback`
		// to construct the JSONP payload.
		JSONPBlob(code int, callback string, b []byte) error

		// XML sends an XML response with status Code.
		XML(code int, i interface{}) error

		// XMLPretty sends a pretty-print XML with status Code.
		XMLPretty(code int, i interface{}, indent string) error

		// XMLBlob sends an XML blob response with status Code.
		XMLBlob(code int, b []byte) error

		// Blob sends a blob response with status Code and content type.
		Blob(code int, contentType string, b []byte) error

		// Stream sends a streaming response with status Code and content type.
		Stream(code int, contentType string, r io.Reader) error

		//File sends a response with the content of the file.
		File(file string) error

		// Attachment sends a response as attachment, prompting client to save the
		// file.
		//Attachment(file string, Name string) error

		// Inline sends a response as inline, opening the file in the browser.
		//Inline(file string, Name string) error

		// NoContent sends a response with no body and a status Code.
		NoContent(code int) error

		// Redirect redirects the request to a provided URL with status Code.
		Redirect(code int, url string) error

		// Handler returns the matched handler by router.
		Handler() HandlerFunc

		// SetHandler sets the matched handler by router.
		SetHandler(h HandlerFunc)

		// Logger returns the `Logger` instance.
		Logger() Logger

		// SetLogger Set the logger
		SetLogger(l Logger)

		// Engine returns the `Engine` instance.
		Engine() *Engine

		// Flash returns flash message instance
		Flash() *Flash

		// SwitchIdentity switch identity instance
		SwitchIdentity(IIdentity)

		// GetIdentity returns identity instance
		GetIdentity() IIdentity

		// SwitchSite switch site instance
		SwitchSite(ISite)

		// GetSite returns site instance
		GetSite() ISite

		// SwitchLanguage switch language instance
		SwitchLanguage(language ILanguage)

		// GetLanguage returns language instance
		GetLanguage() ILanguage

		// Execute executes handler function and send output
		Execute(HandlerFunc)

		// Reset resets the context after request completes. It must be called along
		// with `Engine#AcquireContext()` and `Engine#ReleaseContext()`.
		// See `Engine#ServeHTTP()`
		Reset(r *http.Request, w http.ResponseWriter)
	}

	// IIdentity identity interface
	IIdentity interface {
		GetId() uint
		GetSiteEntityId() uint
		GetEmail() string
		GetName() string
		GetSurname() string
		GetDisplayName() string
		GetLocale() string
		GetType() string
		IsLoggedIn() bool
	}

	// ISite site interface
	ISite interface {
		GetId() uint
		GetName() string
		GetDomainUrl() string
	}

	context struct {
		request        *http.Request
		response       *Response
		responseFormat ResponseFormat
		path           string
		pnames         []string
		pvalues        []string
		query          url.Values
		handler        HandlerFunc
		store          H
		engine         *Engine
		logger         Logger
		flash          *Flash
		identity       IIdentity
		site           ISite
		language       ILanguage
		lock           sync.RWMutex
	}
)

const (
	// ContextKeyHeaderAllow is set by Router for getting value for `Allow` header in later stages of handler call chain.
	// Allow header is mandatory for status 405 (method not found) and useful for OPTIONS method requests.
	// It is added to context only when Router does not find matching method handler for request.
	ContextKeyHeaderAllow = "echo_header_allow"
)

const (
	defaultMemory = 32 << 20 // 32 MB
	indexPage     = "index.html"
	defaultIndent = "  "
)

func (c *context) writeContentType(value string) {
	header := c.Response().Header()
	if header.Get(HeaderContentType) == "" {
		header.Set(HeaderContentType, value)
	}
}

func (c *context) Request() *http.Request {
	return c.request
}

func (c *context) SetRequest(r *http.Request) {
	c.request = r
}

func (c *context) Response() *Response {
	return c.response
}

func (c *context) SetResponse(r *Response) {
	c.response = r
}

func (c *context) SetResponseFormat(format ResponseFormat) {
	c.responseFormat = format
}

func (c *context) IsTLS() bool {
	return c.request.TLS != nil
}

func (c *context) IsWebSocket() bool {
	upgrade := c.request.Header.Get(HeaderUpgrade)
	return strings.EqualFold(upgrade, "websocket")
}

func (c *context) Scheme() string {
	// Can't use `r.Request.URL.Scheme`
	// See: https://groups.google.com/forum/#!topic/golang-nuts/pMUkBlQBDF0
	if c.IsTLS() {
		return "https"
	}
	if scheme := c.request.Header.Get(HeaderXForwardedProto); scheme != "" {
		return scheme
	}
	if scheme := c.request.Header.Get(HeaderXForwardedProtocol); scheme != "" {
		return scheme
	}
	if ssl := c.request.Header.Get(HeaderXForwardedSsl); ssl == "on" {
		return "https"
	}
	if scheme := c.request.Header.Get(HeaderXUrlScheme); scheme != "" {
		return scheme
	}
	return "engine"
}

func (c *context) RealIP() string {
	if c.engine != nil && c.engine.IPExtractor != nil {
		return c.engine.IPExtractor(c.request)
	}
	// Fall back to legacy behavior
	if ip := c.request.Header.Get(HeaderXForwardedFor); ip != "" {
		i := strings.IndexAny(ip, ",")
		if i > 0 {
			return strings.TrimSpace(ip[:i])
		}
		return ip
	}
	if ip := c.request.Header.Get(HeaderXRealIP); ip != "" {
		return ip
	}
	ra, _, _ := net.SplitHostPort(c.request.RemoteAddr)
	return ra
}

func (c *context) Path() string {
	return c.path
}

func (c *context) SetPath(p string) {
	c.path = p
}

func (c *context) Param(name string) string {
	for i, n := range c.pnames {
		if i < len(c.pvalues) {
			if n == name {
				return c.pvalues[i]
			}
		}
	}
	return ""
}

func (c *context) ParamNames() []string {
	return c.pnames
}

func (c *context) SetParamNames(names ...string) {
	c.pnames = names

	l := len(names)
	if *c.engine.maxParam < l {
		*c.engine.maxParam = l
	}

	if len(c.pvalues) < l {
		// Keeping the old pvalues just for backward compatibility, but it sounds that doesn't make sense to keep them,
		// probably those values will be overriden in a Context#SetParamValues
		newPvalues := make([]string, l)
		copy(newPvalues, c.pvalues)
		c.pvalues = newPvalues
	}
}

func (c *context) ParamValues() []string {
	return c.pvalues[:len(c.pnames)]
}

func (c *context) SetParamValues(values ...string) {
	// NOTE: Don't just set c.pvalues = values, because it has to have length c.engine.maxParam at all times
	// It will brake the Router#Find Code
	limit := len(values)
	if limit > *c.engine.maxParam {
		limit = *c.engine.maxParam
	}
	for i := 0; i < limit; i++ {
		c.pvalues[i] = values[i]
	}
}

func (c *context) QueryParam(name string) string {
	if c.query == nil {
		c.query = c.request.URL.Query()
	}
	return c.query.Get(name)
}

func (c *context) QueryParams() url.Values {
	if c.query == nil {
		c.query = c.request.URL.Query()
	}
	return c.query
}

func (c *context) QueryString() string {
	return c.request.URL.RawQuery
}

func (c *context) FormValue(name string) string {
	return c.request.FormValue(name)
}

func (c *context) FormParams() (url.Values, error) {
	if strings.HasPrefix(c.request.Header.Get(HeaderContentType), MIMEMultipartForm) {
		if err := c.request.ParseMultipartForm(defaultMemory); err != nil {
			return nil, err
		}
	} else {
		if err := c.request.ParseForm(); err != nil {
			return nil, err
		}
	}
	return c.request.Form, nil
}

func (c *context) FormFile(name string) (*multipart.FileHeader, error) {
	f, fh, err := c.request.FormFile(name)
	if err != nil {
		return nil, err
	}
	f.Close()
	return fh, nil
}

func (c *context) MultipartForm() (*multipart.Form, error) {
	err := c.request.ParseMultipartForm(defaultMemory)
	return c.request.MultipartForm, err
}

func (c *context) Cookie(name string) (*http.Cookie, error) {
	return c.request.Cookie(name)
}

func (c *context) SetCookie(cookie *http.Cookie) {
	http.SetCookie(c.Response(), cookie)
}

func (c *context) Cookies() []*http.Cookie {
	return c.request.Cookies()
}

func (c *context) Get(key string) interface{} {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.store[key]
}

func (c *context) Set(key string, val interface{}) {
	c.lock.Lock()
	defer c.lock.Unlock()

	if c.store == nil {
		c.store = make(H)
	}
	c.store[key] = val
}

func (c *context) Bind(i interface{}) error {
	return c.engine.Binder.Bind(i, c)
}

func (c *context) Validate(i interface{}) error {
	if c.engine.Validator == nil {
		return ErrValidatorNotRegistered
	}
	return c.engine.Validator.Validate(i)
}

func (c *context) Render(code int, name string, data interface{}) (err error) {
	if c.engine.Renderer == nil {
		return ErrRendererNotRegistered
	}
	buf := new(bytes.Buffer)
	if err = c.engine.Renderer.Render(buf, name, data, c); err != nil {
		return
	}
	return c.HTMLBlob(code, buf.Bytes())
}

func (c *context) HTML(code int, html string) (err error) {
	return c.HTMLBlob(code, []byte(html))
}

func (c *context) HTMLBlob(code int, b []byte) (err error) {
	return c.Blob(code, MIMETextHTMLCharsetUTF8, b)
}

func (c *context) String(code int, s string) (err error) {
	return c.Blob(code, MIMETextPlainCharsetUTF8, []byte(s))
}

func (c *context) jsonPBlob(code int, callback string, i interface{}) (err error) {
	indent := ""
	if _, pretty := c.QueryParams()["pretty"]; c.engine.Debug || pretty {
		indent = defaultIndent
	}
	c.writeContentType(MIMEApplicationJavaScriptCharsetUTF8)
	c.response.WriteHeader(code)
	if _, err = c.response.Write([]byte(callback + "(")); err != nil {
		return
	}
	if err = c.engine.JSONSerializer.Serialize(c, i, indent); err != nil {
		return
	}
	if _, err = c.response.Write([]byte(");")); err != nil {
		return
	}
	return
}

func (c *context) json(code int, i interface{}, indent string) error {
	c.writeContentType(MIMEApplicationJSONCharsetUTF8)
	c.response.Status = code
	return c.engine.JSONSerializer.Serialize(c, i, indent)
}

func (c *context) JSON(code int, i interface{}) (err error) {
	indent := ""
	if _, pretty := c.QueryParams()["pretty"]; c.engine.Debug || pretty {
		indent = defaultIndent
	}
	return c.json(code, i, indent)
}

// JsonResponse send JSON response with default 200 status
func (c *context) JsonResponse(i interface{}) error {
	return c.JSON(http.StatusOK, i)
}

func (c *context) JSONPretty(code int, i interface{}, indent string) (err error) {
	return c.json(code, i, indent)
}

func (c *context) JSONBlob(code int, b []byte) (err error) {
	return c.Blob(code, MIMEApplicationJSONCharsetUTF8, b)
}

func (c *context) JSONP(code int, callback string, i interface{}) (err error) {
	return c.jsonPBlob(code, callback, i)
}

func (c *context) JSONPBlob(code int, callback string, b []byte) (err error) {
	c.writeContentType(MIMEApplicationJavaScriptCharsetUTF8)
	c.response.WriteHeader(code)
	if _, err = c.response.Write([]byte(callback + "(")); err != nil {
		return
	}
	if _, err = c.response.Write(b); err != nil {
		return
	}
	_, err = c.response.Write([]byte(");"))
	return
}

func (c *context) xml(code int, i interface{}, indent string) (err error) {
	c.writeContentType(MIMEApplicationXMLCharsetUTF8)
	c.response.WriteHeader(code)
	enc := xml.NewEncoder(c.response)
	if indent != "" {
		enc.Indent("", indent)
	}
	if _, err = c.response.Write([]byte(xml.Header)); err != nil {
		return
	}
	return enc.Encode(i)
}

func (c *context) XML(code int, i interface{}) (err error) {
	indent := ""
	if _, pretty := c.QueryParams()["pretty"]; c.engine.Debug || pretty {
		indent = defaultIndent
	}
	return c.xml(code, i, indent)
}

func (c *context) XMLPretty(code int, i interface{}, indent string) (err error) {
	return c.xml(code, i, indent)
}

func (c *context) XMLBlob(code int, b []byte) (err error) {
	c.writeContentType(MIMEApplicationXMLCharsetUTF8)
	c.response.WriteHeader(code)
	if _, err = c.response.Write([]byte(xml.Header)); err != nil {
		return
	}
	_, err = c.response.Write(b)
	return
}

func (c *context) Blob(code int, contentType string, b []byte) (err error) {
	c.writeContentType(contentType)
	c.response.WriteHeader(code)
	_, err = c.response.Write(b)
	return
}

func (c *context) Stream(code int, contentType string, r io.Reader) (err error) {
	c.writeContentType(contentType)
	c.response.WriteHeader(code)
	_, err = io.Copy(c.response, r)
	return
}

func (c *context) NoContent(code int) error {
	c.response.WriteHeader(code)
	return nil
}

func (c *context) Redirect(code int, url string) error {
	if code < 300 || code > 308 {
		return ErrInvalidRedirectCode
	}
	c.response.Header().Set(HeaderLocation, url)
	c.response.WriteHeader(code)
	return nil
}

func (c *context) Engine() *Engine {
	return c.engine
}

func (c *context) Handler() HandlerFunc {
	return c.handler
}

func (c *context) SetHandler(h HandlerFunc) {
	c.handler = h
}

func (c *context) Logger() Logger {
	res := c.logger
	if res != nil {
		return res
	}
	return c.engine.Logger
}

func (c *context) SetLogger(l Logger) {
	c.logger = l
}

func (c *context) Flash() *Flash {
	return c.flash
}

// SwitchIdentity switch identity
func (c *context) SwitchIdentity(identity IIdentity) {
	c.identity = identity
}

// GetIdentity returns identity instance
func (c *context) GetIdentity() IIdentity {
	return c.identity
}

// SwitchSite switch site
func (c *context) SwitchSite(site ISite) {
	c.site = site
}

// GetSite returns site instance
func (c *context) GetSite() ISite {
	return c.site
}

// SwitchLanguage switch language
func (c *context) SwitchLanguage(language ILanguage) {
	c.language = language
}

// GetLanguage returns language
func (c *context) GetLanguage() ILanguage {
	return c.language
}

func (c *context) Reset(r *http.Request, w http.ResponseWriter) {
	c.request = r
	c.response.reset(w)
	c.responseFormat = ResponseFormatJson
	c.query = nil
	c.handler = NotFoundHandler
	c.store = nil
	c.path = ""
	c.pnames = nil
	c.logger = nil
	c.flash = NewFlash()
	c.site = nil
	c.identity = nil
	c.language = Language{
		Locale: "en", Code: "en-US", Name: "English (US)",
	}
	// NOTE: Don't reset because it has to have length c.engine.maxParam at all times
	for i := 0; i < *c.engine.maxParam; i++ {
		c.pvalues[i] = ""
	}
}

func (c *context) Execute(handler HandlerFunc) {
	result := handler(c)
	if c.response.Committed {
		return
	}

	var isErrorResponse = false
	var err interface{}

	switch result.(type) {
	case error:
		isErrorResponse = true
		break
	}

	// call error handler
	if isErrorResponse {
		c.Engine().HTTPErrorHandler(result.(error), c)
	}

	// render result with format
	statusCode := c.Response().Status
	switch c.responseFormat {
	case ResponseFormatJson:
		err = c.JSON(statusCode, result)
		break
	case ResponseFormatString:
		err = c.String(statusCode, fmt.Sprintf("%v", result))
		break
	case ResponseFormatHtml:
		err = c.HTML(statusCode, fmt.Sprintf("%v", result))
		break
	default:
		err = c.JSON(statusCode, result)
		break
	}

	if err != nil {
		println(fmt.Sprintf("%v", err))
	}
}
