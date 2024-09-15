package engine

import (
	"bytes"
	stdContext "context"
	"crypto/tls"
	"errors"
	"fmt"
	"golang.org/x/crypto/acme"
	"io"
	"io/ioutil"
	stdLog "log"
	"net"
	"net/http"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/go-trip/web-engine/engine/color"
	"github.com/go-trip/web-engine/engine/log"
	"golang.org/x/crypto/acme/autocert"
)

type (
	// Engine is the top-level framework instance.
	Engine struct {
		filesystem
		common
		// startupMutex is mutex to lock Engine instance access during server configuration and startup. Useful for to get
		// listener address info (on which interface/port was listener binded) without having messages races.
		startupMutex     sync.RWMutex
		StdLogger        *stdLog.Logger
		colorer          *color.Color
		premiddleware    []MiddlewareFunc
		middleware       []MiddlewareFunc
		maxParam         *int
		router           *Router
		routers          map[string]*Router
		pool             sync.Pool
		Server           *http.Server
		TLSServer        *http.Server
		Listener         net.Listener
		TLSListener      net.Listener
		AutoTLSManager   autocert.Manager
		DisableHTTP2     bool
		Debug            bool
		HideBanner       bool
		HidePort         bool
		HTTPErrorHandler HTTPErrorHandler
		Binder           Binder
		JSONSerializer   JSONSerializer
		Validator        Validator
		Renderer         Renderer
		Logger           Logger
		IPExtractor      IPExtractor
		ListenerNetwork  string
	}

	// Route contains a handler and information for matching against requests.
	Route struct {
		Method string `json:"method"`
		Path   string `json:"path"`
		Name   string `json:"Name"`
	}

	// HTTPError represents an error that occurred while handling a request.
	HTTPError struct {
		Code     int         `json:"code"`
		Type     string      `json:"type"`
		Message  interface{} `json:"message"`
		Internal error       `json:"-"` // Stores the error returned by an external dependency
	}

	// MiddlewareFunc defines a function to process middleware.
	MiddlewareFunc func(next HandlerFunc) HandlerFunc

	// HandlerFunc defines a function to serve HTTP requests.
	HandlerFunc func(ctx Context) interface{}

	// HTTPErrorHandler is a centralized HTTP error handler.
	HTTPErrorHandler func(error, Context)

	// Validator is the interface that wraps the Validate function.
	Validator interface {
		Validate(i interface{}) error
	}

	// JSONSerializer is the interface that encodes and decodes JSON to and from interfaces.
	JSONSerializer interface {
		Serialize(c Context, i interface{}, indent string) error
		Deserialize(c Context, i interface{}) error
	}

	// Renderer is the interface that wraps the Render function.
	Renderer interface {
		Render(io.Writer, string, interface{}, Context) error
	}

	// H defines a generic map of type `map[string]interface{}`.
	H map[string]interface{}

	// Common struct for Engine & Group.
	common struct{}
)

// HTTP methods
// NOTE: Deprecated, please use the stdlib constants directly instead.
const (
	CONNECT = http.MethodConnect
	DELETE  = http.MethodDelete
	GET     = http.MethodGet
	HEAD    = http.MethodHead
	OPTIONS = http.MethodOptions
	PATCH   = http.MethodPatch
	POST    = http.MethodPost
	PUT     = http.MethodPut
	TRACE   = http.MethodTrace
)

// MIME types
const (
	MIMEApplicationJSON                  = "application/json"
	MIMEApplicationJSONCharsetUTF8       = MIMEApplicationJSON + "; " + charsetUTF8
	MIMEApplicationJavaScript            = "application/javascript"
	MIMEApplicationJavaScriptCharsetUTF8 = MIMEApplicationJavaScript + "; " + charsetUTF8
	MIMEApplicationXML                   = "application/xml"
	MIMEApplicationXMLCharsetUTF8        = MIMEApplicationXML + "; " + charsetUTF8
	MIMETextXML                          = "text/xml"
	MIMETextXMLCharsetUTF8               = MIMETextXML + "; " + charsetUTF8
	MIMEApplicationForm                  = "application/x-www-form-urlencoded"
	MIMEApplicationProtobuf              = "application/protobuf"
	MIMEApplicationMsgpack               = "application/msgpack"
	MIMETextHTML                         = "text/html"
	MIMETextHTMLCharsetUTF8              = MIMETextHTML + "; " + charsetUTF8
	MIMETextPlain                        = "text/plain"
	MIMETextPlainCharsetUTF8             = MIMETextPlain + "; " + charsetUTF8
	MIMEMultipartForm                    = "multipart/form-messages"
	MIMEOctetStream                      = "application/octet-stream"
)

const (
	charsetUTF8 = "charset=UTF-8"
	// PROPFIND Method can be used on collection and property resources.
	PROPFIND = "PROPFIND"
	// REPORT Method can be used to get information about a resource, see rfc 3253
	REPORT = "REPORT"
)

// Headers
const (
	HeaderAccept         = "Accept"
	HeaderAcceptEncoding = "Accept-Encoding"
	// HeaderAllow is the Name of the "Allow" header field used to list the set of methods
	// advertised as supported by the target resource. Returning an Allow header is mandatory
	// for status 405 (method not found) and useful for the OPTIONS method in responses.
	// See RFC 7231: https://datatracker.ietf.org/doc/html/rfc7231#section-7.4.1
	HeaderAllow               = "Allow"
	HeaderAuthorization       = "Authorization"
	HeaderContentDisposition  = "Content-Disposition"
	HeaderContentEncoding     = "Content-Encoding"
	HeaderContentLength       = "Content-Length"
	HeaderContentType         = "Content-Type"
	HeaderCookie              = "Cookie"
	HeaderSetCookie           = "Set-Cookie"
	HeaderIfModifiedSince     = "If-Modified-Since"
	HeaderLastModified        = "Last-Modified"
	HeaderLocation            = "Location"
	HeaderRetryAfter          = "Retry-After"
	HeaderUpgrade             = "Upgrade"
	HeaderVary                = "Vary"
	HeaderWWWAuthenticate     = "WWW-Authenticate"
	HeaderXForwardedFor       = "X-Forwarded-For"
	HeaderXForwardedProto     = "X-Forwarded-Proto"
	HeaderXForwardedProtocol  = "X-Forwarded-Protocol"
	HeaderXForwardedSsl       = "X-Forwarded-Ssl"
	HeaderXUrlScheme          = "X-Url-Scheme"
	HeaderXHTTPMethodOverride = "X-HTTP-Method-Override"
	HeaderXRealIP             = "X-Real-Ip"
	HeaderXRequestID          = "X-Request-Id"
	HeaderXCorrelationID      = "X-Correlation-Id"
	HeaderXRequestedWith      = "X-Requested-Base"
	HeaderServer              = "Server"
	HeaderOrigin              = "Origin"
	HeaderCacheControl        = "Cache-Control"
	HeaderConnection          = "Connection"

	// Access control
	HeaderAccessControlRequestMethod    = "Access-Control-Request-Method"
	HeaderAccessControlRequestHeaders   = "Access-Control-Request-Headers"
	HeaderAccessControlAllowOrigin      = "Access-Control-Allow-Origin"
	HeaderAccessControlAllowMethods     = "Access-Control-Allow-Methods"
	HeaderAccessControlAllowHeaders     = "Access-Control-Allow-Headers"
	HeaderAccessControlAllowCredentials = "Access-Control-Allow-Credentials"
	HeaderAccessControlExposeHeaders    = "Access-Control-Expose-Headers"
	HeaderAccessControlMaxAge           = "Access-Control-Max-Age"

	// Security
	HeaderStrictTransportSecurity         = "Strict-Transport-Security"
	HeaderXContentTypeOptions             = "X-Content-Type-Options"
	HeaderXXSSProtection                  = "X-XSS-Protection"
	HeaderXFrameOptions                   = "X-Frame-Options"
	HeaderContentSecurityPolicy           = "Content-Security-Policy"
	HeaderContentSecurityPolicyReportOnly = "Content-Security-Policy-Report-Only"
	HeaderXCSRFToken                      = "X-CSRF-Token"
	HeaderReferrerPolicy                  = "Referrer-Policy"
)

var (
	methods = [...]string{
		http.MethodConnect,
		http.MethodDelete,
		http.MethodGet,
		http.MethodHead,
		http.MethodOptions,
		http.MethodPatch,
		http.MethodPost,
		PROPFIND,
		http.MethodPut,
		http.MethodTrace,
		REPORT,
	}
)

// Errors
var (
	ErrUnsupportedMediaType        = NewHTTPError(http.StatusUnsupportedMediaType)
	ErrNotFound                    = NewHTTPError(http.StatusNotFound, "Requested url not is invalid or not exists.")
	ErrUnauthorized                = NewHTTPError(http.StatusUnauthorized)
	ErrForbidden                   = NewHTTPError(http.StatusForbidden)
	ErrMethodNotAllowed            = NewHTTPError(http.StatusMethodNotAllowed)
	ErrStatusRequestEntityTooLarge = NewHTTPError(http.StatusRequestEntityTooLarge)
	ErrTooManyRequests             = NewHTTPError(http.StatusTooManyRequests)
	ErrBadRequest                  = NewHTTPError(http.StatusBadRequest)
	ErrBadGateway                  = NewHTTPError(http.StatusBadGateway)
	ErrInternalServerError         = NewHTTPError(http.StatusInternalServerError)
	ErrRequestTimeout              = NewHTTPError(http.StatusRequestTimeout)
	ErrServiceUnavailable          = NewHTTPError(http.StatusServiceUnavailable)
	ErrValidatorNotRegistered      = errors.New("validator not registered")
	ErrRendererNotRegistered       = errors.New("renderer not registered")
	ErrInvalidRedirectCode         = errors.New("invalid redirect status Code")
	ErrCookieNotFound              = errors.New("cookie not found")
	ErrInvalidCertOrKeyType        = errors.New("invalid cert or key type, must be string or []byte")
	ErrInvalidListenerNetwork      = errors.New("invalid listener network")
)

// Error handlers
var (
	NotFoundHandler = func(c Context) interface{} {
		return ErrNotFound
	}

	MethodNotAllowedHandler = func(c Context) interface{} {
		// See RFC 7231 section 7.4.1: An origin server MUST generate an Allow field in a 405 (Method Not Allowed)
		// response and MAY do so in any other response. For disabled resources an empty Allow header may be returned
		routerAllowMethods, ok := c.Get(ContextKeyHeaderAllow).(string)
		if ok && routerAllowMethods != "" {
			c.Response().Header().Set(HeaderAllow, routerAllowMethods)
		}

		return ErrMethodNotAllowed
	}
)

// New creates an instance of Engine.
func New() (e *Engine) {
	e = &Engine{
		filesystem: createFilesystem(),
		Server:     new(http.Server),
		TLSServer:  new(http.Server),
		AutoTLSManager: autocert.Manager{
			Prompt: autocert.AcceptTOS,
		},
		Logger:          log.New("engine"),
		colorer:         color.New(),
		maxParam:        new(int),
		ListenerNetwork: "tcp",
	}
	e.Server.Handler = e
	e.TLSServer.Handler = e
	e.HTTPErrorHandler = e.DefaultHTTPErrorHandler
	e.Binder = &DefaultBinder{}
	e.JSONSerializer = &DefaultJSONSerializer{}
	e.Logger.SetLevel(log.ERROR)
	e.StdLogger = stdLog.New(e.Logger.Output(), e.Logger.Prefix()+": ", 0)
	e.pool.New = func() interface{} {
		return e.NewContext(nil, nil)
	}
	e.router = NewRouter(e)
	e.routers = map[string]*Router{}
	return
}

// NewContext returns a Context instance.
func (e *Engine) NewContext(r *http.Request, w http.ResponseWriter) Context {
	return &context{
		request:  r,
		response: NewResponse(w, e),
		store:    make(H),
		engine:   e,
		pvalues:  make([]string, *e.maxParam),
		handler:  NotFoundHandler,
	}
}

// Router returns the default router.
func (e *Engine) Router() *Router {
	return e.router
}

// Routers returns the map of host => router.
func (e *Engine) Routers() map[string]*Router {
	return e.routers
}

// DefaultHTTPErrorHandler is the default HTTP error handler. It sends a JSON response
// with status Code.
//
// NOTE: In case errors happens in middleware call-chain that is returning from handler (which did not return an error).
// When handler has already sent response (ala c.JSON()) and there is error in middleware that is returning from
// handler. Then the error that global error handler received will be ignored because we have already "commited" the
// response and status Code header has been sent to the client.
func (e *Engine) DefaultHTTPErrorHandler(err error, c Context) {
	println("DefaultHTTPErrorHandler")
	if c.Response().Committed {
		return
	}

	he, ok := err.(*HTTPError)
	if ok {
		if he.Internal != nil {
			if herr, ok := he.Internal.(*HTTPError); ok {
				he = herr
			}
		}
	} else {
		he = &HTTPError{
			Code:    http.StatusInternalServerError,
			Message: http.StatusText(http.StatusInternalServerError),
		}
	}

	// Issue #1426
	code := he.Code
	message := he.Message
	if m, ok := he.Message.(string); ok {
		if e.Debug {
			message = H{"message": m, "error": err.Error()}
		} else {
			message = H{"message": m}
		}
	}

	// Send response
	if c.Request().Method == http.MethodHead { // Issue #608
		err = c.NoContent(he.Code)
	} else {
		err = c.JSON(code, message)
	}
	if err != nil {
		e.Logger.Error(err)
	}
}

// Pre adds middleware to the chain which is run before router.
func (e *Engine) Pre(middleware ...MiddlewareFunc) {
	e.premiddleware = append(e.premiddleware, middleware...)
}

// Use adds middleware to the chain which is run after router.
func (e *Engine) Use(middleware ...MiddlewareFunc) {
	e.middleware = append(e.middleware, middleware...)
}

// CONNECT registers a new CONNECT route for a path with matching handler in the
// router with optional route-level middleware.
func (e *Engine) CONNECT(path string, h HandlerFunc, m ...MiddlewareFunc) *Route {
	return e.Add(http.MethodConnect, path, h, m...)
}

// DELETE registers a new DELETE route for a path with matching handler in the router
// with optional route-level middleware.
func (e *Engine) DELETE(path string, h HandlerFunc, m ...MiddlewareFunc) *Route {
	return e.Add(http.MethodDelete, path, h, m...)
}

// GET registers a new GET route for a path with matching handler in the router
// with optional route-level middleware.
func (e *Engine) GET(path string, h HandlerFunc, m ...MiddlewareFunc) *Route {
	return e.Add(http.MethodGet, path, h, m...)
}

// HEAD registers a new HEAD route for a path with matching handler in the
// router with optional route-level middleware.
func (e *Engine) HEAD(path string, h HandlerFunc, m ...MiddlewareFunc) *Route {
	return e.Add(http.MethodHead, path, h, m...)
}

// OPTIONS registers a new OPTIONS route for a path with matching handler in the
// router with optional route-level middleware.
func (e *Engine) OPTIONS(path string, h HandlerFunc, m ...MiddlewareFunc) *Route {
	return e.Add(http.MethodOptions, path, h, m...)
}

// PATCH registers a new PATCH route for a path with matching handler in the
// router with optional route-level middleware.
func (e *Engine) PATCH(path string, h HandlerFunc, m ...MiddlewareFunc) *Route {
	return e.Add(http.MethodPatch, path, h, m...)
}

// POST registers a new POST route for a path with matching handler in the
// router with optional route-level middleware.
func (e *Engine) POST(path string, h HandlerFunc, m ...MiddlewareFunc) *Route {
	return e.Add(http.MethodPost, path, h, m...)
}

// PUT registers a new PUT route for a path with matching handler in the
// router with optional route-level middleware.
func (e *Engine) PUT(path string, h HandlerFunc, m ...MiddlewareFunc) *Route {
	return e.Add(http.MethodPut, path, h, m...)
}

// TRACE registers a new TRACE route for a path with matching handler in the
// router with optional route-level middleware.
func (e *Engine) TRACE(path string, h HandlerFunc, m ...MiddlewareFunc) *Route {
	return e.Add(http.MethodTrace, path, h, m...)
}

// Any registers a new route for all HTTP methods and path with matching handler
// in the router with optional route-level middleware.
func (e *Engine) Any(path string, handler HandlerFunc, middleware ...MiddlewareFunc) []*Route {
	routes := make([]*Route, len(methods))
	for i, m := range methods {
		routes[i] = e.Add(m, path, handler, middleware...)
	}
	return routes
}

// Match registers a new route for multiple HTTP methods and path with matching
// handler in the router with optional route-level middleware.
func (e *Engine) Match(methods []string, path string, handler HandlerFunc, middleware ...MiddlewareFunc) []*Route {
	routes := make([]*Route, len(methods))
	for i, m := range methods {
		routes[i] = e.Add(m, path, handler, middleware...)
	}
	return routes
}

func (e *Engine) add(host, method, path string, handler HandlerFunc, middleware ...MiddlewareFunc) *Route {
	path = trimTrailingSlash(path)
	name := handlerName(handler)
	router := e.findRouter(host)
	router.Add(method, path, func(c Context) interface{} {
		h := applyMiddleware(handler, middleware...)
		return h(c)
	})

	r := &Route{
		Method: method,
		Path:   path,
		Name:   name,
	}
	e.router.routes[method+path] = r
	return r
}

// Add registers a new route for an HTTP method and path with matching handler
// in the router with optional route-level middleware.
func (e *Engine) Add(method, path string, handler HandlerFunc, middleware ...MiddlewareFunc) *Route {
	return e.add("", method, path, handler, middleware...)
}

// Host creates a new router group for the provided host and optional host-level middleware.
func (e *Engine) Host(name string, m ...MiddlewareFunc) (g *Group) {
	e.routers[name] = NewRouter(e)
	g = &Group{host: name, engine: e}
	g.Use(m...)
	return
}

// Group creates a new router group with prefix and optional group-level middleware.
func (e *Engine) Group(prefix string, m ...MiddlewareFunc) (g *Group) {
	g = &Group{prefix: prefix, engine: e}
	g.Use(m...)
	return
}

// URI generates a URI from handler.
func (e *Engine) URI(handler HandlerFunc, params ...interface{}) string {
	name := handlerName(handler)
	return e.Reverse(name, params...)
}

// URL is an alias for `URI` function.
func (e *Engine) URL(h HandlerFunc, params ...interface{}) string {
	return e.URI(h, params...)
}

// Reverse generates an URL from route Name and provided parameters.
func (e *Engine) Reverse(name string, params ...interface{}) string {
	uri := new(bytes.Buffer)
	ln := len(params)
	n := 0
	for _, r := range e.router.routes {
		if r.Name == name {
			for i, l := 0, len(r.Path); i < l; i++ {
				if (r.Path[i] == ':' || r.Path[i] == '*') && n < ln {
					for ; i < l && r.Path[i] != '/'; i++ {
					}
					uri.WriteString(fmt.Sprintf("%v", params[n]))
					n++
				}
				if i < l {
					uri.WriteByte(r.Path[i])
				}
			}
			break
		}
	}
	return uri.String()
}

// Routes returns the registered routes.
func (e *Engine) Routes() []*Route {
	routes := make([]*Route, 0, len(e.router.routes))
	for _, v := range e.router.routes {
		routes = append(routes, v)
	}
	return routes
}

// AcquireContext returns an empty `Context` instance from the pool.
// You must return the context by calling `ReleaseContext()`.
func (e *Engine) AcquireContext() Context {
	return e.pool.Get().(Context)
}

// ReleaseContext returns the `Context` instance back to the pool.
// You must call it after `AcquireContext()`.
func (e *Engine) ReleaseContext(c Context) {
	e.pool.Put(c)
}

// ServeHTTP implements `http.Handler` interface, which serves HTTP requests.
func (e *Engine) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Acquire context
	c := e.pool.Get().(*context)
	c.Reset(r, w)
	var h func(Context) interface{}

	path := trimTrailingSlash(GetPath(r))
	path = strings.Replace(path, "//", "/", -1)
	if e.premiddleware == nil {
		e.findRouter(r.Host).Find(r.Method, path, c)
		h = c.Handler()
		h = applyMiddleware(h, e.middleware...)
	} else {
		h = func(c Context) interface{} {
			e.findRouter(r.Host).Find(r.Method, path, c)
			h := c.Handler()
			h = applyMiddleware(h, e.middleware...)
			return h(c)
		}
		h = applyMiddleware(h, e.premiddleware...)
	}

	// execute handler
	c.Execute(h)

	// Release context
	e.pool.Put(c)
}

// Start starts an HTTP server.
func (e *Engine) Start(address string) error {
	e.startupMutex.Lock()
	e.Server.Addr = address
	if err := e.configureServer(e.Server); err != nil {
		e.startupMutex.Unlock()
		return err
	}
	e.startupMutex.Unlock()
	return e.Server.Serve(e.Listener)
}

// StartTLS starts an HTTPS server.
// If `certFile` or `keyFile` is `string` the values are treated as file paths.
// If `certFile` or `keyFile` is `[]byte` the values are treated as the certificate or key as-is.
func (e *Engine) StartTLS(address string, certFile, keyFile interface{}) (err error) {
	e.startupMutex.Lock()
	var cert []byte
	if cert, err = filepathOrContent(certFile); err != nil {
		e.startupMutex.Unlock()
		return
	}

	var key []byte
	if key, err = filepathOrContent(keyFile); err != nil {
		e.startupMutex.Unlock()
		return
	}

	s := e.TLSServer
	s.TLSConfig = new(tls.Config)
	s.TLSConfig.Certificates = make([]tls.Certificate, 1)
	if s.TLSConfig.Certificates[0], err = tls.X509KeyPair(cert, key); err != nil {
		e.startupMutex.Unlock()
		return
	}

	e.configureTLS(address)
	if err := e.configureServer(s); err != nil {
		e.startupMutex.Unlock()
		return err
	}
	e.startupMutex.Unlock()
	return s.Serve(e.TLSListener)
}

func filepathOrContent(fileOrContent interface{}) (content []byte, err error) {
	switch v := fileOrContent.(type) {
	case string:
		return ioutil.ReadFile(v)
	case []byte:
		return v, nil
	default:
		return nil, ErrInvalidCertOrKeyType
	}
}

// StartAutoTLS starts an HTTPS server using certificates automatically installed from https://letsencrypt.org.
func (e *Engine) StartAutoTLS(address string) error {
	e.startupMutex.Lock()
	s := e.TLSServer
	s.TLSConfig = new(tls.Config)
	s.TLSConfig.GetCertificate = e.AutoTLSManager.GetCertificate
	s.TLSConfig.NextProtos = append(s.TLSConfig.NextProtos, acme.ALPNProto)

	e.configureTLS(address)
	if err := e.configureServer(s); err != nil {
		e.startupMutex.Unlock()
		return err
	}
	e.startupMutex.Unlock()
	return s.Serve(e.TLSListener)
}

func (e *Engine) configureTLS(address string) {
	s := e.TLSServer
	s.Addr = address
	if !e.DisableHTTP2 {
		s.TLSConfig.NextProtos = append(s.TLSConfig.NextProtos, "h2")
	}
}

// StartServer starts a custom engine server.
func (e *Engine) StartServer(s *http.Server) (err error) {
	e.startupMutex.Lock()
	if err := e.configureServer(s); err != nil {
		e.startupMutex.Unlock()
		return err
	}

	e.startupMutex.Unlock()
	return s.Serve(e.Listener)
}

// configureServer server
func (e *Engine) configureServer(s *http.Server) error {
	// Setup
	e.colorer.SetOutput(e.Logger.Output())
	s.ErrorLog = e.StdLogger
	s.Handler = e
	if e.Debug {
		e.Logger.SetLevel(log.DEBUG)
	}

	if !e.HideBanner {
		e.colorer.Printf(banner, e.colorer.Red(VERSION))
	}

	if s.TLSConfig == nil {
		if e.Listener == nil {
			l, err := newListener(s.Addr, e.ListenerNetwork)
			if err != nil {
				return err
			}
			e.Listener = l
		}
		if !e.HidePort {
			e.colorer.Printf("⇨ http server started on %s\n", e.colorer.Green(e.Listener.Addr()))
		}
		return nil
	}
	if e.TLSListener == nil {
		l, err := newListener(s.Addr, e.ListenerNetwork)
		if err != nil {
			return err
		}
		e.TLSListener = tls.NewListener(l, s.TLSConfig)
	}
	if !e.HidePort {
		e.colorer.Printf("⇨ https server started on %s\n", e.colorer.Green(e.TLSListener.Addr()))
	}

	return nil
}

// ListenerAddr returns net.Addr for Listener
func (e *Engine) ListenerAddr() net.Addr {
	e.startupMutex.RLock()
	defer e.startupMutex.RUnlock()
	if e.Listener == nil {
		return nil
	}
	return e.Listener.Addr()
}

// TLSListenerAddr returns net.Addr for TLSListener
func (e *Engine) TLSListenerAddr() net.Addr {
	e.startupMutex.RLock()
	defer e.startupMutex.RUnlock()
	if e.TLSListener == nil {
		return nil
	}
	return e.TLSListener.Addr()
}

// Close immediately stops the server.
// It internally calls `http.Server#Close()`.
func (e *Engine) Close() error {
	e.startupMutex.Lock()
	defer e.startupMutex.Unlock()
	return e.Server.Close()
}

// Shutdown stops the server gracefully.
// It internally calls `http.Server#Shutdown()`.
func (e *Engine) Shutdown(ctx stdContext.Context) error {
	e.startupMutex.Lock()
	defer e.startupMutex.Unlock()
	return e.Server.Shutdown(ctx)
}

// NewHTTPError creates a new HTTPError instance.
func NewHTTPError(code int, message ...interface{}) *HTTPError {
	messageText := http.StatusText(code)
	he := &HTTPError{
		Code:    code,
		Type:    strings.ToUpper(strings.Replace(messageText, " ", "_", -1)),
		Message: messageText,
	}
	if len(message) > 0 {
		he.Message = message[0]
	}
	return he
}

// HttpError creates a new HttpError instance.
func HttpError(errorType string, message interface{}, code ...int) *HTTPError {
	e := &HTTPError{Type: errorType, Message: message}
	if len(code) == 0 {
		e.Code = http.StatusNotAcceptable
	} else {
		e.Code = code[0]
	}
	return e
}

// Error makes it compatible with `error` interface.
func (he *HTTPError) Error() string {
	if he.Internal == nil {
		return fmt.Sprintf("Code=%d, message=%v", he.Code, he.Message)
	}
	return fmt.Sprintf("Code=%d, message=%v, internal=%v", he.Code, he.Message, he.Internal)
}

// SetInternal sets error to HTTPError.Internal
func (he *HTTPError) SetInternal(err error) *HTTPError {
	he.Internal = err
	return he
}

// Unwrap satisfies the Go 1.13 error wrapper interface.
func (he *HTTPError) Unwrap() error {
	return he.Internal
}

// WrapHandler wraps `http.Handler` into `engine.HandlerFunc`.
func WrapHandler(h http.Handler) HandlerFunc {
	return func(c Context) interface{} {
		h.ServeHTTP(c.Response(), c.Request())
		return nil
	}
}

// WrapMiddleware wraps `func(http.Handler) http.Handler` into `engine.MiddlewareFunc`
func WrapMiddleware(m func(http.Handler) http.Handler) MiddlewareFunc {
	return func(next HandlerFunc) HandlerFunc {
		return func(c Context) (i interface{}) {
			m(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				c.SetRequest(r)
				c.SetResponse(NewResponse(w, c.Engine()))
				i = next(c)
			})).ServeHTTP(c.Response(), c.Request())
			return
		}
	}
}

// GetPath returns RawPath, if it's empty returns Path from URL
// Difference between RawPath and Path is:
//   - Path is where request path is stored. Value is stored in decoded form: /%47%6f%2f becomes /Go/.
//   - RawPath is an optional field which only gets set if the default encoding is different from Path.
func GetPath(r *http.Request) string {
	path := r.URL.RawPath
	if path == "" {
		path = r.URL.Path
	}
	return path
}

func (e *Engine) findRouter(host string) *Router {
	if len(e.routers) > 0 {
		if r, ok := e.routers[host]; ok {
			return r
		}
	}
	return e.router
}

func handlerName(h HandlerFunc) string {
	t := reflect.ValueOf(h).Type()
	if t.Kind() == reflect.Func {
		return runtime.FuncForPC(reflect.ValueOf(h).Pointer()).Name()
	}
	return t.String()
}

// // PathUnescape is wraps `url.PathUnescape`
// func PathUnescape(s string) (string, error) {
// 	return url.PathUnescape(s)
// }

// tcpKeepAliveListener sets TCP keep-alive timeouts on accepted
// dead TCP connections (e.g. closing laptop mid-download) eventually
// go away.
type tcpKeepAliveListener struct {
	*net.TCPListener
}

func (ln tcpKeepAliveListener) Accept() (c net.Conn, err error) {
	if c, err = ln.AcceptTCP(); err != nil {
		return
	} else if err = c.(*net.TCPConn).SetKeepAlive(true); err != nil {
		return
	}
	// Ignore error from setting the KeepAlivePeriod as some systems, such as
	// OpenBSD, do not support setting TCP_USER_TIMEOUT on IPPROTO_TCP
	_ = c.(*net.TCPConn).SetKeepAlivePeriod(3 * time.Minute)
	return
}

func newListener(address, network string) (*tcpKeepAliveListener, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, ErrInvalidListenerNetwork
	}
	l, err := net.Listen(network, address)
	if err != nil {
		return nil, err
	}
	return &tcpKeepAliveListener{l.(*net.TCPListener)}, nil
}

func applyMiddleware(h HandlerFunc, middleware ...MiddlewareFunc) HandlerFunc {
	for i := len(middleware) - 1; i >= 0; i-- {
		h = middleware[i](h)
	}
	return h
}

func trimTrailingSlash(s string) string {
	if strings.HasSuffix(s, "/") {
		s = s[:len(s)-len("/")]
	}
	s = strings.Replace(s, "//", "/", -1)
	if s == "" {
		s = "/"
	}
	return s
}
