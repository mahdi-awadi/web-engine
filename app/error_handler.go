package app

import (
	"github.com/go-trip/web-engine/engine"
	"net/http"
)

// HttpErrorHandler handle errors.
func HttpErrorHandler(err error, c engine.Context) {
	if c.Response().Committed {
		return
	}

	var errorType = "GENERAL"
	var he *engine.HTTPError
	switch err.(type) {
	case *engine.HTTPError:
		he = err.(*engine.HTTPError)

		if he.Type == "" {
			he.Type = errorType
		}
		break
	case error:
		he = &engine.HTTPError{
			Type:    errorType,
			Code:    http.StatusInternalServerError,
			Message: err.Error(),
		}
		break
	default:
		he = &engine.HTTPError{
			Type:    errorType,
			Code:    http.StatusInternalServerError,
			Message: http.StatusText(http.StatusInternalServerError),
		}
	}

	// set status code and response
	c.Response().Status = he.Code
	c.Response().SetHTTPError(he)

	// Send response
	if c.Request().Method == http.MethodHead { // Issue #608
		c.SetResponseFormat(engine.ResponseFormatNoContent)
		return
	}
}
