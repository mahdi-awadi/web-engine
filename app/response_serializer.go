package app

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-trip/web-engine/engine"
)

// ResponseSerializer implements JSON encoding using encoding/json.
type ResponseSerializer struct{}

// Serialize converts an interface into a json and writes it to the response.
// You can optionally use the indent parameter to produce pretty JSONs.
func (d ResponseSerializer) Serialize(c engine.Context, i interface{}, indent string) error {
	enc := json.NewEncoder(c.Response())
	if indent != "" {
		enc.SetIndent("", indent)
	}

	var response = engine.H{
		"statusCode": c.Response().Status,
	}

	if c.Response().IsHTTPError() {
		response["error"] = c.Response().GetHTTPError()
	} else {
		response["output"] = i
	}

	// set has error status and messages
	if c.Flash().HasMessage() {
		response["messages"] = c.Flash().Messages()
		c.Flash().Clear()
	}

	return enc.Encode(response)
}

// Deserialize reads a JSON from a request body and converts it into an interface.
func (d ResponseSerializer) Deserialize(c engine.Context, i interface{}) error {
	err := json.NewDecoder(c.Request().Body).Decode(i)
	if ute, ok := err.(*json.UnmarshalTypeError); ok {
		return engine.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Unmarshal type error: expected=%v, got=%v, field=%v, offset=%v", ute.Type, ute.Value, ute.Field, ute.Offset)).SetInternal(err)
	} else if se, ok := err.(*json.SyntaxError); ok {
		return engine.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Syntax error: offset=%v, error=%v", se.Offset, se.Error())).SetInternal(err)
	}
	return err
}
