package main

import (
	"github.com/go-trip/web-engine/app"
	"github.com/go-trip/web-engine/engine"
	"github.com/go-trip/web-engine/engine/middleware"
	"golang.org/x/crypto/acme/autocert"
)

func main() {
	e := engine.New()
	e.AutoTLSManager.Cache = autocert.DirCache(".cache")
	e.HTTPErrorHandler = app.HttpErrorHandler
	e.JSONSerializer = app.ResponseSerializer{}

	e.Use(middleware.Recover())
	e.Use(middleware.CORSWithConfig(middleware.DefaultCORSConfig))

	e.GET("/", func(ctx engine.Context) interface{} {
		return "Home page"
	})

	e.GET("/user/:name", func(ctx engine.Context) interface{} {
		return "Hello " + ctx.Param("name")
	})

	e.Logger.Fatal(e.StartAutoTLS("0.0.0.0:443"))
}
