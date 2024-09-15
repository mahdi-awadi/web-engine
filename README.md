````
Web engine framework

 _______             _
(_______)           (_)
 _____   ____   ____ _ ____  _____
|  ___) |  _ \ / _  | |  _ \| ___ |
| |_____| | | ( (_| | | | | | ____|
|_______)_| |_|\___ |_|_| |_|_____)
              (_____|         vx.x.x

````
Web engine framework inspired by [Echo](https://echo.labstack.com/).

<br/>

#### Purpose:
The purpose of this framework is to provide a simple and easy to use web framework.

<br/>

#### Usage:
The framework is designed to be used as a singleton.

````
github.com/go-trip/
````

<br/>

#### Example:
```go
package main

import (
	"github.com/go-trip/web-engine/app"
	"github.com/go-trip/web-engine/engine"
	"github.com/go-trip/web-engine/engine/middleware"
)

func main() {
	e := engine.New()

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

	e.Logger.Fatal(e.Start("127.0.0.1:9596"))
}
```

<br/>
<br/>

#### Authors:
- [Ata amini](https://github.com/ata-amini)