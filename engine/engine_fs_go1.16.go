//go:build go1.16
// +build go1.16

package engine

import (
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

type filesystem struct {
	// Filesystem is file system used by Static and File handlers to access files.
	// Defaults to os.DirFS(".")
	//
	// When dealing with `embed.FS` use `fs := engine.MustSubFS(fs, "rootDirectory") to create sub fs which uses necessary
	// prefix for directory path. This is necessary as `//go:embed assets/images` embeds files with paths
	// including `assets/images` as their prefix.
	Filesystem fs.FS
}

func createFilesystem() filesystem {
	return filesystem{
		Filesystem: newDefaultFS(),
	}
}

// Static registers a new route with path prefix to serve static files from the provided root directory.
func (e *Engine) Static(pathPrefix, fsRoot string) *Route {
	subFs := MustSubFS(e.Filesystem, fsRoot)
	return e.Add(
		http.MethodGet,
		pathPrefix+"*",
		StaticDirectoryHandler(subFs, false),
	)
}

// StaticFS registers a new route with path prefix to serve static files from the provided file system.
//
// When dealing with `embed.FS` use `fs := engine.MustSubFS(fs, "rootDirectory") to create sub fs which uses necessary
// prefix for directory path. This is necessary as `//go:embed assets/images` embeds files with paths
// including `assets/images` as their prefix.
func (e *Engine) StaticFS(pathPrefix string, filesystem fs.FS) *Route {
	return e.Add(
		http.MethodGet,
		pathPrefix+"*",
		StaticDirectoryHandler(filesystem, false),
	)
}

func (common) file(path, file string, get func(string, HandlerFunc, ...MiddlewareFunc) *Route, m ...MiddlewareFunc) *Route {
	return get(path, func(ctx Context) interface{} {
		return ctx.File(file)
	}, m...)
}

// File registers a new route with path to serve a static file with optional route-level middleware.
func (e *Engine) File(path, file string, m ...MiddlewareFunc) *Route {
	return e.file(path, file, e.GET, m...)
}

// StaticDirectoryHandler creates handler function to serve files from provided file system
// When disablePathUnescaping is set then file name from path is not unescaped and is served as is.
func StaticDirectoryHandler(fileSystem fs.FS, disablePathUnescaping bool) HandlerFunc {
	return func(c Context) interface{} {
		p := c.Param("*")
		if !disablePathUnescaping { // when router is already unescaping we do not want to do is twice
			tmpPath, err := url.PathUnescape(p)
			if err != nil {
				return fmt.Errorf("failed to unescape path variable: %w", err)
			}
			p = tmpPath
		}

		// fs.FS.Open() already assumes that file names are relative to FS root path and considers name with prefix `/` as invalid
		name := filepath.ToSlash(filepath.Clean(strings.TrimPrefix(p, "/")))
		fi, err := fs.Stat(fileSystem, name)
		if err != nil {
			return ErrNotFound
		}

		// If the request is for a directory and does not end with "/"
		p = c.Request().URL.Path // path must not be empty.
		if fi.IsDir() && len(p) > 0 && p[len(p)-1] != '/' {
			// Redirect to ends with "/"
			return c.Redirect(http.StatusMovedPermanently, p+"/")
		}
		return fsFile(c, name, fileSystem)
	}
}

// FileFS registers a new route with path to serve file from the provided file system.
func (e *Engine) FileFS(path, file string, filesystem fs.FS, m ...MiddlewareFunc) *Route {
	return e.GET(path, StaticFileHandler(file, filesystem), m...)
}

// StaticFileHandler creates handler function to serve file from provided file system
func StaticFileHandler(file string, filesystem fs.FS) HandlerFunc {
	return func(c Context) interface{} {
		return fsFile(c, file, filesystem)
	}
}

// defaultFS exists to preserve pre v4.7.0 behaviour where files were open by `os.Open`.
// v4.7 introduced `engine.Filesystem` field which is Go1.16+ `fs.Fs` interface.
// Difference between `os.Open` and `fs.Open` is that FS does not allow opening path that start with `.`, `..` or `/`
// etc. For example previously you could have `../images` in your application but `fs := os.DirFS("./")` would not
// allow you to use `fs.Open("../images")` and this would break all old applications that rely on being able to
// traverse up from current executable run path.
// NB: private because you really should use fs.FS implementation instances
type defaultFS struct {
	prefix string
	fs     fs.FS
}

func newDefaultFS() *defaultFS {
	dir, _ := os.Getwd()
	return &defaultFS{
		prefix: dir,
		fs:     nil,
	}
}

func (fs defaultFS) Open(name string) (fs.File, error) {
	if fs.fs == nil {
		return os.Open(name)
	}
	return fs.fs.Open(name)
}

func subFS(currentFs fs.FS, root string) (fs.FS, error) {
	root = filepath.ToSlash(filepath.Clean(root)) // note: fs.FS operates only with slashes. `ToSlash` is necessary for Windows
	if dFS, ok := currentFs.(*defaultFS); ok {
		// we need to make exception for `defaultFS` instances as it interprets root prefix differently from fs.FS.
		// fs.Fs.Open does not like relative paths ("./", "../") and absolute paths at all but prior engine.Filesystem we
		// were able to use paths like `./myfile.log`, `/etc/hosts` and these would work fine with `os.Open` but not with fs.Fs
		if isRelativePath(root) {
			root = filepath.Join(dFS.prefix, root)
		}
		return &defaultFS{
			prefix: root,
			fs:     os.DirFS(root),
		}, nil
	}
	return fs.Sub(currentFs, root)
}

func isRelativePath(path string) bool {
	if path == "" {
		return true
	}
	if path[0] == '/' {
		return false
	}
	if runtime.GOOS == "windows" && strings.IndexByte(path, ':') != -1 {
		// https://docs.microsoft.com/en-us/windows/win32/fileio/naming-a-file?redirectedfrom=MSDN#file_and_directory_names
		// https://docs.microsoft.com/en-us/dotnet/standard/io/file-path-formats
		return false
	}
	return true
}

// MustSubFS creates sub FS from current filesystem or panic on failure.
// Panic happens when `fsRoot` contains invalid path according to `fs.ValidPath` rules.
//
// MustSubFS is helpful when dealing with `embed.FS` because for example `//go:embed assets/images` embeds files with
// paths including `assets/images` as their prefix. In that case use `fs := engine.MustSubFS(fs, "rootDirectory") to
// create sub fs which uses necessary prefix for directory path.
func MustSubFS(currentFs fs.FS, fsRoot string) fs.FS {
	subFs, err := subFS(currentFs, fsRoot)
	if err != nil {
		panic(fmt.Errorf("can not create sub FS, invalid root given, err: %w", err))
	}
	return subFs
}
