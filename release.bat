@echo off

set version="v0.1.9"

git tag %version%
git push origin %version%

REM go env -w GOPRIVATE='github.com/go-per/*'
go list -m github.com/go-per/web-engine@%version%

pause