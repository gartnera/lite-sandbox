package selfupdate

import "runtime"

// Split out so tests can read the values the package defaults to.
var (
	runtimeGOOS   = runtime.GOOS
	runtimeGOARCH = runtime.GOARCH
)
