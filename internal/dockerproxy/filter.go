package dockerproxy

import "regexp"

// The Docker CLI/SDK prefixes every API path with an optional version segment
// (e.g. /v1.43/containers/json). versionPrefix matches that optional prefix so
// the allowlist patterns below stay version-agnostic.
const versionPrefix = `^(/v[0-9]+\.[0-9]+)?`

// allowRule pairs an HTTP method with a path pattern. A request is permitted
// when its method matches and its path matches the (anchored) pattern.
type allowRule struct {
	method string
	path   *regexp.Regexp
}

func rule(method, pathPattern string) allowRule {
	return allowRule{method: method, path: regexp.MustCompile(versionPrefix + pathPattern + `$`)}
}

// allowRules is the default API allowlist. It covers daemon introspection, the
// read-only inspect/list surface, and the container/image lifecycle needed to
// actually build and run containers. Anything not listed here is rejected with
// HTTP 403. This table is the single place to widen or narrow the policy.
//
// Container creation (POST .../containers/create) is allowed here but is
// additionally body-inspected in inspect.go to enforce the privileged and
// bind-mount-path rules.
var allowRules = []allowRule{
	// Daemon introspection
	rule("HEAD", `/_ping`),
	rule("GET", `/_ping`),
	rule("GET", `/version`),
	rule("GET", `/info`),
	rule("GET", `/events`),
	rule("GET", `/system/df`),
	rule("GET", `/auth`),

	// Containers — read
	rule("GET", `/containers/json`),
	rule("GET", `/containers/[^/]+/json`),
	rule("GET", `/containers/[^/]+/logs`),
	rule("GET", `/containers/[^/]+/top`),
	rule("GET", `/containers/[^/]+/changes`),
	rule("GET", `/containers/[^/]+/stats`),
	rule("GET", `/containers/[^/]+/export`),
	rule("GET", `/containers/[^/]+/attach/ws`),
	rule("HEAD", `/containers/[^/]+/archive`),
	rule("GET", `/containers/[^/]+/archive`),

	// Containers — lifecycle
	rule("POST", `/containers/create`),
	rule("POST", `/containers/[^/]+/start`),
	rule("POST", `/containers/[^/]+/stop`),
	rule("POST", `/containers/[^/]+/restart`),
	rule("POST", `/containers/[^/]+/kill`),
	rule("POST", `/containers/[^/]+/pause`),
	rule("POST", `/containers/[^/]+/unpause`),
	rule("POST", `/containers/[^/]+/wait`),
	rule("POST", `/containers/[^/]+/rename`),
	rule("POST", `/containers/[^/]+/resize`),
	rule("POST", `/containers/[^/]+/attach`),
	rule("PUT", `/containers/[^/]+/archive`),
	rule("DELETE", `/containers/[^/]+`),
	rule("POST", `/containers/prune`),

	// Exec — note: exec create does not introduce host binds, so it is not
	// body-inspected.
	rule("POST", `/containers/[^/]+/exec`),
	rule("POST", `/exec/[^/]+/start`),
	rule("POST", `/exec/[^/]+/resize`),
	rule("GET", `/exec/[^/]+/json`),

	// Images
	rule("GET", `/images/json`),
	rule("GET", `/images/[^/]+/json`),
	rule("GET", `/images/[^/]+/history`),
	rule("GET", `/images/search`),
	rule("GET", `/images/get`),
	rule("POST", `/images/create`),
	rule("POST", `/images/[^/]+/push`),
	rule("POST", `/images/[^/]+/tag`),
	rule("POST", `/images/load`),
	rule("POST", `/build`),
	rule("POST", `/build/prune`),
	rule("DELETE", `/images/[^/]+`),
	rule("POST", `/images/prune`),

	// Networks
	rule("GET", `/networks`),
	rule("GET", `/networks/[^/]+`),
	rule("POST", `/networks/create`),
	rule("POST", `/networks/[^/]+/connect`),
	rule("POST", `/networks/[^/]+/disconnect`),
	rule("DELETE", `/networks/[^/]+`),
	rule("POST", `/networks/prune`),

	// Volumes
	rule("GET", `/volumes`),
	rule("GET", `/volumes/[^/]+`),
	rule("POST", `/volumes/create`),
	rule("DELETE", `/volumes/[^/]+`),
	rule("POST", `/volumes/prune`),
}

// isAllowed reports whether the given HTTP method and path are permitted by the
// allowlist.
func isAllowed(method, path string) bool {
	for _, r := range allowRules {
		if r.method == method && r.path.MatchString(path) {
			return true
		}
	}
	return false
}

// isContainerCreate reports whether the request targets the container-create
// endpoint, which must be body-inspected for privileged/bind-mount policy.
var containerCreatePattern = regexp.MustCompile(versionPrefix + `/containers/create$`)

func isContainerCreate(method, path string) bool {
	return method == "POST" && containerCreatePattern.MatchString(path)
}
