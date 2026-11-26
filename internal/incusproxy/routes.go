package incusproxy

import "strings"

// kind selects the extra handling a permitted endpoint gets beyond the
// allowlist and project pinning.
type kind int

const (
	plain           kind = iota
	instanceScoped       // per-instance: tag check in tagged_only mode
	instanceList         // listing filtered to tagged instances in tagged_only mode
	instanceCreate       // body checked: source, config, devices, profiles; tag injected
	instanceUpdate       // PUT/PATCH: changed config/devices/profiles checked
	instanceRename       // POST /instances/{name}: no migration, same project
	snapshotRename       // POST /instances/{name}/snapshots/{snap}: no migration
	instanceRebuild      // source checked
	imageCreate          // publish source tag-checked, same project; new images tagged
	imageWrite           // PUT/PATCH/DELETE an image: tagged images only in tagged_only mode
	aliasWrite           // change/rename/delete an alias: of a tagged image only in tagged_only mode
	projectList          // listing filtered to the pinned project
	projectScoped        // the pinned project only
	profileCreate        // body checked; refused in tagged_only mode
	profileUpdate        // changed config/devices checked; refused in tagged_only mode
	profileOther         // rename/delete; refused in tagged_only mode
	volumeCreate         // same-project JSON create only
)

// route is one permitted endpoint: an HTTP method and the path segments after
// /1.0, where "*" matches any single segment.
type route struct {
	method  string
	pattern []string
	kind    kind
}

func r(method, path string, k kind) route {
	var segs []string
	if path != "" {
		segs = strings.Split(path, "/")
	}
	return route{method: method, pattern: segs, kind: k}
}

// many returns one route per method.
func many(methods, path string, k kind) []route {
	var out []route
	for _, m := range strings.Split(methods, ",") {
		out = append(out, r(m, path, k))
	}
	return out
}

// routes is the API allowlist, covering what the incus and lxc CLIs need to
// launch, run, inspect, snapshot, publish and delete instances, manage images,
// and read the rest. Anything not listed — server configuration,
// certificates, cluster, projects, networks and storage pools beyond reads,
// backup and migration imports, debug endpoints — is refused with 403.
var routes = func() []route {
	var rs []route
	add := func(more ...route) { rs = append(rs, more...) }

	// Server
	add(r("GET", "", plain))
	add(r("GET", "events", plain))
	add(r("GET", "resources", plain))
	add(r("GET", "metadata/configuration", plain))
	add(r("GET", "warnings", plain), r("GET", "warnings/*", plain))

	// Operations (ids are random UUIDs; websockets need the per-operation
	// secret only the creator receives)
	add(r("GET", "operations", plain))
	add(many("GET,DELETE", "operations/*", plain)...)
	add(r("GET", "operations/*/wait", plain))
	add(r("GET", "operations/*/websocket", plain))

	// Instances
	add(r("GET", "instances", instanceList))
	add(r("POST", "instances", instanceCreate))
	add(many("GET,DELETE", "instances/*", instanceScoped)...)
	add(many("PUT,PATCH", "instances/*", instanceUpdate)...)
	add(r("POST", "instances/*", instanceRename))
	add(many("GET,PUT", "instances/*/state", instanceScoped)...)
	add(r("POST", "instances/*/exec", instanceScoped))
	add(many("GET,POST,DELETE", "instances/*/console", instanceScoped)...)
	add(many("GET,HEAD,POST,DELETE", "instances/*/files", instanceScoped)...)
	add(r("GET", "instances/*/sftp", instanceScoped))
	add(r("GET", "instances/*/logs", instanceScoped))
	add(many("GET,DELETE", "instances/*/logs/*", instanceScoped)...)
	add(many("GET,DELETE", "instances/*/logs/exec-output/*", instanceScoped)...)
	add(many("GET,POST", "instances/*/snapshots", instanceScoped)...)
	add(many("GET,PUT,PATCH,DELETE", "instances/*/snapshots/*", instanceScoped)...)
	add(r("POST", "instances/*/snapshots/*", snapshotRename))
	add(many("GET,POST", "instances/*/backups", instanceScoped)...)
	add(many("GET,POST,DELETE", "instances/*/backups/*", instanceScoped)...)
	add(r("GET", "instances/*/backups/*/export", instanceScoped))
	add(many("GET,PUT,PATCH", "instances/*/metadata", instanceScoped)...)
	add(many("GET,POST,PUT,DELETE", "instances/*/metadata/templates", instanceScoped)...)
	add(r("POST", "instances/*/rebuild", instanceRebuild))

	// Images. Aliases come first: "images/aliases/<name>" must not match the
	// "images/<fingerprint>/<op>" routes below for an alias named like an op.
	add(many("GET,POST", "images/aliases", plain)...)
	add(r("GET", "images/aliases/*", plain))
	add(many("PUT,PATCH,POST,DELETE", "images/aliases/*", aliasWrite)...)
	add(r("GET", "images", plain))
	add(r("POST", "images", imageCreate))
	add(r("GET", "images/*", plain))
	add(many("PUT,PATCH,DELETE", "images/*", imageWrite)...)
	add(many("GET,POST", "images/*/export", plain)...)
	add(r("POST", "images/*/refresh", plain))
	add(r("POST", "images/*/secret", plain))

	// Profiles
	add(r("GET", "profiles", plain))
	add(r("POST", "profiles", profileCreate))
	add(r("GET", "profiles/*", plain))
	add(many("PUT,PATCH", "profiles/*", profileUpdate)...)
	add(many("POST,DELETE", "profiles/*", profileOther)...)

	// Read-only: projects, networks, storage pools and volumes
	add(r("GET", "projects", projectList), r("GET", "projects/*", projectScoped), r("GET", "projects/*/state", projectScoped))
	add(r("GET", "networks", plain), r("GET", "networks/*", plain))
	add(r("GET", "networks/*/state", plain), r("GET", "networks/*/leases", plain))
	add(r("GET", "storage-pools", plain), r("GET", "storage-pools/*", plain), r("GET", "storage-pools/*/resources", plain))
	add(r("GET", "storage-pools/*/volumes", plain), r("GET", "storage-pools/*/volumes/*", plain), r("GET", "storage-pools/*/volumes/*/*", plain))

	// Custom storage volumes: create and delete (attaching one is a pool-backed
	// disk device, which the policy allows).
	add(r("POST", "storage-pools/*/volumes", volumeCreate), r("POST", "storage-pools/*/volumes/custom", volumeCreate))
	add(r("DELETE", "storage-pools/*/volumes/custom/*", plain))
	return rs
}()

// match returns the route for a method and the decoded path segments after
// /1.0, and whether one matched.
func match(method string, segs []string) (route, bool) {
	for _, rt := range routes {
		if rt.method != method || len(rt.pattern) != len(segs) {
			continue
		}
		ok := true
		for i, p := range rt.pattern {
			if p != "*" && p != segs[i] {
				ok = false
				break
			}
		}
		if ok {
			return rt, true
		}
	}
	return route{}, false
}
