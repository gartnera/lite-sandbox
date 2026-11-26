package incusproxy

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// shortSocketDir returns a short temp dir for unix sockets (macOS limits
// sun_path to ~104 bytes).
func shortSocketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "ip")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// fakeDaemon is a minimal Incus daemon: it serves the instances and profiles
// it holds for the proxy's own lookups and records every other request.
type fakeDaemon struct {
	socket    string
	mu        sync.Mutex
	instances map[string]instance
	profiles  map[string]instance
	got       []string // "METHOD path?query"
	bodies    []string
	headers   []http.Header
}

func (fd *fakeDaemon) last() (string, string) {
	fd.mu.Lock()
	defer fd.mu.Unlock()
	if len(fd.got) == 0 {
		return "", ""
	}
	return fd.got[len(fd.got)-1], fd.bodies[len(fd.bodies)-1]
}

// lookup serves the networks, images and aliases the proxy's policy looks up.
func lookup(p string) (any, bool) {
	objs := map[string]any{
		"/1.0/networks/incusbr0":                           map[string]any{"name": "incusbr0", "type": "bridge"},
		"/1.0/networks/uplink":                             map[string]any{"name": "uplink", "type": "physical"},
		"/1.0/networks/vfs":                                map[string]any{"name": "vfs", "type": "sriov"},
		"/1.0/images/ownimg":                               map[string]any{"properties": map[string]string{"user.lite-sandbox": "true"}},
		"/1.0/images/adminimg":                             map[string]any{"properties": map[string]string{"os": "debian"}},
		"/1.0/images/aliases/mine-alias":                   map[string]any{"name": "mine-alias", "target": "ownimg"},
		"/1.0/images/aliases/debian":                       map[string]any{"name": "debian", "target": "adminimg"},
		"/1.0/images/aliases/export":                       map[string]any{"name": "export", "target": "adminimg"},
		"/1.0/projects/default":                            map[string]any{"name": "default", "config": map[string]string{}},
		"/1.0/projects/sandbox":                            map[string]any{"name": "sandbox", "config": map[string]string{"restricted": "true", "restricted.devices.disk": "allow", "restricted.devices.disk.paths": "/elsewhere,/work,/ref"}},
		"/1.0/projects/deep":                               map[string]any{"name": "deep", "config": map[string]string{"restricted": "true", "restricted.devices.disk.paths": "/work/sub"}},
		"/1.0/projects/wide":                               map[string]any{"name": "wide", "config": map[string]string{"restricted": "true", "restricted.devices.disk.paths": "/"}},
		"/1.0/storage-pools/default/volumes/custom/v":      map[string]any{"name": "v", "config": map[string]string{}},
		"/1.0/storage-pools/default/volumes/custom/mine-v": map[string]any{"name": "mine-v", "config": map[string]string{"user.lite-sandbox": "true"}},
	}
	if strings.HasPrefix(p, "/1.0/projects/") || strings.HasPrefix(p, "/1.0/storage-pools/") {
		if o, ok := objs[p]; ok {
			return o, true
		}
		return nil, false
	}
	for _, prefix := range []string{"/1.0/networks/", "/1.0/images/"} {
		if strings.HasPrefix(p, prefix) {
			if strings.Count(strings.TrimPrefix(p, prefix), "/") > 0 && !strings.HasPrefix(p, "/1.0/images/aliases/") {
				return nil, false
			}
			if o, ok := objs[p]; ok {
				return o, true
			}
			return nil, true
		}
	}
	return nil, false
}

func sync200(w http.ResponseWriter, md any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"type": "sync", "status_code": 200, "metadata": md})
}

func startFakeDaemon(t *testing.T) *fakeDaemon {
	t.Helper()
	fd := &fakeDaemon{
		socket: filepath.Join(shortSocketDir(t), "d.sock"),
		instances: map[string]instance{
			"vm1":    {Name: "vm1", Type: "virtual-machine", Config: map[string]string{"user.lite-sandbox": "true"}, Profiles: []string{"default"}},
			"mine":   {Name: "mine", Config: map[string]string{"user.lite-sandbox": "true", "volatile.idmap.next": "[...]"}, Devices: map[string]map[string]string{"data": {"type": "disk", "source": "/srv/admin", "path": "/data"}}, Profiles: []string{"default"}},
			"theirs": {Name: "theirs", Config: map[string]string{}, Profiles: []string{"default"}},
		},
		profiles: map[string]instance{
			"default": {Name: "default", Devices: map[string]map[string]string{
				"root": {"type": "disk", "path": "/", "pool": "default"},
				"eth0": {"type": "nic", "nictype": "bridged", "parent": "br0"},
			}},
			"priv": {Name: "priv", Config: map[string]string{"security.privileged": "true"}},
		},
	}
	ln, err := net.Listen("unix", fd.socket)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		fd.mu.Lock()
		defer fd.mu.Unlock()
		p := r.URL.Path
		if r.Method == "GET" {
			if obj, ok := lookup(p); ok && r.Header.Get("X-Test-Client") == "" {
				if obj == nil {
					w.WriteHeader(404)
					io.WriteString(w, `{"type":"error","error":"not found","error_code":404}`)
				} else {
					sync200(w, obj)
				}
				return
			}
			if p == "/1.0/projects" {
				md := []any{"/1.0/projects/default", "/1.0/projects/other"}
				if r.URL.Query().Get("recursion") == "1" {
					md = []any{map[string]any{"name": "default"}, map[string]any{"name": "other"}}
				}
				sync200(w, md)
				return
			}
			if name, ok := strings.CutPrefix(p, "/1.0/profiles/"); ok {
				if prof, ok := fd.profiles[name]; ok {
					sync200(w, prof)
				} else {
					w.WriteHeader(404)
					io.WriteString(w, `{"type":"error","error":"not found","error_code":404}`)
				}
				return
			}
			if name, ok := strings.CutPrefix(p, "/1.0/instances/"); ok && !strings.Contains(name, "/") && r.Header.Get("X-Test-Client") == "" {
				if inst, ok := fd.instances[name]; ok {
					sync200(w, inst)
				} else {
					w.WriteHeader(404)
					io.WriteString(w, `{"type":"error","error":"not found","error_code":404}`)
				}
				return
			}
			if p == "/1.0/instances" {
				var md []any
				for _, n := range []string{"mine", "theirs"} {
					if r.URL.Query().Get("recursion") == "" || r.URL.Query().Get("recursion") == "0" {
						md = append(md, "/1.0/instances/"+n)
					} else {
						md = append(md, fd.instances[n])
					}
				}
				if r.Header.Get("X-Test-Client") != "" {
					fd.got = append(fd.got, r.Method+" "+r.URL.RequestURI())
					fd.bodies = append(fd.bodies, string(body))
				}
				sync200(w, md)
				return
			}
		}
		fd.got = append(fd.got, r.Method+" "+r.URL.RequestURI())
		fd.bodies = append(fd.bodies, string(body))
		fd.headers = append(fd.headers, r.Header.Clone())
		sync200(w, map[string]any{})
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return fd
}

type testProxy struct {
	t      *testing.T
	fd     *fakeDaemon
	client *http.Client
}

func newTestProxy(t *testing.T, mod func(*Options)) *testProxy {
	t.Helper()
	fd := startFakeDaemon(t)
	opts := Options{
		SocketDir: shortSocketDir(t),
		Upstream:  fd.socket,
		TagKey:    "user.lite-sandbox",
		Policy: Policy{
			WorkDir:    "/work",
			ReadPaths:  []string{"/work", "/ref"},
			WritePaths: []string{"/work"},
		},
	}
	if mod != nil {
		mod(&opts)
	}
	srv, err := NewServer(opts)
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	})
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", srv.SocketPath())
	}}}
	return &testProxy{t: t, fd: fd, client: client}
}

// do sends a request and returns the status and the decoded reply.
func (p *testProxy) do(method, path, body string, hdr ...string) (int, map[string]any) {
	p.t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, _ := http.NewRequest(method, "http://unix.socket"+path, rd)
	req.Header.Set("X-Test-Client", "1")
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := p.client.Do(req)
	if err != nil {
		p.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func (p *testProxy) expect(method, path, body string, want int) map[string]any {
	p.t.Helper()
	got, out := p.do(method, path, body)
	if got != want {
		p.t.Fatalf("%s %s %s: status %d, want %d (%v)", method, path, body, got, want, out["error"])
	}
	return out
}

func TestAllowlist(t *testing.T) {
	p := newTestProxy(t, nil)
	for _, c := range []struct {
		method, path string
		want         int
	}{
		{"GET", "/", 200},
		{"GET", "/1.0", 200},
		{"GET", "/1.0/events", 200},
		{"GET", "/1.0/operations/abc/wait", 200},
		{"GET", "/1.0/networks", 200},
		{"GET", "/1.0/images/aliases/debian", 200},
		{"POST", "/1.0/instances/mine/exec", 200},
		{"PUT", "/1.0/instances/mine/state", 200},
		{"GET", "/1.0/instances/mine/sftp", 200},
		{"PUT", "/1.0", 403},
		{"PATCH", "/1.0", 403},
		{"POST", "/1.0/certificates", 403},
		{"GET", "/1.0/certificates", 403},
		{"POST", "/1.0/networks", 403},
		{"PUT", "/1.0/networks/incusbr0", 403},
		{"POST", "/1.0/storage-pools", 403},
		{"POST", "/1.0/projects", 403},
		{"PUT", "/1.0/projects/default", 403},
		{"GET", "/1.0/cluster", 403},
		{"POST", "/1.0/instances/mine/debug/repair", 403},
		{"GET", "/1.0/instances/mine/debug/memory", 403},
		{"GET", "/1.0/containers", 403},
		{"GET", "/1.0/instances/a%2Fb", 403},
		{"GET", "/1.0/instances/../certificates", 403},
		{"GET", "/2.0/instances", 403},
		{"POST", "/", 403},
	} {
		if got, out := p.do(c.method, c.path, ""); got != c.want {
			t.Errorf("%s %s: status %d, want %d (%v)", c.method, c.path, got, c.want, out["error"])
		}
	}
}

func TestProjectPinning(t *testing.T) {
	p := newTestProxy(t, nil)
	p.expect("GET", "/1.0/images?project=other", "", 403)
	p.expect("GET", "/1.0/images?all-projects=true", "", 403)
	p.expect("GET", "/1.0/images?project=default&project=other", "", 403)
	p.expect("GET", "/1.0/images?project=default", "", 200)
	p.expect("GET", "/1.0/images", "", 200)
	if got, _ := p.fd.last(); got != "GET /1.0/images" {
		t.Errorf("default project: forwarded %q, want no project parameter added", got)
	}

	q := newTestProxy(t, func(o *Options) { o.Project = "sandbox" })
	q.expect("GET", "/1.0/images", "", 200)
	if got, _ := q.fd.last(); got != "GET /1.0/images?project=sandbox" {
		t.Errorf("pinned project: forwarded %q", got)
	}
	q.expect("GET", "/1.0/images?project=default", "", 403)
	// Body fields naming another project.
	q.expect("POST", "/1.0/instances", `{"name":"c","source":{"type":"copy","source":"mine","project":"default"}}`, 403)
	q.expect("POST", "/1.0/instances/mine", `{"name":"c","project":"default"}`, 403)
}

func TestCreatePolicy(t *testing.T) {
	p := newTestProxy(t, nil)
	img := `"source":{"type":"image","alias":"debian/12","server":"https://images.linuxcontainers.org","protocol":"simplestreams"}`
	for _, c := range []struct {
		name, body string
		want       int
	}{
		{"plain launch", `{"name":"c",` + img + `}`, 200},
		{"empty", `{"name":"c","source":{"type":"none"}}`, 200},
		{"privileged", `{"name":"c",` + img + `,"config":{"security.privileged":"true"}}`, 403},
		{"privileged false", `{"name":"c",` + img + `,"config":{"security.privileged":"false"}}`, 200},
		{"nesting", `{"name":"c",` + img + `,"config":{"security.nesting":"true"}}`, 403},
		{"raw.lxc", `{"name":"c",` + img + `,"config":{"raw.lxc":"lxc.apparmor.profile=unconfined"}}`, 403},
		{"raw.idmap", `{"name":"c",` + img + `,"config":{"raw.idmap":"both 0 0"}}`, 403},
		{"kernel modules", `{"name":"c",` + img + `,"config":{"linux.kernel_modules":"dummy"}}`, 403},
		{"intercept mount", `{"name":"c",` + img + `,"config":{"security.syscalls.intercept.mount":"true"}}`, 403},
		{"syscall deny", `{"name":"c",` + img + `,"config":{"security.syscalls.deny":"kexec_load"}}`, 200},
		{"deny_default off", `{"name":"c",` + img + `,"config":{"security.syscalls.deny_default":"false"}}`, 403},
		{"volatile idmap", `{"name":"c",` + img + `,"config":{"volatile.idmap.next":"[]"}}`, 403},
		{"volatile hwaddr", `{"name":"c",` + img + `,"config":{"volatile.eth0.hwaddr":"00:16:3e:00:00:01"}}`, 200},
		{"limits", `{"name":"c",` + img + `,"config":{"limits.cpu":"2","environment.FOO":"bar"}}`, 200},
		{"unix-char", `{"name":"c",` + img + `,"devices":{"kvm":{"type":"unix-char","path":"/dev/kvm"}}}`, 403},
		{"gpu", `{"name":"c",` + img + `,"devices":{"g":{"type":"gpu"}}}`, 403},
		{"proxy", `{"name":"c",` + img + `,"devices":{"d":{"type":"proxy","listen":"unix:/run/d.sock","connect":"unix:/var/run/docker.sock","bind":"container"}}}`, 403},
		{"no type", `{"name":"c",` + img + `,"devices":{"d":{"path":"/x"}}}`, 403},
		{"disk outside", `{"name":"c",` + img + `,"devices":{"h":{"type":"disk","source":"/etc","path":"/h"}}}`, 403},
		// The default project cannot be restricted, so the daemon would
		// follow a symlink swapped in after the check: see TestHostPathDisks.
		{"disk inside, unrestricted project", `{"name":"c",` + img + `,"devices":{"h":{"type":"disk","source":"/work/src","path":"/h"}}}`, 403},
		{"disk rw read path", `{"name":"c",` + img + `,"devices":{"h":{"type":"disk","source":"/ref","path":"/h"}}}`, 403},
		{"disk traversal", `{"name":"c",` + img + `,"devices":{"h":{"type":"disk","source":"/work/../etc","path":"/h"}}}`, 403},
		{"disk relative", `{"name":"c",` + img + `,"devices":{"h":{"type":"disk","source":"src","path":"/h"}}}`, 403},
		{"disk pool", `{"name":"c",` + img + `,"devices":{"v":{"type":"disk","pool":"default","source":"vol","path":"/v"}}}`, 200},
		{"disk raw opts", `{"name":"c",` + img + `,"devices":{"v":{"type":"disk","pool":"default","source":"vol","path":"/v","raw.mount.options":"x"}}}`, 403},
		{"cloud-init drive", `{"name":"c",` + img + `,"devices":{"ci":{"type":"disk","source":"cloud-init:config"}}}`, 200},
		{"nic bridged", `{"name":"c",` + img + `,"devices":{"e":{"type":"nic","nictype":"bridged","parent":"br0"}}}`, 200},
		{"nic physical", `{"name":"c",` + img + `,"devices":{"e":{"type":"nic","nictype":"physical","parent":"eth0"}}}`, 403},
		{"privileged profile", `{"name":"c",` + img + `,"profiles":["default","priv"]}`, 403},
		{"migration source", `{"name":"c","source":{"type":"migration","mode":"pull","operation":"https://evil/1.0/operations/x"}}`, 403},
		{"conversion source", `{"name":"c","source":{"type":"conversion"}}`, 403},
		{"copy untagged", `{"name":"c","source":{"type":"copy","source":"theirs"}}`, 403},
		{"copy tagged", `{"name":"c","source":{"type":"copy","source":"mine"}}`, 403}, // its /srv/admin disk is outside the boundary
		{"case-folded key", `{"name":"c",` + img + `,"Config":{"security.privileged":"true"}}`, 403},
		{"not json", `{"name":`, 403},
	} {
		if got, out := p.do("POST", "/1.0/instances", c.body); got != c.want {
			t.Errorf("%s: status %d, want %d (%v)", c.name, got, c.want, out["error"])
		}
	}
	if got, _ := p.do("POST", "/1.0/instances", "tarball", "Content-Type", "application/octet-stream"); got != 403 {
		t.Errorf("backup import: status %d, want 403", got)
	}
}

func TestCreateTagsAndPinsProfiles(t *testing.T) {
	p := newTestProxy(t, nil)
	p.expect("POST", "/1.0/instances", `{"name":"c","source":{"type":"image","alias":"x"},"config":{"limits.cpu":"1"},"CONFIG":{"user.lite-sandbox":"false"}}`, 403)
	p.expect("POST", "/1.0/instances", `{"name":"c","source":{"type":"image","alias":"x"},"config":{"limits.cpu":"1","user.lite-sandbox":"false"}}`, 200)
	_, body := p.fd.last()
	var got struct {
		Config   map[string]string `json:"config"`
		Profiles []string          `json:"profiles"`
	}
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatal(err)
	}
	if got.Config["user.lite-sandbox"] != "true" || got.Config["limits.cpu"] != "1" {
		t.Errorf("forwarded config %v: want the tag added and limits.cpu kept", got.Config)
	}
	if len(got.Profiles) != 1 || got.Profiles[0] != "default" {
		t.Errorf("forwarded profiles %v: want [default] named explicitly", got.Profiles)
	}
	var raw map[string]json.RawMessage
	json.Unmarshal([]byte(body), &raw)
	if _, ok := raw["CONFIG"]; ok {
		t.Errorf("differently-cased config key survived: %s", body)
	}

	// Outside tagged-only mode the body is left alone when profiles are given.
	q := newTestProxy(t, func(o *Options) { o.TagKey = "" })
	in := `{"name":"c","source":{"type":"image","alias":"x"},"profiles":["default"]}`
	q.expect("POST", "/1.0/instances", in, 200)
	if _, body := q.fd.last(); body != in {
		t.Errorf("body rewritten: %s", body)
	}
	q.expect("POST", "/1.0/instances", `{"name":"c","source":{"type":"copy","source":"theirs"}}`, 200)
}

func TestTaggedOnly(t *testing.T) {
	p := newTestProxy(t, nil)
	p.expect("POST", "/1.0/instances/mine/exec", `{"command":["sh"]}`, 200)
	p.expect("POST", "/1.0/instances/theirs/exec", `{"command":["sh"]}`, 403)
	p.expect("DELETE", "/1.0/instances/theirs", "", 403)
	p.expect("GET", "/1.0/instances/theirs/sftp", "", 403)
	p.expect("PUT", "/1.0/instances/theirs/state", `{"action":"stop"}`, 403)
	p.expect("POST", "/1.0/instances/theirs/snapshots", `{"name":"s"}`, 403)
	p.expect("GET", "/1.0/instances/missing", "", 200) // the daemon reports its own 404
	p.expect("POST", "/1.0/profiles", `{"name":"p"}`, 403)
	p.expect("PATCH", "/1.0/profiles/default", `{"config":{"limits.cpu":"1"}}`, 403)
	p.expect("DELETE", "/1.0/profiles/default", "", 403)
	p.expect("POST", "/1.0/images", `{"source":{"type":"instance","name":"theirs"}}`, 403)
	p.expect("POST", "/1.0/images", `{"source":{"type":"instance","name":"mine"}}`, 200)
	// A JSON body is still a publish whatever its Content-Type says.
	if got, _ := p.do("POST", "/1.0/images", ` {"source":{"type":"snapshot","name":"theirs/s0"}}`, "Content-Type", "application/octet-stream"); got != 403 {
		t.Errorf("publish disguised as upload: status %d, want 403", got)
	}
	if got, _ := p.do("POST", "/1.0/images", "\x1f\x8bnot-json-tarball", "Content-Type", "application/octet-stream"); got != 200 {
		t.Errorf("image upload: status %d, want 200", got)
	}

	for _, rec := range []string{"", "?recursion=1", "?recursion=2"} {
		out := p.expect("GET", "/1.0/instances"+rec, "", 200)
		md, _ := out["metadata"].([]any)
		if len(md) != 1 {
			t.Fatalf("listing%s: %v, want only the tagged instance", rec, md)
		}
		if s, ok := md[0].(string); ok && s != "/1.0/instances/mine" {
			t.Errorf("listing%s: kept %v", rec, s)
		}
		if m, ok := md[0].(map[string]any); ok && m["name"] != "mine" {
			t.Errorf("listing%s: kept %v", rec, m["name"])
		}
	}

	q := newTestProxy(t, func(o *Options) { o.TagKey = "" })
	q.expect("POST", "/1.0/instances/theirs/exec", `{"command":["sh"]}`, 200)
	q.expect("PATCH", "/1.0/profiles/default", `{"config":{"limits.cpu":"1"}}`, 200)
	q.expect("PATCH", "/1.0/profiles/default", `{"config":{"raw.lxc":"x"}}`, 403)
	q.expect("PUT", "/1.0/profiles/default", `{"devices":{"root":{"type":"disk","path":"/","pool":"default"},"eth0":{"type":"nic","nictype":"bridged","parent":"br0"},"k":{"type":"unix-char","path":"/dev/kvm"}}}`, 403)
	out := q.expect("GET", "/1.0/instances", "", 200)
	if md, _ := out["metadata"].([]any); len(md) != 2 {
		t.Errorf("unfiltered listing: %v", md)
	}
}

func TestUpdateChecksOnlyChanges(t *testing.T) {
	p := newTestProxy(t, nil)
	// `incus config set mine limits.cpu 2`: a PUT of the whole config,
	// volatile state and the admin's out-of-boundary disk included.
	p.expect("PUT", "/1.0/instances/mine", `{"config":{"user.lite-sandbox":"true","volatile.idmap.next":"[...]","limits.cpu":"2"},"devices":{"data":{"type":"disk","source":"/srv/admin","path":"/data"}},"profiles":["default"]}`, 200)
	p.expect("PUT", "/1.0/instances/mine", `{"config":{"volatile.idmap.next":"[{\"Isuid\":true,\"Hostid\":0}]"}}`, 403)
	p.expect("PATCH", "/1.0/instances/mine", `{"config":{"raw.lxc":"x"}}`, 403)
	p.expect("PATCH", "/1.0/instances/mine", `{"devices":{"data":{"type":"disk","source":"/srv/admin","path":"/elsewhere"}}}`, 403)
	p.expect("PATCH", "/1.0/instances/mine", `{"profiles":["default","priv"]}`, 403)
	p.expect("PATCH", "/1.0/instances/theirs", `{"config":{"limits.cpu":"1"}}`, 403)
	p.expect("POST", "/1.0/instances/mine", `{"name":"renamed"}`, 200)
	p.expect("POST", "/1.0/instances/mine", `{"name":"x","migration":true}`, 403)
	p.expect("POST", "/1.0/instances/mine/snapshots/s0", `{"name":"s1"}`, 200)
	p.expect("POST", "/1.0/instances/mine/snapshots/s0", `{"name":"s1","migration":true}`, 403)
	p.expect("POST", "/1.0/instances/mine/rebuild", `{"source":{"type":"image","alias":"x"}}`, 200)
	p.expect("POST", "/1.0/instances/mine/rebuild", `{"source":{"type":"migration"}}`, 403)
}

func TestAllowFlags(t *testing.T) {
	p := newTestProxy(t, func(o *Options) { o.Policy.AllowNesting = true })
	p.expect("POST", "/1.0/instances", `{"name":"c","source":{"type":"none"},"config":{"security.nesting":"true"}}`, 200)
	p.expect("POST", "/1.0/instances", `{"name":"c","source":{"type":"none"},"config":{"security.privileged":"true"}}`, 403)

	q := newTestProxy(t, func(o *Options) { o.Policy.AllowPrivileged = true })
	q.expect("POST", "/1.0/instances", `{"name":"c","source":{"type":"none"},"config":{"security.privileged":"true","raw.lxc":"x"},"devices":{"g":{"type":"gpu"}}}`, 200)
	// Host paths stay confined to the boundary.
	q.expect("POST", "/1.0/instances", `{"name":"c","source":{"type":"none"},"devices":{"h":{"type":"disk","source":"/etc","path":"/h"}}}`, 403)
}

func TestVolumes(t *testing.T) {
	p := newTestProxy(t, nil)
	p.expect("POST", "/1.0/storage-pools/default/volumes/custom", `{"name":"v","type":"custom"}`, 200)
	p.expect("POST", "/1.0/storage-pools/default/volumes/custom", `{"name":"v","source":{"type":"migration"}}`, 403)
	if got, _ := p.do("POST", "/1.0/storage-pools/default/volumes/custom", "backup", "Content-Type", "application/octet-stream"); got != 403 {
		t.Errorf("volume import: status %d, want 403", got)
	}
	p.expect("DELETE", "/1.0/storage-pools/default/volumes/custom/v", "", 403)
	p.expect("DELETE", "/1.0/storage-pools/default/volumes/custom/mine-v", "", 200)
	p.expect("POST", "/1.0/storage-pools/default/volumes/custom", `{"name":"v","source":{"type":"backup","backup":{"type":"url","url":"http://x"}}}`, 403)
	p.expect("POST", "/1.0/storage-pools/default/volumes/custom", `{"name":"v2","config":{"size":"1GiB"}}`, 200)
	_, body := p.fd.last()
	var vol struct {
		Config map[string]string `json:"config"`
	}
	json.Unmarshal([]byte(body), &vol)
	if vol.Config["user.lite-sandbox"] != "true" || vol.Config["size"] != "1GiB" {
		t.Errorf("created volume config %v: want the tag added", vol.Config)
	}
	p.expect("PUT", "/1.0/storage-pools/default/volumes/custom/v", `{}`, 403)
}

func TestNameFromURL(t *testing.T) {
	for in, want := range map[string]string{
		"/1.0/instances/c1":                       "c1",
		"/1.0/instances/c1?project=default":       "c1",
		"/1.0/instances/" + url.PathEscape("a b"): "a b",
	} {
		if got := nameFromURL(in); got != want {
			t.Errorf("nameFromURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestReviewFindings(t *testing.T) {
	p := newTestProxy(t, nil)
	img := `"source":{"type":"image","alias":"x"}`

	// Case-variant duplicate keys would be reordered by a rewrite.
	p.expect("POST", "/1.0/instances", `{"name":"c",`+img+`,"config":{"security.privileged":"true"},"Config":{"security.privileged":"false"}}`, 403)
	p.expect("POST", "/1.0/instances", `{"name":"c",`+img+`,"config":{"security.privileged":"true"},"Config":null}`, 403)

	// Publish bodies are inspected the way the daemon decodes them.
	if got, _ := p.do("POST", "/1.0/images", `{"source":{"type":"instance","name":"theirs"}}garbage`, "Content-Type", "application/octet-stream"); got != 403 {
		t.Errorf("publish with trailing data: status %d, want 403", got)
	}
	if got, _ := p.do("POST", "/1.0/images", strings.Repeat(" ", 5000)+`{"source":{"type":"instance","name":"theirs"}}`, "Content-Type", "application/octet-stream"); got != 403 {
		t.Errorf("publish after long whitespace: status %d, want 403", got)
	}

	// Refresh copies onto an existing instance.
	p.expect("POST", "/1.0/instances", `{"name":"theirs","source":{"type":"copy","source":"mine","refresh":true}}`, 403)

	// Restoring another instance's snapshot.
	p.expect("PUT", "/1.0/instances/mine", `{"restore":"theirs/snap0"}`, 403)
	p.expect("PUT", "/1.0/instances/mine", `{"restore":"snap0"}`, 200)

	// NICs on a managed physical network.
	p.expect("POST", "/1.0/instances", `{"name":"c",`+img+`,"devices":{"e":{"type":"nic","network":"uplink"}}}`, 403)
	p.expect("POST", "/1.0/instances", `{"name":"c",`+img+`,"devices":{"e":{"type":"nic","network":"incusbr0"}}}`, 200)

	// LXD's spelling of the guest image API key.
	p.expect("POST", "/1.0/instances", `{"name":"c",`+img+`,"config":{"security.devlxd.images":"true"}}`, 403)

	// Images and aliases someone else's launches use.
	p.expect("PATCH", "/1.0/images/adminimg", `{"profiles":["priv"]}`, 403)
	p.expect("DELETE", "/1.0/images/adminimg", "", 403)
	p.expect("PATCH", "/1.0/images/ownimg", `{"profiles":["default"]}`, 200)
	p.expect("PUT", "/1.0/images/aliases/debian", `{"target":"ownimg"}`, 403)
	p.expect("DELETE", "/1.0/images/aliases/debian", "", 403)
	p.expect("POST", "/1.0/images/aliases/export", `{"name":"renamed"}`, 403)
	p.expect("PUT", "/1.0/images/aliases/mine-alias", `{"target":"ownimg"}`, 200)
	p.expect("POST", "/1.0/images/aliases", `{"name":"new","target":"adminimg"}`, 200)
	p.expect("POST", "/1.0/images", `{"source":{"type":"image","server":"https://images.example","alias":"x"},"properties":{"user.lite-sandbox":"true"}}`, 403)
	p.expect("POST", "/1.0/images", `{"source":{"type":"image","fingerprint":"admin"},"public":true,"profiles":["priv"]}`, 403)
	p.expect("POST", "/1.0/images/adminimg/secret", "", 403)
	p.expect("POST", "/1.0/images/adminimg/refresh", "", 403)
	p.expect("POST", "/1.0/images/ownimg/secret", "", 200)

	// The sandbox's own images are tagged.
	p.expect("POST", "/1.0/images", `{"source":{"type":"instance","name":"mine"},"properties":{"description":"d"}}`, 200)
	_, body := p.fd.last()
	var pub struct {
		Properties map[string]string `json:"properties"`
	}
	json.Unmarshal([]byte(body), &pub)
	if pub.Properties["user.lite-sandbox"] != "true" || pub.Properties["description"] != "d" {
		t.Errorf("published image properties %v: want the tag added", pub.Properties)
	}
	if got, _ := p.do("POST", "/1.0/images", "\x1f\x8btarball", "Content-Type", "application/octet-stream"); got != 200 {
		t.Fatalf("upload: status %d", got)
	}
	p.fd.mu.Lock()
	h := p.fd.headers[len(p.fd.headers)-1]
	p.fd.mu.Unlock()
	if h.Get("X-Incus-properties") != "user.lite-sandbox=true" || h.Get("X-LXD-properties") != "user.lite-sandbox=true" {
		t.Errorf("upload headers %v: want the tag property", h)
	}

	// Projects other than the pinned one.
	p.expect("GET", "/1.0/projects/other", "", 403)
	p.expect("GET", "/1.0/projects/other/state", "", 403)
	p.expect("GET", "/1.0/projects/default", "", 200)
	for _, rec := range []string{"", "?recursion=1"} {
		out := p.expect("GET", "/1.0/projects"+rec, "", 200)
		if md, _ := out["metadata"].([]any); len(md) != 1 {
			t.Errorf("project listing%s: %v, want only the pinned project", rec, md)
		}
	}
}

func TestHostPathDisks(t *testing.T) {
	disk := func(src string, extra string) string {
		return `{"name":"c","source":{"type":"none"},"devices":{"h":{"type":"disk","source":"` + src + `","path":"/h"` + extra + `}}}`
	}
	p := newTestProxy(t, func(o *Options) { o.Project = "sandbox" })
	p.expect("POST", "/1.0/instances", disk("/work/src", ""), 200)
	p.expect("POST", "/1.0/instances", disk("/ref/doc", `,"readonly":"true"`), 200)
	p.expect("POST", "/1.0/instances", disk("/ref/doc", ""), 403) // read-only grant, read-write disk
	p.expect("POST", "/1.0/instances", disk("/etc", ""), 403)
	p.expect("POST", "/1.0/instances", disk("/work/src", `,"shift":"true"`), 403)

	// A prefix the sandbox could replace, or one wider than the boundary.
	q := newTestProxy(t, func(o *Options) { o.Project = "deep" })
	q.expect("POST", "/1.0/instances", disk("/work/sub/x", ""), 403)
	w := newTestProxy(t, func(o *Options) { o.Project = "wide" })
	w.expect("POST", "/1.0/instances", disk("/work/src", ""), 403)

	// allow_privileged opts out of the confinement, not of the boundary.
	a := newTestProxy(t, func(o *Options) { o.Policy.AllowPrivileged = true })
	a.expect("POST", "/1.0/instances", disk("/work/src", ""), 200)
	a.expect("POST", "/1.0/instances", disk("/etc", ""), 403)
}

func TestNICHostOptions(t *testing.T) {
	p := newTestProxy(t, nil)
	nic := func(dev string) string {
		return `{"name":"c","source":{"type":"none"},"devices":{"e":` + dev + `}}`
	}
	p.expect("POST", "/1.0/instances", nic(`{"type":"nic","nictype":"bridged","parent":"br0","ipv4.address":"10.0.0.5"}`), 200)
	p.expect("POST", "/1.0/instances", nic(`{"type":"nic","nictype":"macvlan","parent":"eth0"}`), 200)
	p.expect("POST", "/1.0/instances", nic(`{"type":"nic","nictype":"p2p"}`), 200)
	p.expect("POST", "/1.0/instances", nic(`{"type":"nic","nictype":"p2p","ipv4.routes":"0.0.0.0/1"}`), 403)
	p.expect("POST", "/1.0/instances", nic(`{"type":"nic","nictype":"routed","ipv4.address":"192.168.1.10"}`), 403)
	p.expect("POST", "/1.0/instances", nic(`{"type":"nic","nictype":"ipvlan","parent":"eth0","ipv4.address":"192.168.1.10"}`), 403)
	p.expect("POST", "/1.0/instances", nic(`{"type":"nic","nictype":"sriov","parent":"eth0"}`), 403)
	p.expect("POST", "/1.0/instances", nic(`{"type":"nic","nictype":"bridged","parent":"br0","host_name":"eth0"}`), 403)
}

func TestSecondReviewFindings(t *testing.T) {
	p := newTestProxy(t, func(o *Options) { o.Project = "sandbox" })
	// Host-path disks on VMs: virtiofsd shares them as host root.
	p.expect("POST", "/1.0/instances", `{"name":"v","type":"virtual-machine","source":{"type":"none"},"devices":{"h":{"type":"disk","source":"/work/src","path":"/h"}}}`, 403)
	p.expect("POST", "/1.0/instances", `{"name":"c","source":{"type":"none"},"devices":{"h":{"type":"disk","source":"/work/src","path":"/h"}}}`, 200)
	p.expect("PATCH", "/1.0/instances/vm1", `{"devices":{"h":{"type":"disk","source":"/work/src","path":"/h","readonly":"true"}}}`, 403)
	p.expect("PATCH", "/1.0/instances/vm1", `{"devices":{"v":{"type":"disk","pool":"default","source":"vol","path":"/v"}}}`, 200)
	p.expect("POST", "/1.0/instances", `{"name":"c","source":{"type":"copy","source":"vm1"},"devices":{"h":{"type":"disk","source":"/work/src","path":"/h"}}}`, 403)

	// Passthrough through a managed network or OVN acceleration.
	p.expect("POST", "/1.0/instances", `{"name":"c","source":{"type":"none"},"devices":{"e":{"type":"nic","network":"vfs"}}}`, 403)
	p.expect("POST", "/1.0/instances", `{"name":"c","source":{"type":"none"},"devices":{"e":{"type":"nic","network":"incusbr0","acceleration":"sriov"}}}`, 403)

	// Volume refresh onto a volume the sandbox did not create.
	p.expect("POST", "/1.0/storage-pools/default/volumes/custom", `{"name":"v","source":{"type":"copy","pool":"default","name":"mine-v","refresh":true}}`, 403)

	// Profiles can apply to VMs, so host-path disks in them are refused.
	q := newTestProxy(t, func(o *Options) { o.Project = "sandbox"; o.TagKey = "" })
	q.expect("POST", "/1.0/profiles", `{"name":"p","devices":{"h":{"type":"disk","source":"/work/src","path":"/h"}}}`, 403)
}

func TestDiskPrefixReplaceable(t *testing.T) {
	base := t.TempDir()
	home := filepath.Join(base, "home")
	proj := filepath.Join(home, "src", "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(proj, link); err != nil {
		t.Fatal(err)
	}
	policy := func(prefix string, osWrite []string) *Policy {
		return &Policy{
			WorkDir:      proj,
			ReadPaths:    []string{proj, link},
			WritePaths:   []string{proj, link},
			OSWritePaths: osWrite,
			ProjectConfig: func() (string, map[string]string, error) {
				return "sandbox", map[string]string{"restricted": "true", "restricted.devices.disk.paths": prefix}, nil
			},
		}
	}
	disk := func(src string) map[string]string {
		return map[string]string{"type": "disk", "source": src, "path": "/h"}
	}

	if err := policy(proj, []string{proj}).checkDevice("h", disk(filepath.Join(proj, "d")), false); err != nil {
		t.Errorf("prefix = the working directory: %v", err)
	}
	// Denylist mode: $HOME is writable, so the directories above the
	// working directory could be renamed away and replaced.
	if err := policy(proj, []string{proj, home}).checkDevice("h", disk(filepath.Join(proj, "d")), false); err == nil {
		t.Error("prefix under a writable $HOME was allowed")
	}
	// A prefix going through a symlink is opened through it by the daemon.
	if err := policy(link, []string{proj}).checkDevice("h", disk(filepath.Join(link, "d")), false); err == nil {
		t.Error("prefix through a symlink was allowed")
	}
}
