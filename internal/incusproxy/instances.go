package incusproxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

// instance is the part of an instance (or snapshot, or profile) the policy
// reads. Config and Devices are the object's own, not the profile-expanded
// ones, so a profile cannot lend an instance the tag.
type instance struct {
	Name     string                       `json:"name"`
	Config   map[string]string            `json:"config"`
	Devices  map[string]map[string]string `json:"devices"`
	Profiles []string                     `json:"profiles"`
}

// source is the part of an instance source (api.InstanceSource) the policy
// reads.
type source struct {
	Type    string `json:"type"`
	Source  string `json:"source"`
	Project string `json:"project"`
}

// errNotFound means the daemon answered 404; the proxy then forwards the
// request so the client gets the daemon's own error.
var errNotFound = fmt.Errorf("not found")

// getJSON fetches an object from the daemon in the pinned project and decodes
// its metadata into v.
func (s *Server) getJSON(ctx context.Context, path string, query url.Values, v any) error {
	if query == nil {
		query = url.Values{}
	}
	query.Set("project", s.opts.Project)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://unix.socket"+path+"?"+query.Encode(), nil)
	if err != nil {
		return err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("querying the daemon: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return errNotFound
	}
	var env struct {
		Metadata json.RawMessage `json:"metadata"`
		Error    string          `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return fmt.Errorf("decoding the daemon's reply to %s: %w", path, err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("daemon refused %s: %s", path, env.Error)
	}
	return json.Unmarshal(env.Metadata, v)
}

func instancePath(name string) string { return "/1.0/instances/" + url.PathEscape(name) }

// fetchInstance returns the instance's current state, nil when it does not exist.
func (s *Server) fetchInstance(ctx context.Context, name string) (*instance, error) {
	var inst instance
	if err := s.getJSON(ctx, instancePath(name), nil, &inst); err != nil {
		if err == errNotFound {
			return nil, nil
		}
		return nil, err
	}
	return &inst, nil
}

func (s *Server) isTagged(inst *instance) bool {
	return isTrue(inst.Config[s.opts.TagKey])
}

// requireInstance enforces tagged-only mode for a per-instance request: the
// instance must carry the tag. It returns the instance's current state (nil
// when it does not exist, which the daemon reports itself). Outside
// tagged-only mode it fetches nothing and returns nil.
func (s *Server) requireInstance(ctx context.Context, name string) (*instance, error) {
	if s.opts.TagKey == "" {
		return nil, nil
	}
	inst, err := s.fetchInstance(ctx, name)
	if err != nil || inst == nil {
		return nil, err
	}
	if !s.isTagged(inst) {
		return nil, deny("instance %q was not created by the sandbox (no %s tag); only the sandbox's own instances can be used", name, s.opts.TagKey)
	}
	return inst, nil
}

// checkProfiles validates the profiles an instance is being given: each is
// fetched and its whole configuration checked, so an instance cannot pick up
// a privileged profile someone else defined.
func (s *Server) checkProfiles(ctx context.Context, names []string) error {
	for _, name := range names {
		var prof instance
		if err := s.getJSON(ctx, "/1.0/profiles/"+url.PathEscape(name), nil, &prof); err != nil {
			if err == errNotFound {
				continue // the daemon rejects the request itself
			}
			return err
		}
		if err := s.opts.Policy.checkChanges(prof.Config, nil, prof.Devices, nil); err != nil {
			return deny("profile %q: %v", name, err)
		}
	}
	return nil
}

// checkSourceType refuses instance sources other than an image, nothing, or
// (where allowCopy) a copy of an instance in the same project. Migration and
// conversion pull an instance, with its configuration, from elsewhere.
func (s *Server) checkSourceType(src source, allowCopy bool) error {
	switch src.Type {
	case "", "image", "none":
	case "copy":
		if !allowCopy {
			return deny("instance source type %q is not permitted here", src.Type)
		}
	default:
		return deny("instance source type %q is not permitted by the lite-sandbox incus proxy", src.Type)
	}
	return s.checkProject("source project", src.Project)
}

// checkInstanceCreate validates POST /1.0/instances and, in tagged-only mode,
// tags the new instance.
func (s *Server) checkInstanceCreate(req *http.Request) error {
	if strings.HasPrefix(req.Header.Get("Content-Type"), "application/octet-stream") {
		return deny("importing instance backups is not permitted by the lite-sandbox incus proxy")
	}
	var body struct {
		instance
		Source source `json:"source"`
	}
	raw, err := readJSON(req, &body)
	if err != nil {
		return err
	}
	if err := s.checkSourceType(body.Source, true); err != nil {
		return err
	}
	ctx := req.Context()
	if err := s.opts.Policy.checkChanges(body.Config, nil, body.Devices, nil); err != nil {
		return deny("%v", err)
	}

	profiles := body.Profiles
	setProfiles := false
	if body.Source.Type == "copy" {
		src, err := s.checkCopySource(ctx, body.Source.Source)
		if err != nil {
			return err
		}
		if profiles == nil && src != nil {
			profiles = src.Profiles
		}
	} else if profiles == nil {
		// Without a profile list the daemon falls back to the image's own
		// profiles, which the proxy cannot see; name the daemon's final
		// fallback explicitly instead.
		profiles = []string{"default"}
		setProfiles = true
	}
	if err := s.checkProfiles(ctx, profiles); err != nil {
		return err
	}

	if s.opts.TagKey == "" && !setProfiles {
		return nil
	}
	return rewriteCreate(req, raw, s.opts.TagKey, profiles, setProfiles)
}

// checkCopySource checks the instance (or "instance/snapshot") a copy is made
// from: in tagged-only mode it must be the sandbox's own, and its
// configuration, which the copy inherits, must pass the policy. Volatile keys
// are skipped: the daemon regenerates them for the copy.
func (s *Server) checkCopySource(ctx context.Context, name string) (*instance, error) {
	instName, snap, isSnap := strings.Cut(name, "/")
	parent, err := s.fetchInstance(ctx, instName)
	if err != nil || parent == nil {
		return nil, err
	}
	if s.opts.TagKey != "" && !s.isTagged(parent) {
		return nil, deny("instance %q was not created by the sandbox (no %s tag); only the sandbox's own instances can be copied", instName, s.opts.TagKey)
	}
	src := parent
	if isSnap {
		var sn instance
		if err := s.getJSON(ctx, instancePath(instName)+"/snapshots/"+url.PathEscape(snap), nil, &sn); err != nil {
			if err == errNotFound {
				return nil, nil
			}
			return nil, err
		}
		src = &sn
	}
	cfg := map[string]string{}
	for k, v := range src.Config {
		if !strings.HasPrefix(k, "volatile.") {
			cfg[k] = v
		}
	}
	if err := s.opts.Policy.checkChanges(cfg, nil, src.Devices, nil); err != nil {
		return nil, deny("copy source %q: %v", name, err)
	}
	return src, nil
}

// rewriteCreate re-encodes a create body with the tag added to its config
// (when tagKey is set) and, when setProfiles, an explicit profile list. Keys
// are matched the way encoding/json (and so the daemon) matches them,
// case-insensitively, so no differently-cased duplicate survives to override
// the rewritten one.
func rewriteCreate(req *http.Request, raw []byte, tagKey string, profiles []string, setProfiles bool) error {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return deny("failed to parse request body: %v", err)
	}
	if tagKey != "" {
		cfg := map[string]string{}
		for _, k := range sortedKeys(obj) {
			if strings.EqualFold(k, "config") {
				if string(obj[k]) != "null" {
					if err := json.Unmarshal(obj[k], &cfg); err != nil {
						return deny("failed to parse instance config: %v", err)
					}
				}
				delete(obj, k)
			}
		}
		cfg[tagKey] = "true"
		b, _ := json.Marshal(cfg)
		obj["config"] = b
	}
	if setProfiles {
		for k := range obj {
			if strings.EqualFold(k, "profiles") {
				delete(obj, k)
			}
		}
		b, _ := json.Marshal(profiles)
		obj["profiles"] = b
	}
	out, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	setBody(req, out)
	return nil
}

// newProfiles returns the profiles in next that are not in cur.
func newProfiles(next, cur []string) []string {
	var out []string
	for _, p := range next {
		if !slices.Contains(cur, p) {
			out = append(out, p)
		}
	}
	return out
}

// checkInstanceUpdate validates PUT/PATCH /1.0/instances/{name}: the config
// keys, devices and profiles the request changes.
func (s *Server) checkInstanceUpdate(req *http.Request, name string) error {
	var body instance
	if _, err := readJSON(req, &body); err != nil {
		return err
	}
	cur, err := s.currentForUpdate(req.Context(), name)
	if err != nil || cur == nil {
		return err
	}
	if err := s.opts.Policy.checkChanges(body.Config, cur.Config, body.Devices, cur.Devices); err != nil {
		return deny("%v", err)
	}
	return s.checkProfiles(req.Context(), newProfiles(body.Profiles, cur.Profiles))
}

// currentForUpdate returns the instance a request modifies, enforcing the tag
// in tagged-only mode; nil when it does not exist.
func (s *Server) currentForUpdate(ctx context.Context, name string) (*instance, error) {
	if s.opts.TagKey != "" {
		return s.requireInstance(ctx, name)
	}
	return s.fetchInstance(ctx, name)
}

// checkInstanceRename validates POST /1.0/instances/{name}, which renames,
// moves between pools or cluster members, or (refused) migrates an instance
// out or into another project.
func (s *Server) checkInstanceRename(req *http.Request, name string) error {
	var body struct {
		instance
		Migration bool   `json:"migration"`
		Project   string `json:"project"`
	}
	if _, err := readJSON(req, &body); err != nil {
		return err
	}
	if body.Migration {
		return deny("migrating instances is not permitted by the lite-sandbox incus proxy")
	}
	if err := s.checkProject("target project", body.Project); err != nil {
		return err
	}
	cur, err := s.currentForUpdate(req.Context(), name)
	if err != nil || cur == nil {
		return err
	}
	if err := s.opts.Policy.checkChanges(body.Config, cur.Config, body.Devices, cur.Devices); err != nil {
		return deny("%v", err)
	}
	if body.Profiles == nil {
		return nil
	}
	return s.checkProfiles(req.Context(), newProfiles(body.Profiles, cur.Profiles))
}

// checkSnapshotRename validates POST /1.0/instances/{name}/snapshots/{snap}.
func (s *Server) checkSnapshotRename(req *http.Request, name string) error {
	if _, err := s.requireInstance(req.Context(), name); err != nil {
		return err
	}
	var body struct {
		Migration bool `json:"migration"`
	}
	if _, err := readJSON(req, &body); err != nil {
		return err
	}
	if body.Migration {
		return deny("migrating snapshots is not permitted by the lite-sandbox incus proxy")
	}
	return nil
}

// checkRebuild validates POST /1.0/instances/{name}/rebuild: a fresh image or
// an empty root disk; the instance keeps its (already checked) configuration.
func (s *Server) checkRebuild(req *http.Request, name string) error {
	if _, err := s.requireInstance(req.Context(), name); err != nil {
		return err
	}
	var body struct {
		Source source `json:"source"`
	}
	if _, err := readJSON(req, &body); err != nil {
		return err
	}
	return s.checkSourceType(body.Source, false)
}

// checkImageCreate validates POST /1.0/images. A JSON body publishes an
// instance or snapshot, or copies an image; the daemon treats any body that
// decodes as JSON that way, whatever its Content-Type, so the body is peeked
// and inspected whenever it starts like a JSON object. Other bodies are image
// file uploads and stream through unread.
func (s *Server) checkImageCreate(req *http.Request) error {
	if !strings.HasPrefix(req.Header.Get("Content-Type"), "application/json") {
		br := bufio.NewReader(req.Body)
		first := firstNonSpace(br)
		req.Body = struct {
			io.Reader
			io.Closer
		}{br, req.Body}
		if first != '{' && first != 'n' {
			return nil
		}
		body, err := io.ReadAll(io.LimitReader(br, maxBody+1))
		req.Body.Close()
		if err != nil {
			return fmt.Errorf("failed to read request body: %w", err)
		}
		if len(body) > maxBody {
			return deny("request body too large")
		}
		setBody(req, body)
		var probe any
		if json.Unmarshal(body, &probe) != nil {
			return nil // not JSON after all: an upload
		}
		req.Header.Set("Content-Type", "application/json")
	}
	var body struct {
		Source struct {
			Type    string `json:"type"`
			Name    string `json:"name"`
			Project string `json:"project"`
		} `json:"source"`
	}
	if _, err := readJSON(req, &body); err != nil {
		return err
	}
	if err := s.checkProject("source project", body.Source.Project); err != nil {
		return err
	}
	switch body.Source.Type {
	case "container", "instance", "virtual-machine", "snapshot":
		instName, _, _ := strings.Cut(body.Source.Name, "/")
		if _, err := s.requireInstance(req.Context(), instName); err != nil {
			return err
		}
	}
	return nil
}

// firstNonSpace returns the first byte of br that is not JSON whitespace,
// without consuming it (0 at EOF).
func firstNonSpace(br *bufio.Reader) byte {
	for i := 1; ; i++ {
		b, err := br.Peek(i)
		if err != nil || len(b) < i {
			return 0
		}
		switch c := b[i-1]; c {
		case ' ', '\t', '\r', '\n':
			if i >= 4096 {
				return 0
			}
			continue
		default:
			return c
		}
	}
}

// checkProfileCreate validates POST /1.0/profiles.
func (s *Server) checkProfileCreate(req *http.Request) error {
	var body instance
	if _, err := readJSON(req, &body); err != nil {
		return err
	}
	if err := s.opts.Policy.checkChanges(body.Config, nil, body.Devices, nil); err != nil {
		return deny("%v", err)
	}
	return nil
}

// checkProfileUpdate validates PUT/PATCH /1.0/profiles/{name}: the keys and
// devices the request changes.
func (s *Server) checkProfileUpdate(req *http.Request, name string) error {
	var body instance
	if _, err := readJSON(req, &body); err != nil {
		return err
	}
	var cur instance
	if err := s.getJSON(req.Context(), "/1.0/profiles/"+url.PathEscape(name), nil, &cur); err != nil && err != errNotFound {
		return err
	}
	if err := s.opts.Policy.checkChanges(body.Config, cur.Config, body.Devices, cur.Devices); err != nil {
		return deny("%v", err)
	}
	return nil
}

// checkVolumeCreate validates custom storage volume creation: JSON only (an
// octet-stream body imports a backup or ISO) and copies only from the pinned
// project.
func (s *Server) checkVolumeCreate(req *http.Request) error {
	var body struct {
		Source struct {
			Type    string `json:"type"`
			Project string `json:"project"`
		} `json:"source"`
	}
	if _, err := readJSON(req, &body); err != nil {
		return err
	}
	if body.Source.Type == "migration" {
		return deny("migrating storage volumes is not permitted by the lite-sandbox incus proxy")
	}
	return s.checkProject("source project", body.Source.Project)
}

// serveInstanceList forwards GET /1.0/instances and filters the reply to the
// instances carrying the tag. Entries are either URLs (recursion=0) or objects
// with their config (recursion>=1); URL entries are matched against a
// recursion=1 listing the proxy makes itself.
func (s *Server) serveInstanceList(w http.ResponseWriter, req *http.Request) error {
	out := req.Clone(req.Context())
	out.RequestURI = ""
	out.URL.Scheme, out.URL.Host, out.Host = "http", "unix.socket", "unix.socket"
	out.Header.Del("Accept-Encoding")
	resp, err := s.client.Do(out)
	if err != nil {
		return fmt.Errorf("querying the daemon: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading the daemon's reply: %w", err)
	}

	var env map[string]json.RawMessage
	var entries []json.RawMessage
	if resp.StatusCode == http.StatusOK && json.Unmarshal(body, &env) == nil && json.Unmarshal(env["metadata"], &entries) == nil {
		var tagged map[string]bool
		kept := make([]json.RawMessage, 0, len(entries))
		for _, e := range entries {
			var urlEntry string
			if json.Unmarshal(e, &urlEntry) == nil {
				if tagged == nil {
					if tagged, err = s.taggedNames(req.Context()); err != nil {
						return err
					}
				}
				if tagged[nameFromURL(urlEntry)] {
					kept = append(kept, e)
				}
				continue
			}
			var inst instance
			if json.Unmarshal(e, &inst) == nil && s.isTagged(&inst) {
				kept = append(kept, e)
			}
		}
		env["metadata"], _ = json.Marshal(kept)
		body, _ = json.Marshal(env)
	} else if resp.StatusCode == http.StatusOK {
		return fmt.Errorf("unexpected instance listing from the daemon")
	}
	for k, vs := range resp.Header {
		if k == "Content-Length" || k == "Content-Encoding" {
			continue
		}
		w.Header()[k] = vs
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, bytes.NewReader(body))
	return nil
}

// taggedNames returns the names of the tagged instances in the pinned project.
func (s *Server) taggedNames(ctx context.Context) (map[string]bool, error) {
	var all []instance
	if err := s.getJSON(ctx, "/1.0/instances", url.Values{"recursion": {"1"}}, &all); err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for i := range all {
		if s.isTagged(&all[i]) {
			out[all[i].Name] = true
		}
	}
	return out, nil
}

// nameFromURL returns the instance name of a listing URL entry
// ("/1.0/instances/<name>?project=...").
func nameFromURL(u string) string {
	parsed, err := url.Parse(u)
	if err != nil {
		return ""
	}
	p := parsed.EscapedPath()
	name, err := url.PathUnescape(p[strings.LastIndex(p, "/")+1:])
	if err != nil {
		return ""
	}
	return name
}
