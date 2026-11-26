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
	Type     string                       `json:"type"`
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
	Refresh bool   `json:"refresh"`
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
func (s *Server) checkProfiles(ctx context.Context, names []string, vm bool) error {
	for _, name := range names {
		var prof instance
		if err := s.getJSON(ctx, "/1.0/profiles/"+url.PathEscape(name), nil, &prof); err != nil {
			if err == errNotFound {
				continue // the daemon rejects the request itself
			}
			return err
		}
		if err := s.opts.Policy.checkChanges(prof.Config, nil, prof.Devices, nil, vm); err != nil {
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
	// The daemon takes a copy's type from its source, and defaults to a
	// container.
	vm := isVM(body.Type)
	profiles := body.Profiles
	setProfiles := false
	if body.Source.Type == "copy" {
		src, srcVM, err := s.checkCopySource(ctx, body.Source.Source)
		if err != nil {
			return err
		}
		vm = srcVM
		if profiles == nil && src != nil {
			profiles = src.Profiles
		}
		// A refresh copies onto an instance that already exists (body.Name),
		// replacing its root filesystem: it must be the sandbox's own.
		if body.Source.Refresh && s.opts.TagKey != "" {
			if _, err := s.requireInstance(ctx, body.Name); err != nil {
				return err
			}
		}
	} else if profiles == nil {
		// Without a profile list the daemon falls back to the image's own
		// profiles, which the proxy cannot see; name the daemon's final
		// fallback explicitly instead.
		profiles = []string{"default"}
		setProfiles = true
	}
	if err := s.opts.Policy.checkChanges(body.Config, nil, body.Devices, nil, vm); err != nil {
		return deny("%v", err)
	}
	if err := s.checkProfiles(ctx, profiles, vm); err != nil {
		return err
	}

	if s.opts.TagKey == "" && !setProfiles {
		return nil
	}
	return rewriteCreate(req, raw, s.opts.TagKey, &body.instance, profiles, setProfiles)
}

// checkCopySource checks the instance (or "instance/snapshot") a copy is made
// from: in tagged-only mode it must be the sandbox's own, and its
// configuration, which the copy inherits, must pass the policy. Volatile keys
// are skipped: the daemon regenerates them for the copy.
func (s *Server) checkCopySource(ctx context.Context, name string) (*instance, bool, error) {
	instName, snap, isSnap := strings.Cut(name, "/")
	parent, err := s.fetchInstance(ctx, instName)
	if err != nil || parent == nil {
		return nil, false, err
	}
	if s.opts.TagKey != "" && !s.isTagged(parent) {
		return nil, false, deny("instance %q was not created by the sandbox (no %s tag); only the sandbox's own instances can be copied", instName, s.opts.TagKey)
	}
	vm := isVM(parent.Type)
	src := parent
	if isSnap {
		var sn instance
		if err := s.getJSON(ctx, instancePath(instName)+"/snapshots/"+url.PathEscape(snap), nil, &sn); err != nil {
			if err == errNotFound {
				return nil, vm, nil
			}
			return nil, false, err
		}
		src = &sn
	}
	cfg := map[string]string{}
	for k, v := range src.Config {
		if !strings.HasPrefix(k, "volatile.") {
			cfg[k] = v
		}
	}
	if err := s.opts.Policy.checkChanges(cfg, nil, src.Devices, nil, vm); err != nil {
		return nil, false, deny("copy source %q: %v", name, err)
	}
	return src, vm, nil
}

// isVM reports whether an instance type is a virtual machine.
func isVM(typ string) bool { return typ == "virtual-machine" }

// rewriteCreate re-encodes a create body with the tag added to its config
// (when tagKey is set) and, when setProfiles, an explicit profile list. The
// config, devices and profiles written are the ones the policy checked
// (checked), not re-read from the raw body; decodeStrict already refused
// bodies whose keys differ only in case, so no other spelling survives to
// override them.
func rewriteCreate(req *http.Request, raw []byte, tagKey string, checked *instance, profiles []string, setProfiles bool) error {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return deny("failed to parse request body: %v", err)
	}
	for k := range obj {
		switch strings.ToLower(k) {
		case "config", "devices":
			delete(obj, k)
		case "profiles":
			if setProfiles {
				delete(obj, k)
			}
		}
	}
	cfg := map[string]string{}
	for k, v := range checked.Config {
		cfg[k] = v
	}
	if tagKey != "" {
		cfg[tagKey] = "true"
	}
	obj["config"], _ = json.Marshal(cfg)
	if checked.Devices != nil {
		obj["devices"], _ = json.Marshal(checked.Devices)
	}
	if setProfiles {
		obj["profiles"], _ = json.Marshal(profiles)
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
	var body struct {
		instance
		Restore string `json:"restore"`
	}
	if _, err := readJSON(req, &body); err != nil {
		return err
	}
	// The daemon reads "other/snap" as another instance's snapshot and
	// applies its configuration to this one.
	if strings.Contains(body.Restore, "/") {
		return deny("restoring another instance's snapshot (%q) is not permitted by the lite-sandbox incus proxy", body.Restore)
	}
	cur, err := s.currentForUpdate(req.Context(), name)
	if err != nil || cur == nil {
		return err
	}
	if err := s.opts.Policy.checkChanges(body.Config, cur.Config, body.Devices, cur.Devices, isVM(cur.Type)); err != nil {
		return deny("%v", err)
	}
	return s.checkProfiles(req.Context(), newProfiles(body.Profiles, cur.Profiles), isVM(cur.Type))
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
	if err := s.opts.Policy.checkChanges(body.Config, cur.Config, body.Devices, cur.Devices, isVM(cur.Type)); err != nil {
		return deny("%v", err)
	}
	if body.Profiles == nil {
		return nil
	}
	return s.checkProfiles(req.Context(), newProfiles(body.Profiles, cur.Profiles), isVM(cur.Type))
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
// instance or snapshot, or copies an image from a server or URL; anything else
// is an image file upload. The daemon decodes the first JSON value of the body
// (trailing data ignored) whatever the Content-Type and treats the body as an
// upload only when that fails, so the proxy decides the same way.
//
// In tagged-only mode the images the sandbox creates are tagged with the
// user.lite-sandbox property: a publish through its properties, an upload
// through the X-Incus-properties / X-LXD-properties headers. Both are refused
// by the daemon when the image already exists, so the tag never lands on
// someone else's image. A copy from a server or URL can merge properties into
// an image that is already there, so it is left untagged and may not set the
// tag itself.
func (s *Server) checkImageCreate(req *http.Request) error {
	isJSON := strings.HasPrefix(req.Header.Get("Content-Type"), "application/json")
	br := bufio.NewReaderSize(req.Body, 8192) // room to peek past firstNonSpace's limit
	orig := req.Body
	req.Body = struct {
		io.Reader
		io.Closer
	}{br, orig}
	if !isJSON {
		first, ok := firstNonSpace(br)
		if !ok {
			return deny("image upload starts with too much whitespace")
		}
		if first != '{' && first != 'n' {
			s.tagUpload(req)
			return nil
		}
	}
	body, err := io.ReadAll(io.LimitReader(br, maxBody+1))
	orig.Close()
	if err != nil {
		return fmt.Errorf("failed to read request body: %w", err)
	}
	if len(body) > maxBody {
		return deny("request body too large")
	}
	setBody(req, body)

	var post struct {
		Source struct {
			Type    string `json:"type"`
			Name    string `json:"name"`
			Project string `json:"project"`
		} `json:"source"`
		Properties map[string]string `json:"properties"`
	}
	if err := json.NewDecoder(bytes.NewReader(body)).Decode(&post); err != nil {
		if isJSON {
			return deny("failed to parse request body: %v", err)
		}
		s.tagUpload(req) // not JSON after all: an upload
		return nil
	}
	if err := s.checkProject("source project", post.Source.Project); err != nil {
		return err
	}
	if s.opts.TagKey == "" {
		return nil
	}
	switch post.Source.Type {
	case "container", "instance", "virtual-machine", "snapshot":
		instName, _, _ := strings.Cut(post.Source.Name, "/")
		if _, err := s.requireInstance(req.Context(), instName); err != nil {
			return err
		}
		return rewriteImagePublish(req, body, s.opts.TagKey, post.Properties)
	}
	// A copy from a server or URL (or of a local image by fingerprint) that
	// the project already holds is merged into that image: the daemon
	// overwrites its profiles, visibility, auto-update and properties.
	// Launching from the remote (`incus launch images:...`) needs none of this.
	return deny("copying images (source type %q) is not permitted in tagged-only mode, as it can rewrite an image the sandbox did not create; launch from the remote image instead", post.Source.Type)
}

// tagUpload tags an uploaded image in tagged-only mode.
func (s *Server) tagUpload(req *http.Request) {
	if s.opts.TagKey == "" {
		return
	}
	v := url.Values{s.opts.TagKey: {"true"}}.Encode()
	req.Header.Add("X-Incus-properties", v)
	req.Header.Add("X-LXD-properties", v)
}

// rewriteImagePublish re-encodes a publish body (its first JSON value) with
// the tag added to its properties.
func rewriteImagePublish(req *http.Request, body []byte, tagKey string, props map[string]string) error {
	var obj map[string]json.RawMessage
	if err := json.NewDecoder(bytes.NewReader(body)).Decode(&obj); err != nil {
		return deny("failed to parse request body: %v", err)
	}
	seen := map[string]bool{}
	for k := range obj {
		lk := strings.ToLower(k)
		if seen[lk] {
			return deny("request body has field %q more than once", k)
		}
		seen[lk] = true
		if lk == "properties" {
			delete(obj, k)
		}
	}
	merged := map[string]string{}
	for k, v := range props {
		merged[k] = v
	}
	merged[tagKey] = "true"
	obj["properties"], _ = json.Marshal(merged)
	out, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	setBody(req, out)
	req.Header.Set("Content-Type", "application/json")
	return nil
}

// requireImage enforces tagged-only mode for a change to an image: only the
// images the sandbox created (tagged) may be changed or deleted, since an
// image's profiles and the image itself are what other launches use.
func (s *Server) requireImage(ctx context.Context, fingerprint string) error {
	if s.opts.TagKey == "" {
		return nil
	}
	var img struct {
		Properties map[string]string `json:"properties"`
	}
	if err := s.getJSON(ctx, "/1.0/images/"+url.PathEscape(fingerprint), nil, &img); err != nil {
		if err == errNotFound {
			return nil
		}
		return err
	}
	if !isTrue(img.Properties[s.opts.TagKey]) {
		return deny("image %q was not created by the sandbox (no %s property); only the sandbox's own images can be changed", fingerprint, s.opts.TagKey)
	}
	return nil
}

// requireAlias enforces tagged-only mode for a change to an existing alias:
// it must point at one of the sandbox's own images, so the sandbox cannot
// repoint (or delete and recreate) an alias someone else launches from.
func (s *Server) requireAlias(ctx context.Context, name string) error {
	if s.opts.TagKey == "" {
		return nil
	}
	var alias struct {
		Target string `json:"target"`
	}
	if err := s.getJSON(ctx, "/1.0/images/aliases/"+url.PathEscape(name), nil, &alias); err != nil {
		if err == errNotFound {
			return nil
		}
		return err
	}
	if err := s.requireImage(ctx, alias.Target); err != nil {
		return deny("alias %q points at an image the sandbox did not create; only aliases of the sandbox's own images can be changed", name)
	}
	return nil
}

// firstNonSpace returns the first byte of br that is not JSON whitespace,
// without consuming it, and false when more than 4096 bytes of whitespace
// come first. It returns 0, true at EOF.
func firstNonSpace(br *bufio.Reader) (byte, bool) {
	for i := 1; i <= 4097; i++ {
		b, err := br.Peek(i)
		if len(b) < i {
			return 0, err == io.EOF
		}
		switch c := b[i-1]; c {
		case ' ', '\t', '\r', '\n':
			continue
		default:
			return c, true
		}
	}
	return 0, false
}

// checkProfileCreate validates POST /1.0/profiles.
func (s *Server) checkProfileCreate(req *http.Request) error {
	var body instance
	if _, err := readJSON(req, &body); err != nil {
		return err
	}
	if err := s.opts.Policy.checkChanges(body.Config, nil, body.Devices, nil, true); err != nil { // a profile can apply to a VM
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
	if err := s.opts.Policy.checkChanges(body.Config, cur.Config, body.Devices, cur.Devices, true); err != nil { // a profile can apply to a VM
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
			Refresh bool   `json:"refresh"`
		} `json:"source"`
		Config map[string]string `json:"config"`
	}
	raw, err := readJSON(req, &body)
	if err != nil {
		return err
	}
	// An empty volume or a copy of one in the project; migrations and backup
	// imports (which also make the daemon fetch a URL) are refused.
	if body.Source.Type != "" && body.Source.Type != "copy" {
		return deny("storage volume source type %q is not permitted by the lite-sandbox incus proxy", body.Source.Type)
	}
	if err := s.checkProject("source project", body.Source.Project); err != nil {
		return err
	}
	if s.opts.TagKey == "" {
		return nil
	}
	// A refresh copies onto a volume that already exists, which may be one
	// the sandbox did not create.
	if body.Source.Refresh {
		return deny("refreshing a storage volume copy is not permitted in tagged-only mode")
	}
	// Tag the volume so the sandbox can delete it later.
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return deny("failed to parse request body: %v", err)
	}
	for k := range obj {
		if strings.EqualFold(k, "config") {
			delete(obj, k)
		}
	}
	cfg := map[string]string{}
	for k, v := range body.Config {
		cfg[k] = v
	}
	cfg[s.opts.TagKey] = "true"
	obj["config"], _ = json.Marshal(cfg)
	out, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	setBody(req, out)
	return nil
}

// requireVolume enforces tagged-only mode for deleting a custom volume: only
// the volumes the sandbox created (tagged) may be deleted.
func (s *Server) requireVolume(ctx context.Context, pool, name string) error {
	if s.opts.TagKey == "" {
		return nil
	}
	var vol struct {
		Config map[string]string `json:"config"`
	}
	if err := s.getJSON(ctx, "/1.0/storage-pools/"+url.PathEscape(pool)+"/volumes/custom/"+url.PathEscape(name), nil, &vol); err != nil {
		if err == errNotFound {
			return nil
		}
		return err
	}
	if !isTrue(vol.Config[s.opts.TagKey]) {
		return deny("storage volume %q was not created by the sandbox (no %s key); only the sandbox's own volumes can be deleted", name, s.opts.TagKey)
	}
	return nil
}

// serveFilteredList forwards a listing (GET /1.0/instances, /1.0/projects)
// and keeps only the entries keep accepts. Entries are either URLs
// (recursion=0) or objects with a name (recursion>=1); keep gets the name and,
// for an object, its JSON.
func (s *Server) serveFilteredList(w http.ResponseWriter, req *http.Request, keep func(ctx context.Context, name string, obj json.RawMessage) (bool, error)) error {
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

	if resp.StatusCode == http.StatusOK {
		var env map[string]json.RawMessage
		var entries []json.RawMessage
		if json.Unmarshal(body, &env) != nil || json.Unmarshal(env["metadata"], &entries) != nil {
			return fmt.Errorf("unexpected listing from the daemon")
		}
		kept := make([]json.RawMessage, 0, len(entries))
		for _, e := range entries {
			var name string
			var obj json.RawMessage
			var urlEntry string
			if json.Unmarshal(e, &urlEntry) == nil {
				name = nameFromURL(urlEntry)
			} else {
				var named struct {
					Name string `json:"name"`
				}
				if json.Unmarshal(e, &named) != nil {
					continue
				}
				name, obj = named.Name, e
			}
			ok, err := keep(req.Context(), name, obj)
			if err != nil {
				return err
			}
			if ok {
				kept = append(kept, e)
			}
		}
		env["metadata"], _ = json.Marshal(kept)
		body, _ = json.Marshal(env)
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

// taggedFilter returns a serveFilteredList filter keeping the instances that
// carry the tag. URL entries are matched against the tagged set, looked up
// once per listing.
func (s *Server) taggedFilter() func(context.Context, string, json.RawMessage) (bool, error) {
	var tagged map[string]bool
	return func(ctx context.Context, name string, obj json.RawMessage) (bool, error) {
		if obj != nil {
			var inst instance
			if json.Unmarshal(obj, &inst) != nil {
				return false, nil
			}
			return s.isTagged(&inst), nil
		}
		if tagged == nil {
			var err error
			if tagged, err = s.taggedNames(ctx); err != nil {
				return false, err
			}
		}
		return tagged[name], nil
	}
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
