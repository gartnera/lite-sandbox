package cmd

// Helpers for editing JWCC (JSON with comments and trailing commas) configs
// in place via hujson, so a user's comments and formatting survive.

import (
	"encoding/json"
	"fmt"
	"slices"

	"github.com/tailscale/hujson"
)

// hujsonMarshal JSON-encodes x as a hujson Value.
func hujsonMarshal(x any) (hujson.Value, error) {
	raw, err := json.Marshal(x)
	if err != nil {
		return hujson.Value{}, err
	}
	return hujson.Parse(raw)
}

// hujsonString wraps a Go string as a hujson JSON-string Value.
func hujsonString(s string) hujson.Value {
	return hujson.Value{Value: hujson.String(s)}
}

// hujsonMemberName returns the decoded string name of an object member, or ""
// if the name is not a JSON string literal.
func hujsonMemberName(name hujson.Value) string {
	lit, ok := name.Value.(hujson.Literal)
	if !ok {
		return ""
	}
	var s string
	if err := json.Unmarshal([]byte(lit), &s); err != nil {
		return ""
	}
	return s
}

// hujsonFindMember returns a pointer to the value of the member named key, or
// nil if absent. The pointer aliases into obj.Members, so mutating *result
// mutates the tree.
func hujsonFindMember(obj *hujson.Object, key string) *hujson.Value {
	for i := range obj.Members {
		if hujsonMemberName(obj.Members[i].Name) == key {
			return &obj.Members[i].Value
		}
	}
	return nil
}

// hujsonSetMember sets obj[key] = val, replacing the existing member's value
// (preserving its name and comments) or appending a new member.
func hujsonSetMember(obj *hujson.Object, key string, val hujson.Value) {
	if mv := hujsonFindMember(obj, key); mv != nil {
		mv.Value = val.Value
		mv.BeforeExtra, mv.AfterExtra = val.BeforeExtra, val.AfterExtra
		return
	}
	obj.Members = append(obj.Members, hujson.ObjectMember{
		Name:  hujsonString(key),
		Value: val,
	})
}

// hujsonEnsureObject returns obj[key] as an *Object, creating an empty one if
// the member is absent. It errors if the member exists but is not an object.
func hujsonEnsureObject(obj *hujson.Object, key string) (*hujson.Object, error) {
	if mv := hujsonFindMember(obj, key); mv != nil {
		sub, ok := mv.Value.(*hujson.Object)
		if !ok {
			return nil, fmt.Errorf("%q is not a JSON object", key)
		}
		return sub, nil
	}
	sub := &hujson.Object{}
	hujsonSetMember(obj, key, hujson.Value{Value: sub})
	return sub, nil
}

// hujsonDeleteMember removes obj[key], if present.
func hujsonDeleteMember(obj *hujson.Object, key string) {
	obj.Members = slices.DeleteFunc(obj.Members, func(m hujson.ObjectMember) bool {
		return hujsonMemberName(m.Name) == key
	})
}

// hujsonDeleteMemberIf removes obj[key] if it is the JSON string want.
func hujsonDeleteMemberIf(obj *hujson.Object, key, want string) {
	mv := hujsonFindMember(obj, key)
	if mv == nil {
		return
	}
	lit, ok := mv.Value.(hujson.Literal)
	if ok && lit.Kind() == '"' && lit.String() == want {
		hujsonDeleteMember(obj, key)
	}
}

// hujsonEnsureArray returns obj[key] as an *Array, creating an empty one if
// the member is absent. It errors if the member exists but is not an array.
func hujsonEnsureArray(obj *hujson.Object, key string) (*hujson.Array, error) {
	if mv := hujsonFindMember(obj, key); mv != nil {
		arr, ok := mv.Value.(*hujson.Array)
		if !ok {
			return nil, fmt.Errorf("%q is not a JSON array", key)
		}
		return arr, nil
	}
	arr := &hujson.Array{}
	hujsonSetMember(obj, key, hujson.Value{Value: arr})
	return arr, nil
}
