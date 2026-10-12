package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Tag labels are presentation-only metadata; no remote host changes are made.
type ServerTag struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Color string `json:"color"`
}

var tagColors = map[string]bool{
	"blue": true, "teal": true, "green": true, "violet": true,
	"orange": true, "red": true, "pink": true, "slate": true,
}

func tagFile() string { return filepath.Join(filepath.Dir(storePath), "server-tags.json") }
func readTags() ([]ServerTag, error) {
	data, err := os.ReadFile(tagFile())
	if errors.Is(err, os.ErrNotExist) {
		return []ServerTag{}, nil
	}
	if err != nil {
		return nil, err
	}
	var tags []ServerTag
	if err = json.Unmarshal(data, &tags); err != nil {
		return nil, err
	}
	if tags == nil {
		return []ServerTag{}, nil
	}
	return tags, nil
}
func saveTags(tags []ServerTag) error {
	b, err := json.MarshalIndent(tags, "", "  ")
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(tagFile()), 0700); err != nil {
		return err
	}
	tmp := tagFile() + ".tmp"
	if err = os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, tagFile())
}
func validTag(t ServerTag) bool {
	if !tagColors[t.Color] || utf8.RuneCountInString(t.Name) < 1 || utf8.RuneCountInString(t.Name) > 48 {
		return false
	}
	for _, r := range t.Name {
		if unicode.IsControl(r) {
			return false
		}
	}
	return strings.TrimSpace(t.Name) != ""
}
func uniqueTagName(tags []ServerTag, tag ServerTag) bool {
	for _, other := range tags {
		if other.ID != tag.ID && strings.EqualFold(other.Name, tag.Name) {
			return false
		}
	}
	return true
}
func validTagIDs(ids []string, tags []ServerTag) bool {
	if len(ids) > 8 {
		return false
	}
	present := map[string]bool{}
	for _, tag := range tags {
		present[tag.ID] = true
	}
	seen := map[string]bool{}
	for _, id := range ids {
		if !safe.MatchString(id) || !present[id] || seen[id] {
			return false
		}
		seen[id] = true
	}
	return true
}
func readTagBody(w http.ResponseWriter, r *http.Request) (ServerTag, error) {
	r.Body = http.MaxBytesReader(w, r.Body, 2048)
	var t ServerTag
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&t); err != nil {
		return t, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return t, errors.New("invalid JSON payload")
	}
	t.Name = strings.TrimSpace(t.Name)
	return t, nil
}
func serveTags(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()
	tags, err := readTags()
	if err != nil {
		jsonResponse(w, 500, map[string]string{"error": "Cannot read tag registry"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		jsonResponse(w, 200, tags)
	case http.MethodPost:
		t, e := readTagBody(w, r)
		if e != nil || t.ID != "" || !validTag(t) {
			jsonResponse(w, 400, map[string]string{"error": "Tag name must be 1–48 characters; choose a supported color"})
			return
		}
		if !uniqueTagName(tags, t) {
			jsonResponse(w, 409, map[string]string{"error": "A tag with this name already exists"})
			return
		}
		if len(tags) >= 80 {
			jsonResponse(w, 409, map[string]string{"error": "Limit of 80 tags reached"})
			return
		}
		id := make([]byte, 8)
		if _, e = rand.Read(id); e != nil {
			http.Error(w, "Failed to create tag", 500)
			return
		}
		t.ID = hex.EncodeToString(id)
		tags = append(tags, t)
		if e = saveTags(tags); e != nil {
			http.Error(w, "Failed to save tag", 500)
			return
		}
		jsonResponse(w, 201, t)
	case http.MethodPatch:
		t, e := readTagBody(w, r)
		if e != nil || !safe.MatchString(t.ID) || !validTag(t) {
			jsonResponse(w, 400, map[string]string{"error": "Invalid tag"})
			return
		}
		if !uniqueTagName(tags, t) {
			jsonResponse(w, 409, map[string]string{"error": "Tag name already in use"})
			return
		}
		for i := range tags {
			if tags[i].ID == t.ID {
				tags[i].Name = t.Name
				tags[i].Color = t.Color
				if e = saveTags(tags); e != nil {
					http.Error(w, "Failed to save tag", 500)
					return
				}
				jsonResponse(w, 200, tags[i])
				return
			}
		}
		http.NotFound(w, r)
	case http.MethodDelete:
		var body struct {
			ID string `json:"id"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, 512)
		if json.NewDecoder(r.Body).Decode(&body) != nil || !safe.MatchString(body.ID) {
			http.Error(w, "Invalid tag", 400)
			return
		}
		found := false
		kept := make([]ServerTag, 0, len(tags))
		for _, t := range tags {
			if t.ID == body.ID {
				found = true
			} else {
				kept = append(kept, t)
			}
		}
		if !found {
			http.NotFound(w, r)
			return
		}
		servers, e := load()
		if e != nil {
			http.Error(w, "Cannot read servers", 500)
			return
		}
		original := make([]Server, len(servers))
		copy(original, servers)
		for i := range servers {
			selected := make([]string, 0, len(servers[i].Tags))
			for _, id := range servers[i].Tags {
				if id != body.ID {
					selected = append(selected, id)
				}
			}
			servers[i].Tags = selected
		}
		// Preserve references in case either filesystem operation fails.
		if e = save(servers); e != nil {
			http.Error(w, "Cannot update server assignments", 500)
			return
		}
		if e = saveTags(kept); e != nil {
			_ = save(original)
			http.Error(w, "Cannot remove tag", 500)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", "GET, POST, PATCH, DELETE")
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}
func serveTagAssignments(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		w.Header().Set("Allow", "PUT")
		w.WriteHeader(405)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 2048)
	var input struct {
		ServerID string   `json:"serverId"`
		Tags     []string `json:"tags"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if dec.Decode(&input) != nil || !safe.MatchString(input.ServerID) {
		http.Error(w, "Invalid assignment", 400)
		return
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		http.Error(w, "Invalid assignment", 400)
		return
	}
	mu.Lock()
	defer mu.Unlock()
	tags, e := readTags()
	if e != nil {
		http.Error(w, "Cannot load tags", 500)
		return
	}
	if !validTagIDs(input.Tags, tags) {
		jsonResponse(w, 400, map[string]string{"error": "Select up to eight existing tags"})
		return
	}
	servers, e := load()
	if e != nil {
		http.Error(w, "Cannot load servers", 500)
		return
	}
	for i := range servers {
		if servers[i].ID != input.ServerID {
			continue
		}
		servers[i].Tags = append([]string{}, input.Tags...)
		if e = save(servers); e != nil {
			http.Error(w, "Cannot save assignment", 500)
			return
		}
		jsonResponse(w, 200, map[string]any{"serverId": input.ServerID, "tags": servers[i].Tags})
		return
	}
	http.NotFound(w, r)
}
