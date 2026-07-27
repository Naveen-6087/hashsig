package lms

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// FileStore persists state as JSON with an atomic write-fsync-rename, so a
// crash leaves either the old or the new state on disk, never a partial file.
type FileStore struct {
	Path string
}

func (f FileStore) Save(s State) error {
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	dir := filepath.Dir(f.Path)
	tmp, err := os.CreateTemp(dir, ".lms-state-*")
	if err != nil {
		return err
	}
	cleanup := func(err error) error {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return cleanup(err)
	}
	if err := tmp.Sync(); err != nil {
		return cleanup(err)
	}
	if err := tmp.Close(); err != nil {
		return cleanup(err)
	}
	if err := os.Rename(tmp.Name(), f.Path); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	syncDir(dir)
	return nil
}

func (f FileStore) Load() (State, error) {
	data, err := os.ReadFile(f.Path)
	if err != nil {
		return State{}, err
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return State{}, fmt.Errorf("%w: state file: %v", ErrMalformed, err)
	}
	return s, nil
}

// syncDir makes the rename durable where the platform supports it.
func syncDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	_ = d.Sync()
	d.Close()
}
