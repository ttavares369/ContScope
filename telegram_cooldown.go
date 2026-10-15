package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"time"
)

func telegramCooldownPath() string {
	return filepath.Join(filepath.Dir(storePath), "telegram-cooldowns.json")
}

// Called under telegramMu. Read afresh so there is no process-local state to lose
// on restart. Failed delivery attempts also consume the cooldown to avoid floods.
func reserveTelegramCooldown(key string, minutes int, now time.Time) (bool, error) {
	last := map[string]time.Time{}
	b, err := os.ReadFile(telegramCooldownPath())
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	if err == nil {
		if err = json.Unmarshal(b, &last); err != nil {
			return false, err
		}
		if last == nil {
			last = map[string]time.Time{}
		}
	}
	for k, at := range last {
		if now.Sub(at) >= 24*time.Hour || at.After(now.Add(5*time.Minute)) {
			delete(last, k)
		}
	}
	if at, ok := last[key]; ok && now.Sub(at) < time.Duration(minutes)*time.Minute {
		return false, nil
	}
	last[key] = now
	// Bound retained keys even when containers are frequently recreated.
	if len(last) > 4096 {
		keys := make([]string, 0, len(last))
		for k := range last {
			if k != key {
				keys = append(keys, k)
			}
		}
		sort.Slice(keys, func(i, j int) bool { return last[keys[i]].Before(last[keys[j]]) })
		for _, k := range keys[:len(last)-4096] {
			delete(last, k)
		}
	}
	b, err = json.Marshal(last)
	if err != nil {
		return false, err
	}
	path := telegramCooldownPath()
	if err = os.WriteFile(path+".tmp", b, 0600); err != nil {
		return false, err
	}
	if err = os.Rename(path+".tmp", path); err != nil {
		return false, err
	}
	return true, nil
}
