package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Configuration via environment variables
var (
	port           = getEnv("PORT", "8080")
	dataDir        = getEnv("DATA_DIR", "./data")
	statsAPIToken  = os.Getenv("STATS_API_TOKEN")
	hmacSecret     = os.Getenv("HMAC_SECRET")
)

var (
	// 1x1 transparent GIF (43 bytes), base64 encoded
	pixelData = func() []byte {
		b64 := "R0lGODlhAQABAIAAAAAAAP///yH5BAAAAAAALAAAAAABAAEAAAICRAEAOw=="
		data, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			panic("invalid pixel base64: " + err.Error())
		}
		return data
	}()

	tokenRegex   = regexp.MustCompile(`^[A-Za-z0-9\-_]{43}$`)
	mailIDRegex  = regexp.MustCompile(`^\d+$`)
)

// TrackEvent represents a single email open event.
type TrackEvent struct {
	MailID    int64  `json:"mail_id"`
	Token     string `json:"token"`
	IP        string `json:"ip"`
	Country   string `json:"country,omitempty"`
	UserAgent string `json:"user_agent"`
	Timestamp int64  `json:"timestamp"`
}

// StatsResponse is the aggregated statistics response.
type StatsResponse struct {
	MailID       int64    `json:"mail_id"`
	TotalOpens   int      `json:"total_opens"`
	FirstOpened  *int64   `json:"first_opened_at,omitempty"`
	LastOpened   *int64   `json:"last_opened_at,omitempty"`
	UniqueIPs    []string `json:"unique_ips,omitempty"`
	Countries    []string `json:"countries,omitempty"`
	UserAgents   []string `json:"user_agents,omitempty"`
}

// fileMutex protects concurrent writes to the same log file.
var fileMutex sync.Mutex

func main() {
	// Ensure data directory exists
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		log.Fatalf("Failed to create data directory %s: %v", dataDir, err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/track", handleTrack)
	mux.HandleFunc("/track/", handleTrack)
	mux.HandleFunc("/stats", handleStats)
	mux.HandleFunc("/stats/", handleStats)
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/", handleHealth)

	handler := corsMiddleware(mux)

	log.Printf("NovaMail Tracker starting on :%s", port)
	log.Printf("Data directory: %s", dataDir)
	log.Printf("Stats API: %s", map[bool]string{true: "enabled", false: "DISABLED (no STATS_API_TOKEN)"}[statsAPIToken != ""])
	log.Printf("HMAC verification: %s", map[bool]string{true: "enabled", false: "DISABLED (no HMAC_SECRET)"}[hmacSecret != ""])

	if err := http.ListenAndServe(":"+port, handler); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

// --- Handlers ---

func handleTrack(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodOptions {
		writePixel(w)
		return
	}

	mailIDStr := r.URL.Query().Get("e")
	token := r.URL.Query().Get("t")
	signature := r.URL.Query().Get("s")

	// Validate — always return pixel even on invalid params
	var mailID int64
	valid := true
	if !mailIDRegex.MatchString(mailIDStr) {
		valid = false
	}
	if !tokenRegex.MatchString(token) {
		valid = false
	}
	if valid {
		mailID, _ = strconv.ParseInt(mailIDStr, 10, 64)
	}

	// HMAC-SHA256 signature verification (M3-10)
	if valid && hmacSecret != "" {
		if signature == "" {
			// Missing signature with HMAC configured — reject silently
			writePixel(w)
			return
		}
		mac := hmac.New(sha256.New, []byte(hmacSecret))
		mac.Write([]byte(mailIDStr + token))
		expected := hex.EncodeToString(mac.Sum(nil))
		if signature != expected {
			// Forged or tampered — do NOT log event, return pixel silently
			writePixel(w)
			return
		}
	}

	if valid {
		// Extract client info
		ip := r.Header.Get("X-Forwarded-For")
		if ip == "" {
			// Try CF-Connecting-IP (if behind Cloudflare)
			ip = r.Header.Get("CF-Connecting-IP")
		}
		if ip == "" {
			// Fall back to remote address
			parts := strings.SplitN(r.RemoteAddr, ":", 2)
			ip = parts[0]
		}
		// Take first IP from X-Forwarded-For
		if idx := strings.Index(ip, ","); idx > 0 {
			ip = strings.TrimSpace(ip[:idx])
		}

		country := r.Header.Get("CF-IPCountry")
		if country == "" {
			country = r.Header.Get("X-Geo-Country")
		}
		userAgent := r.Header.Get("User-Agent")

		event := TrackEvent{
			MailID:    mailID,
			Token:     token,
			IP:        ip,
			Country:   country,
			UserAgent: userAgent,
			Timestamp: time.Now().UnixMilli(),
		}

		// Write event to file asynchronously
		go logEvent(event)
	}

	writePixel(w)
}

func handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Authenticate
	apiToken := r.URL.Query().Get("api_token")
	if statsAPIToken != "" && apiToken != statsAPIToken {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "unauthorized"})
		return
	}

	mailIDStr := r.URL.Query().Get("mail_id")
	if !mailIDRegex.MatchString(mailIDStr) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid mail_id"})
		return
	}

	mailID, _ := strconv.ParseInt(mailIDStr, 10, 64)
	events, err := readEvents(mailID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	if len(events) == 0 {
		writeJSON(w, http.StatusOK, StatsResponse{MailID: mailID, TotalOpens: 0})
		return
	}

	// Aggregate
	timestamps := make([]int64, len(events))
	ipSet := make(map[string]bool)
	countrySet := make(map[string]bool)
	uaSet := make(map[string]bool)

	for i, e := range events {
		timestamps[i] = e.Timestamp
		ipSet[e.IP] = true
		if e.Country != "" {
			countrySet[e.Country] = true
		}
		if e.UserAgent != "" {
			uaSet[e.UserAgent] = true
		}
	}

	sort.Slice(timestamps, func(i, j int) bool { return timestamps[i] < timestamps[j] })

	firstOpened := timestamps[0]
	lastOpened := timestamps[len(timestamps)-1]

	stats := StatsResponse{
		MailID:     mailID,
		TotalOpens: len(events),
		FirstOpened:  &firstOpened,
		LastOpened:   &lastOpened,
		UniqueIPs:  sortedKeys(ipSet),
		Countries:  sortedKeys(countrySet),
		UserAgents: sortedKeys(uaSet),
	}

	writeJSON(w, http.StatusOK, stats)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "service": "novamail-tracker"})
}

// --- Storage ---

func logPath(mailID int64) string {
	return filepath.Join(dataDir, fmt.Sprintf("%d.jsonl", mailID))
}

func logEvent(event TrackEvent) {
	line, err := json.Marshal(event)
	if err != nil {
		log.Printf("Failed to marshal event: %v", err)
		return
	}

	fileMutex.Lock()
	defer fileMutex.Unlock()

	f, err := os.OpenFile(logPath(event.MailID), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("Failed to open log file: %v", err)
		return
	}
	defer f.Close()

	if _, err := f.Write(append(line, '\n')); err != nil {
		log.Printf("Failed to write event: %v", err)
	}
}

func readEvents(mailID int64) ([]TrackEvent, error) {
	f, err := os.Open(logPath(mailID))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var events []TrackEvent
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var event TrackEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			log.Printf("Skipping malformed log line: %v", err)
			continue
		}
		events = append(events, event)
	}

	return events, scanner.Err()
}

// --- Middleware ---

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")

		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Headers", "*")
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// --- Helpers ---

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writePixel(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "image/gif")
	w.Header().Set("Content-Length", fmt.Sprint(len(pixelData)))
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	w.Write(pixelData)
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}