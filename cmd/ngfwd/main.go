package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/msteinert/pam"
	"github.com/vishvananda/netlink"
)

// --- Configuration & Constants ---
const (
	Port       = ":8080"
	AdminGroup = "ngfw-admin"
)

var jwtSecret = []byte("development_secret_replace_in_production")

// --- Models ---
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type AuthResponse struct {
	Token string `json:"token"`
	User  string `json:"user"`
}

type InterfaceDTO struct {
	Index        int      `json:"index"`
	Name         string   `json:"name"`
	Type         string   `json:"type"`
	MTU          int      `json:"mtu"`
	HardwareAddr string   `json:"mac"`
	OperState    string   `json:"state"`
	Addresses    []string `json:"addresses"`
}

// --- Middleware ---
func withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
		token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

// --- Handlers ---

// handleLogin validates against Debian PAM and issues a JWT
func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	// 1. Authenticate against OS PAM
	tx, err := pam.StartFunc("login", req.Username, func(s pam.Style, msg string) (string, error) {
		switch s {
		case pam.PromptEchoOff:
			return req.Password, nil
		case pam.PromptEchoOn, pam.ErrorMsg, pam.TextInfo:
			return "", nil
		}
		return "", fmt.Errorf("unsupported PAM message style")
	})
	
	if err != nil {
		log.Printf("PAM start error for user %s: %v", req.Username, err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if err := tx.Authenticate(0); err != nil {
		log.Printf("Authentication failed for %s: %v", req.Username, err)
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// 2. Verify user is in the ngfw-admin group
	if !isUserInAdminGroup(req.Username) {
		log.Printf("User %s authenticated but is not in %s group", req.Username, AdminGroup)
		http.Error(w, "Forbidden: Insufficient privileges", http.StatusForbidden)
		return
	}

	// 3. Issue JWT
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": req.Username,
		"exp": time.Now().Add(12 * time.Hour).Unix(),
		"iat": time.Now().Unix(),
	})

	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		http.Error(w, "Token generation failed", http.StatusInternalServerError)
		return
	}

	log.Printf("Successful login for OS user: %s", req.Username)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(AuthResponse{Token: tokenString, User: req.Username})
}

// handleInterfaces queries netlink for live interface states
func handleInterfaces(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	links, err := netlink.LinkList()
	if err != nil {
		http.Error(w, "Failed to fetch interfaces", http.StatusInternalServerError)
		return
	}

	var interfaces []InterfaceDTO
	for _, link := range links {
		attrs := link.Attrs()
		
		// Fetch IPs for this link
		addrs, _ := netlink.AddrList(link, netlink.FAMILY_ALL)
		var ipStrings []string
		for _, addr := range addrs {
			ipStrings = append(ipStrings, addr.IPNet.String())
		}

		interfaces = append(interfaces, InterfaceDTO{
			Index:        attrs.Index,
			Name:         attrs.Name,
			Type:         link.Type(),
			MTU:          attrs.MTU,
			HardwareAddr: attrs.HardwareAddr.String(),
			OperState:    attrs.OperState.String(),
			Addresses:    ipStrings,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(interfaces)
}

// --- Utility Functions ---

// isUserInAdminGroup shells out to `id` to check OS group membership.
// While standard Go user lookup exists, os/user can be inconsistent with network-backed groups.
func isUserInAdminGroup(username string) bool {
	cmd := exec.Command("id", "-nG", username)
	out, err := cmd.Output()
	if err != nil {
		return false
	}
	groups := strings.Split(strings.TrimSpace(string(out)), " ")
	for _, g := range groups {
		if g == AdminGroup {
			return true
		}
	}
	return false
}

// CORS Middleware for UI development
func corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		next(w, r)
	}
}

func main() {
	// Ensure we are root (required for netlink and PAM shadow access)
	if os.Getuid() != 0 {
		log.Fatal("ngfwd must be run as root to manage network state and PAM.")
	}

	mux := http.NewServeMux()

	// Unauthenticated endpoints
	mux.HandleFunc("/api/v1/auth/login", corsMiddleware(handleLogin))

	// Authenticated endpoints
	mux.HandleFunc("/api/v1/system/interfaces", corsMiddleware(withAuth(handleInterfaces)))

	log.Printf("Starting NGFW Control Plane API on %s", Port)
	if err := http.ListenAndServe(Port, mux); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
