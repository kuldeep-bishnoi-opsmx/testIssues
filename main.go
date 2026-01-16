package main

import (
	"crypto/md5"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"time"
	"unsafe"

	_ "github.com/go-sql-driver/mysql"
)

// SAST Issue 1: Hardcoded credentials
const (
	DB_USER     = "admin"
	DB_PASSWORD = "password123"
	API_KEY     = "sk_live_1234567890abcdef"
	SECRET_KEY  = "my_secret_key_12345"
)

// SAST Issue 2: SQL Injection vulnerability
func getUserData(db *sql.DB, username string) error {
	query := fmt.Sprintf("SELECT * FROM users WHERE username = '%s'", username)
	rows, err := db.Query(query)
	if err != nil {
		return err
	}
	defer rows.Close()
	return nil
}

// SAST Issue 3: Command Injection vulnerability
func executeCommand(userInput string) error {
	cmd := exec.Command("sh", "-c", "echo "+userInput)
	return cmd.Run()
}

// SAST Issue 4: Path Traversal vulnerability
func readFile(filename string) ([]byte, error) {
	return ioutil.ReadFile("/var/www/data/" + filename)
}

// SAST Issue 5: Weak cryptography - MD5 is cryptographically broken
func hashPassword(password string) string {
	hash := md5.Sum([]byte(password))
	return fmt.Sprintf("%x", hash)
}

// SAST Issue 6: Insecure random number generation
func generateToken() string {
	return fmt.Sprintf("%d", rand.Intn(1000000))
}

// SAST Issue 7: Insecure file permissions
func writeConfig(data string) error {
	return ioutil.WriteFile("/tmp/config.json", []byte(data), 0777)
}

// SAST Issue 8: Information disclosure - sensitive data in logs
func logUserInfo(username, password string) {
	fmt.Printf("User login: username=%s, password=%s\n", username, password)
}

// SAST Issue 9: XSS vulnerability (if used in web context)
func renderUserInput(input string) string {
	return "<div>" + input + "</div>"
}

// SAST Issue 10: Insecure HTTP connection
func fetchData(url string) (*http.Response, error) {
	return http.Get(url) // Should use https
}

// SAST Issue 11: Race condition - unprotected shared resource
var globalCounter int

func incrementCounter() {
	globalCounter++ // Not thread-safe
}

// SAST Issue 12: Use of deprecated function
func readOldFile(path string) ([]byte, error) {
	return ioutil.ReadFile(path) // ioutil.ReadFile is deprecated
}

// SAST Issue 14: Server-Side Request Forgery (SSRF) vulnerability
func fetchUserURL(url string) (*http.Response, error) {
	// No validation of URL - allows requests to internal network
	return http.Get(url)
}

// CRITICAL SAST Issue 15: Unsafe Deserialization - Unmarshaling untrusted JSON data
type UserConfig struct {
	Command string `json:"command"`
	Path    string `json:"path"`
	Data    string `json:"data"`
}

func deserializeUserConfig(jsonData []byte) error {
	var config UserConfig
	// CRITICAL: Deserializing untrusted JSON without validation
	// This can lead to remote code execution if the data is used in exec.Command
	if err := json.Unmarshal(jsonData, &config); err != nil {
		return err
	}
	// Dangerous: Executing command from untrusted JSON data
	if config.Command != "" {
		cmd := exec.Command("sh", "-c", config.Command)
		return cmd.Run()
	}
	return nil
}

func main() {
	// SAST Issue 13: Hardcoded connection string with credentials
	dsn := fmt.Sprintf("%s:%s@tcp(localhost:3306)/mydb", DB_USER, DB_PASSWORD)
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer db.Close()

	// Example usage that would trigger SAST issues
	userInput := os.Args[1] // No input validation
	getUserData(db, userInput)
	executeCommand(userInput)
	readFile(userInput)

	// Weak password hashing
	hashed := hashPassword("userpassword")
	fmt.Println("Hashed password:", hashed)

	// Insecure token generation
	token := generateToken()
	fmt.Println("Generated token:", token)

	// Insecure file write
	writeConfig(`{"api_key": "` + API_KEY + `"}`)

	// Information disclosure
	logUserInfo("admin", "secret123")

	// Insecure HTTP
	fetchData("http://example.com/api/data")

	// Race condition
	for i := 0; i < 10; i++ {
		go incrementCounter()
	}
	time.Sleep(100 * time.Millisecond)
	fmt.Println("Counter:", globalCounter)

	// SSRF vulnerability
	if len(os.Args) > 2 {
		fetchUserURL(os.Args[2])
	}

	// CRITICAL: Unsafe deserialization vulnerability
	if len(os.Args) > 3 {
		jsonData := []byte(os.Args[3])
		deserializeUserConfig(jsonData)
	}
	// NEW: Insecure TLS request
	if len(os.Args) > 4 {
		insecureTLSRequest(os.Args[4])
	}

	// NEW: Unsafe memory access
	unsafeMemoryAccess()

	// NEW: IDOR vulnerability - missing authorization
	if len(os.Args) > 5 {
		userID := 1
		fileID := 2
		getUserFile(userID, fileID) // No check if userID owns fileID
	}

	// NEW: Improper error handling
	authenticateUser("admin", "wrongpassword")

	// NEW: Weak session management
	sessionID := generateSessionID()
	fmt.Println("Session ID:", sessionID)
}

// openai secrets
const (
	OPENAI_API_KEY = "sk-proj-1234567890abcdef"
	OPENAI_MODEL   = "gpt-4o-mini"
)

// Vulnerable: user input used in shell command
func commandInjection() {
	userInput := "echo 1 | cat /etc/passwd"
	out, _ := exec.Command("sh", "-c", userInput).Output()
	fmt.Println(string(out))
}

// NEW SAST Issue 16: Insecure TLS Configuration - Disabling certificate verification
func insecureTLSRequest(url string) (*http.Response, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // CRITICAL: Disables certificate verification
		},
	}
	client := &http.Client{Transport: tr}
	return client.Get(url) // Vulnerable to man-in-the-middle attacks
}

// NEW SAST Issue 17: Use of unsafe package - Memory safety violation
func unsafeMemoryAccess() {
	var x int = 42
	ptr := unsafe.Pointer(&x)
	// Dangerous: Direct memory manipulation without bounds checking
	*(*int)(ptr) = 100
	// Even more dangerous: Pointer arithmetic
	ptr2 := uintptr(ptr) + 8
	_ = unsafe.Pointer(ptr2) // Potential buffer overflow
}

// NEW SAST Issue 18: Insecure Direct Object Reference (IDOR) - Missing authorization
func getUserFile(userID int, fileID int) ([]byte, error) {
	// VULNERABLE: No authorization check - any user can access any file
	// Should verify that fileID belongs to userID before accessing
	filename := fmt.Sprintf("/data/user_%d/file_%d.txt", userID, fileID)
	return ioutil.ReadFile(filename) // Missing access control check
}

// NEW SAST Issue 19: Improper Error Handling - Information disclosure
func authenticateUser(username, password string) error {
	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(localhost:3306)/mydb", DB_USER, DB_PASSWORD))
	if err != nil {
		return fmt.Errorf("database connection failed: %v", err) // Leaks internal error details
	}
	defer db.Close()

	query := fmt.Sprintf("SELECT password FROM users WHERE username = '%s'", username)
	var storedPassword string
	err = db.QueryRow(query).Scan(&storedPassword)
	if err != nil {
		// VULNERABLE: Error message reveals whether user exists
		return fmt.Errorf("authentication failed: user '%s' not found: %v", username, err)
	}

	if storedPassword != password {
		// VULNERABLE: Different error messages leak information about account status
		return fmt.Errorf("authentication failed: invalid password for user '%s'", username)
	}
	return nil
}

// NEW SAST Issue 20: Weak Session Management - Predictable session ID
var sessionCounter int

func generateSessionID() string {
	sessionCounter++
	// VULNERABLE: Predictable session ID based on counter and time
	// Attackers can guess or enumerate session IDs
	timestamp := time.Now().Unix()
	return fmt.Sprintf("SESSION_%d_%d", timestamp, sessionCounter)
}
