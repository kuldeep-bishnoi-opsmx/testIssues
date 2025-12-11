module testIssues

go 1.19

require github.com/go-sql-driver/mysql v1.5.0

// SCA Issue 1: Outdated dependency with known vulnerabilities
// This version of go-sql-driver/mysql may have security issues
// SCA Issue 2: Missing dependency version pinning for transitive dependencies
// SCA Issue 3: No dependency vulnerability scanning configured
