// Package pki implements certificate issuance for homepki: roots,
// intermediates, and leaves. It is concerned only with building the bytes
// of a signed certificate and producing a fresh keypair per request.
// Persistence and encryption of the resulting key live elsewhere
// (internal/store, internal/crypto).
package pki

import (
	"crypto"
	"crypto/x509"
	"net"
	"time"
)

// KeyAlgo identifies a private-key algorithm. Mirrors STORAGE.md §5.3
// certificates.key_algo.
type KeyAlgo string

const (
	RSA     KeyAlgo = "rsa"
	ECDSA   KeyAlgo = "ecdsa"
	Ed25519 KeyAlgo = "ed25519"
)

// KeySpec is the algorithm + parameters pair (e.g. RSA 4096, ECDSA P-256).
type KeySpec struct {
	Algo   KeyAlgo
	Params string // RSA: "2048"|"3072"|"4096". ECDSA: "P-256"|"P-384". Ed25519: "".
}

// Subject names a certificate's subject DN. CN is required; the rest are
// optional.
type Subject struct {
	CN string
	O  string
	OU string
	L  string
	ST string
	C  string
}

// Issued bundles everything an Issue* call produces. Key is the freshly-
// generated private key; the caller must encrypt and persist it before it
// goes out of scope (LIFECYCLE.md §2).
type Issued struct {
	Cert *x509.Certificate
	DER  []byte
	Key  crypto.Signer
}

// Signer is the (cert, key) pair needed to sign a child certificate.
// Constructed by callers that load an existing CA from storage.
type Signer struct {
	Cert *x509.Certificate
	Key  crypto.Signer
}

// RootRequest is the input to IssueRoot. There is no parent — roots are
// self-signed. CRL DP is not set on a root cert (the trust anchor is not
// itself revoked via a CRL it hosts).
type RootRequest struct {
	Subject  Subject
	Key      KeySpec
	Validity time.Duration // not_after = Now + Validity
	Now      time.Time     // zero means time.Now()
}

// IntermediateRequest is the input to IssueIntermediate.
type IntermediateRequest struct {
	Subject    Subject
	Key        KeySpec
	Parent     *Signer
	ParentID   string // UUID of parent in storage; baked into CRL DP
	CRLBaseURL string // e.g. "https://certs.lan"; CRL DP = base + "/crl/" + ParentID + ".crl"
	PathLen    *int   // basicConstraints pathLen; nil to omit
	Validity   time.Duration
	Now        time.Time
}

// LeafRequest is the input to IssueLeaf. At least one of SANDNS / SANIPs is
// required.
type LeafRequest struct {
	Subject    Subject
	Key        KeySpec
	Parent     *Signer
	ParentID   string
	CRLBaseURL string
	SANDNS     []string
	SANIPs     []net.IP
	Validity   time.Duration
	Now        time.Time
}
