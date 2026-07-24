// devtool: the wallet stand-in for demos and tests. It plays "the person" —
// it holds a secp256k1 root key and Ed25519 agent keys, and it signs the
// EIP-712 attestations (PSA, AgentGrant) and step-up approvals that the PS can
// store and serve but never author. This is the embryo of a future `psd init`.
//
// Subcommands:
//
//	devtool gen-root                                        -> testroot.json (address + priv)
//	devtool gen-agent   --id aauth:x@y                      -> agent.json (jwk + thumbprint + priv)
//	devtool sign-psa    --root testroot.json --psa psa.json          (fills .signature in place)
//	devtool sign-grant  --root testroot.json --grant grant.json [--agent agent.json]
//	devtool sign-approval --root testroot.json (--request req.json | --digest 0x…)
//	devtool revoke      --root testroot.json --nonce N [--ps http://localhost:8090]
//	devtool thumb       --agent agent.json                 -> prints the agent key thumbprint
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"

	"signet.dev/ps/internal/attest"
	"signet.dev/ps/internal/consent"
	"signet.dev/ps/internal/tokens"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "gen-root":
		genRoot()
	case "gen-agent":
		genAgent(os.Args[2:])
	case "sign-psa":
		signPSA(os.Args[2:])
	case "sign-grant":
		signGrant(os.Args[2:])
	case "sign-approval":
		signApproval(os.Args[2:])
	case "revoke":
		revoke(os.Args[2:])
	case "thumb":
		thumb(os.Args[2:])
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: devtool <gen-root|gen-agent|sign-psa|sign-grant|sign-approval|revoke|thumb> [flags]")
	os.Exit(2)
}

// --- key files ------------------------------------------------------------

type rootFile struct {
	Address string `json:"address"` // 0x… EOA
	Priv    string `json:"priv"`    // hex secp256k1 private key
}

type agentFile struct {
	ID         string     `json:"id"`         // aauth:local@domain
	JWK        tokens.JWK `json:"jwk"`        // public key
	Thumbprint string     `json:"thumbprint"` // RFC 7638
	Priv       string     `json:"priv"`       // base64url Ed25519 seed (private)
}

func genRoot() {
	priv, err := ethcrypto.GenerateKey()
	check(err)
	rf := rootFile{
		Address: ethcrypto.PubkeyToAddress(priv.PublicKey).Hex(),
		Priv:    hex.EncodeToString(ethcrypto.FromECDSA(priv)),
	}
	writeJSONFile("testroot.json", rf)
	fmt.Printf("wrote testroot.json — root %s\n", rf.Address)
}

func genAgent(argv []string) {
	fs := flag.NewFlagSet("gen-agent", flag.ExitOnError)
	id := fs.String("id", "", "agent identifier, e.g. aauth:demo@olearylabs.com")
	out := fs.String("out", "agent.json", "output file")
	_ = fs.Parse(argv)
	if *id == "" {
		fatal("gen-agent: --id required")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	check(err)
	jwk := tokens.JWK{Kty: "OKP", Crv: "Ed25519", X: base64.RawURLEncoding.EncodeToString(pub)}
	af := agentFile{
		ID:         *id,
		JWK:        jwk,
		Thumbprint: jwk.Thumbprint(),
		Priv:       base64.RawURLEncoding.EncodeToString(priv.Seed()),
	}
	writeJSONFile(*out, af)
	fmt.Printf("wrote %s — agent %s — thumb %s\n", *out, af.ID, af.Thumbprint)
}

func thumb(argv []string) {
	fs := flag.NewFlagSet("thumb", flag.ExitOnError)
	agentPath := fs.String("agent", "agent.json", "agent key file")
	_ = fs.Parse(argv)
	var af agentFile
	readJSONFile(*agentPath, &af)
	fmt.Println(af.JWK.Thumbprint())
}

// --- signing --------------------------------------------------------------

func signPSA(argv []string) {
	fs := flag.NewFlagSet("sign-psa", flag.ExitOnError)
	rootPath := fs.String("root", "testroot.json", "root key file")
	psaPath := fs.String("psa", "psa.json", "PSA file to sign in place")
	_ = fs.Parse(argv)

	var psa attest.PersonServerAuthorization
	readJSONFile(*psaPath, &psa)
	if psa.Root == "" {
		psa.Root = loadRoot(*rootPath).Address
	}
	digest, err := attest.PSADigest(&psa)
	check(err)
	psa.Signature = signDigest(*rootPath, digest)
	writeJSONFile(*psaPath, psa)
	fmt.Printf("signed %s — root %s covers %d issuer key(s)\n", *psaPath, psa.Root, len(psa.KeyThumbprints))
}

func signGrant(argv []string) {
	fs := flag.NewFlagSet("sign-grant", flag.ExitOnError)
	rootPath := fs.String("root", "testroot.json", "root key file")
	grantPath := fs.String("grant", "grant.json", "AgentGrant file to sign in place")
	agentPath := fs.String("agent", "", "optional agent.json to fill identifier/thumbprint/pubkey")
	_ = fs.Parse(argv)

	var g attest.AgentGrant
	readJSONFile(*grantPath, &g)
	if g.Root == "" {
		g.Root = loadRoot(*rootPath).Address
	}
	if *agentPath != "" {
		var af agentFile
		readJSONFile(*agentPath, &af)
		g.AgentIdentifier = af.ID
		g.AgentThumbprint = af.JWK.Thumbprint()
		g.AgentPubKey = af.JWK.X
	}
	digest, err := attest.AgentGrantDigest(&g)
	check(err)
	g.Signature = signDigest(*rootPath, digest)
	writeJSONFile(*grantPath, g)
	fmt.Printf("signed %s — grant for %s under root %s\n", *grantPath, g.AgentIdentifier, g.Root)
}

func signApproval(argv []string) {
	fs := flag.NewFlagSet("sign-approval", flag.ExitOnError)
	rootPath := fs.String("root", "testroot.json", "root key file")
	reqPath := fs.String("request", "", "consent.Request JSON (from GET /approve/{code})")
	digestHex := fs.String("digest", "", "raw 32-byte ApprovalDigest hex (alternative to --request)")
	chainID := fs.Int64("chain", 8453, "registry chain id (must match the PS)")
	registry := fs.String("registry", "0x0000000000000000000000000000000000000000", "registry address (must match the PS)")
	_ = fs.Parse(argv)

	var digest [32]byte
	switch {
	case *digestHex != "":
		b := mustHex(*digestHex)
		if len(b) != 32 {
			fatal("sign-approval: --digest must be 32 bytes")
		}
		copy(digest[:], b)
	case *reqPath != "":
		var req consent.Request
		readJSONFile(*reqPath, &req)
		d, err := consent.ApprovalDigest(&req, *chainID, *registry)
		check(err)
		digest = d
	default:
		fatal("sign-approval: one of --request or --digest is required")
	}
	sig := signDigest(*rootPath, digest)
	fmt.Println(hexStr(sig))
}

// --- revocation -----------------------------------------------------------

func revoke(argv []string) {
	fs := flag.NewFlagSet("revoke", flag.ExitOnError)
	rootPath := fs.String("root", "testroot.json", "root key file")
	nonce := fs.Uint64("nonce", 0, "the (root, nonce) grant handle to revoke")
	ps := fs.String("ps", "http://localhost:8090", "PS base URL (dev revoke endpoint)")
	_ = fs.Parse(argv)

	root := loadRoot(*rootPath).Address
	u := fmt.Sprintf("%s/dev/revoke?root=%s&nonce=%d", *ps, url.QueryEscape(root), *nonce)
	resp, err := http.Post(u, "application/json", nil)
	check(err)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fatal(fmt.Sprintf("revoke: PS returned %s", resp.Status))
	}
	fmt.Printf("revoked (root=%s nonce=%d) at %s\n", root, *nonce, *ps)
}

// --- crypto + io ----------------------------------------------------------

// signDigest ecdsa-signs a 32-byte digest with the root secp256k1 key. The
// output is [R||S||V] with V in {0,1}, which attest.verifyRootSig accepts.
func signDigest(rootPath string, digest [32]byte) []byte {
	rf := loadRoot(rootPath)
	priv, err := ethcrypto.HexToECDSA(rf.Priv)
	check(err)
	sig, err := ethcrypto.Sign(digest[:], priv)
	check(err)
	return sig
}

func loadRoot(path string) rootFile {
	var rf rootFile
	readJSONFile(path, &rf)
	if rf.Priv == "" {
		fatal("root file missing priv: " + path)
	}
	return rf
}

func readJSONFile(path string, v any) {
	b, err := os.ReadFile(path)
	check(err)
	check(json.Unmarshal(b, v))
}

func writeJSONFile(path string, v any) {
	b, err := json.MarshalIndent(v, "", "  ")
	check(err)
	check(os.WriteFile(path, append(b, '\n'), 0o600))
}

func mustHex(s string) []byte {
	if len(s) >= 2 && (s[:2] == "0x" || s[:2] == "0X") {
		s = s[2:]
	}
	b, err := hex.DecodeString(s)
	check(err)
	return b
}

func hexStr(b []byte) string { return "0x" + hex.EncodeToString(b) }

func check(err error) {
	if err != nil {
		fatal(err.Error())
	}
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, "devtool: "+msg)
	os.Exit(1)
}
