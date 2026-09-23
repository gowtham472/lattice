package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"net/http"
)

func signingKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func main() {
	server := &http.Server{
		Addr: ":8443",
		TLSConfig: &tls.Config{
			MinVersion:       tls.VersionTLS13,
			CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519},
		},
	}
	http.HandleFunc("/v1/ledger/entries", entries)
	server.ListenAndServeTLS("ledger.crt", "ledger.key")
}

func entries(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}
