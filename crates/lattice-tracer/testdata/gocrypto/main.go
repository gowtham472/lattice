// A workload for testing LATTICE's Go tracing: each algorithm is used once, and a TLS 1.3
// handshake runs over loopback.
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/md5"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/rc4"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"os"
	"time"
)

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "wait" {
		time.Sleep(2 * time.Second)
	}
	key := make([]byte, 16)
	block, err := aes.NewCipher(key)
	check(err)
	gcm, err := cipher.NewGCM(block)
	check(err)
	_ = gcm.Seal(nil, make([]byte, 12), []byte("hello"), nil)

	_, err = des.NewTripleDESCipher(make([]byte, 24))
	check(err)
	_, err = rc4.NewCipher(make([]byte, 16))
	check(err)
	fmt.Printf("%x %x %x\n", md5.Sum([]byte("a")), sha1.Sum([]byte("a")), sha256.Sum256([]byte("a")))
	mac := hmac.New(sha1.New, []byte("k"))
	mac.Write([]byte("m"))
	_ = mac.Sum(nil)

	rsaKey, err := rsa.GenerateKey(rand.Reader, 1024)
	check(err)
	_, err = rsa.SignPKCS1v15(rand.Reader, rsaKey, 0, []byte("unhashed"))
	_ = err
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	check(err)
	_, _, err = ed25519.GenerateKey(rand.Reader)
	check(err)
	dk, err := mlkem.GenerateKey768()
	check(err)
	_, _ = dk.EncapsulationKey().Encapsulate()

	// TLS 1.3 over loopback, with Go's default groups (X25519MLKEM768 first)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &ecKey.PublicKey, ecKey)
	check(err)
	certificate := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: ecKey}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{certificate}})
	check(err)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			_, _ = io.Copy(conn, conn)
			conn.Close()
		}
	}()
	pool := x509.NewCertPool()
	parsed, _ := x509.ParseCertificate(der)
	pool.AddCert(parsed)
	conn, err := tls.Dial("tcp", listener.Addr().String(), &tls.Config{RootCAs: pool, ServerName: "localhost"})
	check(err)
	state := conn.ConnectionState()
	fmt.Println("tls", tls.VersionName(state.Version), state.CurveID)
	conn.Close()
}
