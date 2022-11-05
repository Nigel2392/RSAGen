package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
)

var GO_IMPORTS = []string{
	"crypto/rsa",
	"crypto/x509",
	"encoding/base64",
	"encoding/pem",
	"log",
}

func Obfuscate_PrivKey(key *rsa.PrivateKey, obf_len int) error {
	// Encode the private key to PEM format.
	pemPrivKey := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	// Base64 encode the private key.
	b64PrivKey := base64.StdEncoding.EncodeToString(pemPrivKey)
	return Obfuscate(b64PrivKey, true, obf_len)
}

func Obfuscate_PubKey(key *rsa.PublicKey, obf_len int) error {
	// Encode the public key to PEM format.
	pemPubKey := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(key),
	})
	// Base64 encode the public key.
	b64PubKey := base64.StdEncoding.EncodeToString(pemPubKey)
	return Obfuscate(b64PubKey, false, obf_len)
}

func Obfuscate(data string, privkey bool, group_size int) error {
	// Setup filename
	var fname string
	if privkey {
		fname = "privkey.go"

	} else {
		fname = "pubkey.go"
	}
	fname_safe := strings.ReplaceAll(fname, ".", "_")
	fname_safe = strings.ReplaceAll(fname_safe, "-", "_")
	fname_safe = strings.ReplaceAll(fname_safe, " ", "_")

	// Group the data into a list of strings, each of which is
	// group_size characters long.
	// Make sure not to panic if the key is not a multiple of group_size.
	// Split the data
	var groups []string
	for i := 0; i < len(data); i += group_size {
		if i+group_size > len(data) {
			groups = append(groups, data[i:])
		} else {
			groups = append(groups, data[i:i+group_size])
		}
	}
	//
	buf := bytes.Buffer{}
	buf.WriteString("package main\n\n")
	buf.WriteString("import (\n")
	for _, imp := range GO_IMPORTS {
		buf.WriteString(fmt.Sprintf("\t%q\n", imp))
	}
	buf.WriteString(")\n\n")
	// Write all variable groups to the buffer
	for i, group := range groups {
		nowvar := fmt.Sprintf("var %s_%d", fname_safe, i)
		// vars = append(vars, nowvar)
		buf.WriteString(fmt.Sprintf("%s = %q\n", nowvar, group))
	}

	buf.WriteString("var whole_encoded_" + fname_safe + " = ")
	for i := range groups {
		nowvar := fmt.Sprintf("%s_%d", fname_safe, i)
		buf.WriteString(nowvar)
		if i != len(groups)-1 {
			buf.WriteString(" + ")
		}
	}
	buf.WriteString("\nvar decoded_key_" + fname_safe + ", _ = base64.StdEncoding.DecodeString(whole_encoded_" + fname_safe + ")")
	if privkey {
		// Write private key decoding method
		buf.WriteString(`
func PrivKeySTR_to_PrivKey(privkeystr string) *rsa.PrivateKey {
	block, _ := pem.Decode([]byte(privkeystr))
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Println(err)
	}
	return key
}
`)
		buf.WriteString(`
var privkey_str = string(decoded_key_` + fname_safe + `)
var PRIVATE_KEY *rsa.PrivateKey = PrivKeySTR_to_PrivKey(privkey_str)
`)
	} else {
		// Write public key decoding method
		buf.WriteString(`
func PubKeySTR_to_PubKey(pubkeystr string) *rsa.PublicKey {
	block, _ := pem.Decode([]byte(pubkeystr))
	key, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		log.Println(err)
	}
	return key
}
`)
		buf.WriteString(`
var pubkey_str = string(decoded_key_` + fname_safe + `)
var PUBLIC_KEY *rsa.PublicKey = PubKeySTR_to_PubKey(pubkey_str)
	`)
	}
	return os.WriteFile(fname, buf.Bytes(), 0644)
}
