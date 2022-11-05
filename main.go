package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"

	"github.com/TwiN/go-color"
)

func ExpPriv_PEM(key *rsa.PrivateKey, filename string) error {
	block, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	err = os.WriteFile(filename, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: block}), 0644)
	if err != nil {
		return err
	}
	return nil
}

func ExpPub_PEM(key *rsa.PublicKey, filename string) error {
	block, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return err
	}
	err = os.WriteFile(filename, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: block}), 0644)
	if err != nil {
		return err
	}
	return nil
}

func GenKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privkey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	return privkey, &privkey.PublicKey, nil
}

func ImpPrivKeyfilePEM(filename string) (*rsa.PrivateKey, error) {
	keyFile, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(keyFile)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return key.(*rsa.PrivateKey), nil
}

func WritePubFromPriv(filename string) error {
	privkey, err := ImpPrivKeyfilePEM(filename)
	if err != nil {
		return err
	}
	ExpPub_PEM(&privkey.PublicKey, "PUBKEY.pem")
	return nil
}

func PrintInfo() {
	str := ` _____   _____         _____            
|  __ \ / ____|  /\   / ____|           
| |__) | (___   /  \ | |  __  ___ _ __  
|  _  / \___ \ / /\ \| | |_ |/ _ \ '_ \ 
| | \ \ ____) / ____ \ |__| |  __/ | | |
|_|  \_\_____/_/    \_\_____|\___|_| |_|

Usage:
` + color.Colorize(color.Blue, "  RSAGen.exe -bits int") + `
  	Number of bits for the keypair (default 2048)
` + color.Colorize(color.Blue, "  RSAGen.exe -generate") + `
  	Generate a new keypair
` + color.Colorize(color.Blue, "  RSAGen.exe -privkey string") + `
  	Private key file
` + color.Colorize(color.Blue, "  RSAGen.exe -privkey string") + `
	Private key file name (default "PRIVKEY.pem")
` + color.Colorize(color.Blue, "  RSAGen.exe -privkey string") + `
	Public key file name (default PUBKEY.pem)
` + color.Colorize(color.Blue, "  RSAGen.exe -obf bool (optional -len)") + `
	Generate obfuscated keypair as golang code.
	-len is the length of the obfuscated key (default 32)`

	fmt.Println(color.Colorize(color.Purple, str))
}

func PrintExtraInfo() {
	fmt.Println(color.Colorize(color.Purple, "About:"))
	fmt.Println("  This program is a simple RSA keypair generator.")
	fmt.Println("  It can also be used to extract the public key from a private key.")

}

func PrintErr(err error) {
	if err != nil {
		fmt.Println(color.Colorize(color.Red, "An error has ocurred: "+err.Error()))
		panic(err)
	}
}

func main() {
	if len(os.Args) == 1 {
		PrintInfo()
		fmt.Println(color.Colorize(color.Red, "Error: No arguments provided"))
		return
	}

	generate := flag.Bool("generate", false, "Generate a new keypair")
	privkey_fname := flag.String("privname", "PRIVKEY.pem", "Private key file name (default: PRIVKEY.pem)")
	pubkey_fname := flag.String("pubname", "PUBKEY.pem", "Public key file name (default: PUBKEY.pem)")
	bits := flag.Int("bits", 2048, "Number of bits for the keypair")
	privkeyfile := flag.String("privkey", "", "Private key file")
	extra_info := flag.Bool("info", false, "Extra info")
	obf_info := flag.Bool("obf", false, "Obfuscate key into a go file")
	obf_len := flag.Int("len", 32, "Length of the obfuscated key")

	flag.Parse()

	if *generate {
		privkey, pubkey, err := GenKeyPair(*bits)
		PrintErr(err)
		if *obf_info {
			err := Obfuscate_PrivKey(privkey, *obf_len)
			PrintErr(err)
			err = Obfuscate_PubKey(pubkey, *obf_len)
			PrintErr(err)
		}
		err = ExpPriv_PEM(privkey, *privkey_fname)
		PrintErr(err)
		err = ExpPub_PEM(pubkey, *pubkey_fname)
		PrintErr(err)
	}
	if *privkeyfile != "" {
		if *generate {
			fmt.Println(color.Colorize(color.Red, "You can't generate a keypair and import a private key at the same time"))
			return
		}
		err := WritePubFromPriv(*privkeyfile)
		PrintErr(err)
	}
	if *extra_info {
		PrintInfo()
		PrintExtraInfo()
	}

}
