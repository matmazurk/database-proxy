package main

import (
	"log"
	"os"

	"github.com/matmazurk/database-proxy/proxy"
)

func main() {
	cfg := proxy.Config{
		ListenAddr:  envOrDefault("LISTEN_ADDR", ":5555"),
		TLSCert:     os.Getenv("TLS_CERT"),
		TLSKey:      os.Getenv("TLS_KEY"),
		TLSCA:       os.Getenv("TLS_CA"),
		PGAddr:      envOrDefault("PG_ADDR", "localhost:5432"),
		VaultAddr:   envOrDefault("VAULT_ADDR", "http://localhost:8200"),
		VaultToken:  os.Getenv("VAULT_TOKEN"),
		VaultDBRole: envOrDefault("VAULT_DB_ROLE", "readonly"),
	}

	p, err := proxy.New(cfg)
	if err != nil {
		log.Fatalf("creating proxy: %v", err)
	}

	log.Fatal(p.Listen())
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
