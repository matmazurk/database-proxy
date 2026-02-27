package main

import (
	"log"
	"os"

	"github.com/matmazurk/database-proxy/oracle"
	"github.com/matmazurk/database-proxy/postgres"
	"github.com/matmazurk/database-proxy/proxy"
)

func main() {
	dbType := envOrDefault("DB_TYPE", "postgres")

	var handler proxy.DBHandler
	switch dbType {
	case "postgres":
		handler = &postgres.Handler{}
	case "oracle":
		handler = &oracle.Handler{}
	default:
		log.Fatalf("unsupported DB_TYPE: %s", dbType)
	}

	cfg := proxy.Config{
		ListenAddr:  envOrDefault("LISTEN_ADDR", ":5555"),
		TLSCert:     os.Getenv("TLS_CERT"),
		TLSKey:      os.Getenv("TLS_KEY"),
		TLSCA:       os.Getenv("TLS_CA"),
		DBAddr:      envOrDefault("DB_ADDR", envOrDefault("PG_ADDR", "localhost:5432")),
		VaultAddr:   envOrDefault("VAULT_ADDR", "https://localhost:8200"),
		VaultCACert: os.Getenv("VAULT_CA_CERT"),
		VaultDBRole: envOrDefault("VAULT_DB_ROLE", "readonly"),
	}

	p, err := proxy.New(cfg, handler)
	if err != nil {
		log.Fatalf("creating proxy: %v", err)
	}

	log.Printf("starting proxy with db_type=%s", dbType)
	log.Fatal(p.Listen())
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
