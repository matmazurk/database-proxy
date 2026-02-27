storage "file" {
  path = "/vault/data"
}

listener "tcp" {
  address                            = "0.0.0.0:8200"
  tls_cert_file                      = "/certs/vault-server.crt"
  tls_key_file                       = "/certs/vault-server.key"
  tls_client_ca_file                 = "/certs/ca.crt"
  tls_require_and_verify_client_cert = true
}

plugin_directory = "/vault/plugins"

disable_mlock = true
api_addr      = "https://vault:8200"
