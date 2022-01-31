export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_TOKEN='root'
vault secrets enable pki
vault secrets tune -max-lease-ttl=8760h pki
vault write pki/root/generate/internal common_name=vault.com ttl=8760h # signing CRL
vault write pki/config/urls \
    issuing_certificates="http://127.0.0.1:8200/v1/pki/ca" \
    crl_distribution_points="http://127.0.0.1:8200/v1/pki/crl"
vault write pki/roles/myrole \
    allowed_domains=website.com \
    allow_subdomains=true \
    max_ttl=72h
vault write pki/issue/myrole \
    common_name=www.website.com