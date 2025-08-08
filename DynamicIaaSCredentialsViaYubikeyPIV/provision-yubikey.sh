# 2a – Generate a new key inside the YubiKey PIV (slot 9c)
yubico-piv-tool -s 9c -a generate -o yubikey_pub.pem

# 2b – Export the public key and create a CSR (CN includes serial)
SERIAL=$(yubico-piv-tool -a status | grep 'Serial number' | awk '{print $3}')
cat > yubikey.csr <<EOF
[ req ]
distinguished_name = req_distinguished_name
prompt = no

[ req_distinguished_name ]
CN = yubikey-${SERIAL}.example.com
O = Acme Corp
EOF

yubico-piv-tool -s 9c -a request-csr -i yubikey_pub.pem -o yubikey.csr -O yubikey.csr.cfg

# 2c – Have Vault sign the CSR
vault write -format=json pki/sign/yubikey-client \
      csr=@yubikey.csr \
      common_name="yubikey-${SERIAL}.haxx.ninja" \
      ttl="720h" > signed.json

CERT=$(jq -r .data.certificate signed.json)
echo "$CERT" > yubikey_cert.pem

#Configure Vault policy that grants AWS creds
# policies/aws-terraform.hcl
vault policy write aws-terraform policies/aws-terraform.hcl


# Enable AWS secrets engine
vault secrets enable -path=aws aws
 
# Configure it with a long‑lived IAM user that can assume the Terraform role
vault write aws/config/root \
      access_key=AKIA... \
      secret_key=...
 
# Create a role that maps to the Terraform IAM role (TTL 15m)
vault write aws/roles/terraform-role \
      credential_type=assumed_role \
      role_arn=arn:aws:iam::123456789012:role/vault-terraform \
      ttl=15m
