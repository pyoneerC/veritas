import os
import subprocess

def run_cmd(cmd):
    print(f"Running: {cmd}")
    subprocess.check_call(cmd, shell=True)

def setup_pki():
    """
    Creates a 3-level certificate chain like the official c2pa-python examples:
    Root CA -> Intermediate CA -> Signing Certificate
    """
    
    # 1. Generate Root CA Key (EC prime256v1)
    run_cmd("openssl ecparam -name prime256v1 -genkey -noout -out root_key.pem")
    
    # 2. Generate Root CA Certificate (Self-Signed)
    run_cmd('openssl req -x509 -new -key root_key.pem -out root_cert.pem -days 365 -nodes -subj "/C=US/ST=CA/L=Somewhere/O=Basalt Root CA/OU=FOR_TESTING_ONLY/CN=Root CA" -config openssl.cnf -extensions v3_ca')
    
    # 3. Generate Intermediate CA Key
    run_cmd("openssl ecparam -name prime256v1 -genkey -noout -out intermediate_key.pem")
    
    # 4. Generate Intermediate CA CSR
    run_cmd('openssl req -new -key intermediate_key.pem -out intermediate.csr -nodes -subj "/C=US/ST=CA/L=Somewhere/O=Basalt Intermediate CA/OU=FOR_TESTING_ONLY/CN=Intermediate CA" -config openssl.cnf')
    
    # 5. Sign Intermediate CA with Root CA
    run_cmd("openssl x509 -req -in intermediate.csr -CA root_cert.pem -CAkey root_key.pem -CAcreateserial -out intermediate_cert.pem -days 365 -extfile openssl.cnf -extensions v3_intermediate")
    
    # 6. Generate Leaf/Signing Key (EC prime256v1)
    run_cmd("openssl ecparam -name prime256v1 -genkey -noout -out leaf_key.pem")
    
    # 7. Generate Leaf CSR
    run_cmd('openssl req -new -key leaf_key.pem -out leaf.csr -nodes -subj "/C=US/ST=CA/L=Somewhere/O=Basalt Signing Cert/OU=FOR_TESTING_ONLY/CN=Basalt Signer" -config openssl.cnf')
    
    # 8. Sign Leaf/Signing CSR with Intermediate CA (Apply v3_leaf extensions)
    run_cmd("openssl x509 -req -in leaf.csr -CA intermediate_cert.pem -CAkey intermediate_key.pem -CAcreateserial -out leaf_cert.pem -days 365 -extfile openssl.cnf -extensions v3_leaf")
    
    # 9. Create Bundle (Signing Cert + Intermediate + Root) - Full chain
    with open("leaf_cert.pem", "r") as leaf, \
         open("intermediate_cert.pem", "r") as intermediate, \
         open("root_cert.pem", "r") as root:
        bundle_content = leaf.read() + intermediate.read() + root.read()
    
    with open("my_cert.pem", "w") as f:
        f.write(bundle_content)
        
    # 10. Convert Leaf Key to PKCS#8 (REQUIRED by c2pa-python)
    run_cmd("openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in leaf_key.pem -out leaf_key_pkcs8.pem")

    # 11. Use PKCS#8 Key as the signing key
    with open("leaf_key_pkcs8.pem", "r") as src, open("my_private_key.pem", "w") as dst:
        dst.write(src.read())

    print("\n=== CERTIFICATES GENERATED ===")
    print("my_cert.pem (Chain: Signing Cert + Intermediate CA + Root CA)")
    print("my_private_key.pem (Signing Key in PKCS#8 format)")
    
    # Verify the chain
    print("\n=== VERIFYING CHAIN ===")
    run_cmd("openssl verify -CAfile root_cert.pem -untrusted intermediate_cert.pem leaf_cert.pem")

if __name__ == "__main__":
    setup_pki()
