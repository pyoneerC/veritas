import os
import subprocess

def run_cmd(cmd):
    print(f"Running: {cmd}")
    subprocess.check_call(cmd, shell=True)

def setup_pki():
    # 1. Generate Root CA Key (EC prime256v1)
    run_cmd("openssl ecparam -name prime256v1 -genkey -noout -out root_key.pem")
    
    # 2. Generate Root CA Certificate (Self-Signed)
    run_cmd('openssl req -x509 -new -key root_key.pem -out root_cert.pem -days 365 -nodes -subj "/CN=Veritas Root CA" -config openssl.cnf -extensions v3_ca')
    
    # 3. Generate Leaf Key (EC prime256v1)
    run_cmd("openssl ecparam -name prime256v1 -genkey -noout -out leaf_key.pem")
    
    # 4. Generate Leaf CSR
    run_cmd('openssl req -new -key leaf_key.pem -out leaf.csr -nodes -subj "/CN=Veritas Protocol" -config openssl.cnf -extensions v3_req')
    
    # 5. Sign Leaf CSR with Root CA (Apply v3_leaf extensions)
    run_cmd("openssl x509 -req -in leaf.csr -CA root_cert.pem -CAkey root_key.pem -CAcreateserial -out leaf_cert.pem -days 365 -extfile openssl.cnf -extensions v3_leaf")
    
    # 6. Create Bundle (Leaf + Root)
    with open("leaf_cert.pem", "r") as leaf, open("root_cert.pem", "r") as root:
        bundle_content = leaf.read() + root.read()
    
    with open("my_cert.pem", "w") as f:
        f.write(bundle_content)
        
    # 7. Convert Leaf Key to PKCS#8 (REQUIRED by c2pa-python)
    run_cmd("openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in leaf_key.pem -out leaf_key_pkcs8.pem")

    # 8. Use PKCS#8 Key as the signing key
    with open("leaf_key_pkcs8.pem", "r") as src, open("my_private_key.pem", "w") as dst:
        dst.write(src.read())

    print("=== CERTIFICATES GENERATED ===")
    print("my_cert.pem (Chain: Leaf + Root)")
    print("my_private_key.pem (Leaf Key)")

if __name__ == "__main__":
    setup_pki()
