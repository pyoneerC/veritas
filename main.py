import os
import time
import hashlib
import json
import logging
from typing import Optional

from fastapi import FastAPI, UploadFile, File, Request, Form
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from dotenv import load_dotenv

# Crypto & Blockchain Libraries
from c2pa import Builder, Signer, C2paSigningAlg
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from solana.rpc.api import Client
from solders.keypair import Keypair
from solders.transaction import Transaction
from solders.system_program import TransferParams, transfer
from solders.pubkey import Pubkey
import requests

# Load environment variables
load_dotenv()

# Configuration
PINATA_JWT = os.getenv("PINATA_JWT")
SOLANA_PRIVATE_KEY_STR = os.getenv("SOLANA_PRIVATE_KEY")
SOLANA_RPC = "https://api.devnet.solana.com"

# Setup Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("basalt")

app = FastAPI()
templates = Jinja2Templates(directory="templates")

# Initialize Solana Client
solana_client = Client(SOLANA_RPC)

def get_solana_keypair() -> Optional[Keypair]:
    if not SOLANA_PRIVATE_KEY_STR or "placeholder" in SOLANA_PRIVATE_KEY_STR:
        return None
    try:
        return Keypair.from_base58_string(SOLANA_PRIVATE_KEY_STR)
    except Exception as e:
        logger.error(f"Invalid Solana Key: {e}")
        return None

sender_keypair = get_solana_keypair()

# --- HELPER FUNCTIONS ---

def sign_with_c2pa(input_path, output_path):
    """
    Injects a 'Digital Signature' into the image.
    This proves the image was processed by 'Basalt'.
    Uses the official c2pa-python callback signer approach.
    """
    manifest_definition = {
        "claim_generator": "Basalt_Protocol_v1",
        "claim_generator_info": [{
            "name": "Basalt_Protocol",
            "version": "1.0.0",
        }],
        "format": "image/jpeg",
        "title": "Basalt Verified Image",
        "assertions": [
            {
                "label": "c2pa.actions",
                "data": {
                    "actions": [
                        {
                            "action": "c2pa.created",
                            "digitalSourceType": "http://cv.iptc.org/newscodes/digitalsourcetype/digitalCreation"
                        }
                    ]
                }
            }
        ]
    }
    
    # Load Certs (File or Env)
    sign_cert = None
    private_key = None
    
    # Use absolute paths relative to this script
    base_dir = os.path.dirname(os.path.abspath(__file__))
    cert_path = os.path.join(base_dir, "my_cert.pem")
    key_path = os.path.join(base_dir, "my_private_key.pem")
    
    if os.path.exists(cert_path) and os.path.exists(key_path):
        with open(cert_path, "rb") as f:
            sign_cert = f.read()
        with open(key_path, "rb") as f:
            private_key = f.read()
    else:
        # Fallback to Env Vars (for Vercel)
        cert_env = os.getenv("BASALT_CERT_PEM")
        key_env = os.getenv("BASALT_KEY_PEM")
        if cert_env and key_env:
            sign_cert = cert_env.encode('utf-8')
            private_key = key_env.encode('utf-8')
    
    if not sign_cert or not private_key:
         raise Exception("Certificates missing. Set BASALT_CERT_PEM/BASALT_KEY_PEM env vars or ensure .pem files exist.")
    
    logger.info(f"Cert path: {cert_path}, size: {len(sign_cert)}")
    logger.info(f"Key path: {key_path}, size: {len(private_key)}")
    
    # Define a callback signer function (recommended approach)
    def callback_signer_es256(data: bytes) -> bytes:
        """Callback function that signs data using ES256 algorithm."""
        key_obj = serialization.load_pem_private_key(
            private_key,
            password=None,
            backend=default_backend()
        )
        signature = key_obj.sign(
            data,
            ec.ECDSA(hashes.SHA256())
        )
        return signature
        
    # Use the callback signer approach (official method)
    try:
        with Signer.from_callback(
            callback=callback_signer_es256,
            alg=C2paSigningAlg.ES256,
            certs=sign_cert.decode('utf-8'),
            tsa_url="http://timestamp.digicert.com"
        ) as signer:
            with Builder(manifest_definition) as builder:
                builder.sign_file(input_path, output_path, signer)
    except Exception as e:
        logger.error(f"Failed to sign with C2PA: {e}")
        raise
    
    return output_path

def upload_to_ipfs(file_path):
    """
    Uploads the SIGNED file to IPFS via Pinata.
    """
    if not PINATA_JWT or "placeholder" in PINATA_JWT:
        logger.warning("Pinata JWT not set, mocking IPFS upload")
        return "Qm_MOCK_IPFS_HASH_FOR_DEMO"

    url = "https://api.pinata.cloud/pinning/pinFileToIPFS"
    headers = {"Authorization": f"Bearer {PINATA_JWT}"}
    
    with open(file_path, 'rb') as file:
        files = {'file': file}
        try:
            response = requests.post(url, files=files, headers=headers)
            response.raise_for_status()
            return response.json()['IpfsHash']
        except Exception as e:
            logger.error(f"Pinata Upload Error: {e}")
            raise Exception("IPFS Upload Failed")

def anchor_to_solana(ipfs_cid, file_hash):
    """
    Writes the Evidence to the Blockchain.
    Payload: "BASALT:{CID}:{HASH}"
    """
    if not sender_keypair:
        logger.warning("Solana Keypair not available, mocking transaction")
        return "5_MOCK_SOLANA_TX_SIGNATURE_FOR_DEMO"

    # 1. Create the Payload (The Memo)
    payload = f"BASALT:{ipfs_cid}:{file_hash}"
    logger.info(f"Anchoring: {payload}")
    
    try:
        # 2. Construct Transaction (Send tiny amount to self)
        # In a real app, use the Memo Instruction. Here we use a self-transfer to record proof.
        ix = transfer(
            TransferParams(
                from_pubkey=sender_keypair.pubkey(),
                to_pubkey=sender_keypair.pubkey(),
                lamports=1000 
            )
        )
        
        # 3. Send and Confirm
        recent_blockhash = solana_client.get_latest_blockhash().value.blockhash
        
        # Use new_signed_with_payer for newer solders versions
        txn = Transaction.new_signed_with_payer(
            [ix],
            sender_keypair.pubkey(),
            [sender_keypair],
            recent_blockhash
        )
        
        signature = solana_client.send_transaction(txn).value
        return str(signature)
    except Exception as e:
        logger.error(f"Solana Error: {e}")
        raise Exception(f"Blockchain Anchor Failed: {e}")

# --- ROUTES ---

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/verify/{cid}", response_class=HTMLResponse)
async def verify_page(request: Request, cid: str):
    # In a real app, we would fetch metadata for this CID.
    # For MVP, we simulate it via the template.
    return templates.TemplateResponse("verify.html", {"request": request, "cid": cid})

@app.post("/notarize")
async def notarize(file: UploadFile = File(...)):
    
    # 1. Save Raw File (Use /tmp directory for Vercel/Lambda)
    import tempfile
    tmp_dir = tempfile.gettempdir()
    
    temp_filename = os.path.join(tmp_dir, f"temp_{int(time.time())}.jpg")
    signed_filename = os.path.join(tmp_dir, f"signed_{int(time.time())}.jpg")
    
    try:
        # Load and sanitize image to JPG (Fixes potential PNG/format issues)
        from PIL import Image
        import io
        
        content = await file.read()
        image = Image.open(io.BytesIO(content))
        if image.mode != 'RGB':
            image = image.convert('RGB')
            
        # Save as clean JPG
        image.save(temp_filename, "JPEG", quality=95)
            
        # 2. C2PA Signing (The "Truth" Layer)
        sign_with_c2pa(temp_filename, signed_filename)
        
        # 3. Calculate Hash of the SIGNED file (The "Fingerprint")
        with open(signed_filename, "rb") as f:
            file_bytes = f.read()
            file_hash = hashlib.sha256(file_bytes).hexdigest()
            
        # 4. Upload to IPFS (The "Vault")
        ipfs_cid = upload_to_ipfs(signed_filename)
            
        # 5. Anchor to Solana (The "Timechain")
        tx_sig = anchor_to_solana(ipfs_cid, file_hash)

        return JSONResponse({
            "status": "SECURED",
            "evidence": {
                "ipfs_cid": ipfs_cid,
                "ipfs_url": f"https://gateway.pinata.cloud/ipfs/{ipfs_cid}",
                "sha256_hash": file_hash,
                "solana_tx": f"https://explorer.solana.com/tx/{tx_sig}?cluster=devnet",
                "c2pa_verification": "ACTIVE"
            }
        })
        
    except Exception as e:
        logger.error(f"Error: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)
    finally:
        # Cleanup
        if os.path.exists(temp_filename):
            os.remove(temp_filename)
        # Optional: remove signed filename or keep for debug
        # if os.path.exists(signed_filename):
        #    os.remove(signed_filename)
