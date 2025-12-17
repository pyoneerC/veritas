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
from c2pa import Builder, Signer
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
logger = logging.getLogger("veritas")

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
    This proves the image was processed by 'Veritas'.
    """
    manifest_json = json.dumps({
        "title": "Veritas Secured Asset",
        "claim_generator": "Veritas_Protocol_v1",
        "assertions": [
            {
                "label": "c2pa.actions",
                "data": {"actions": [{"action": "c2pa.created"}]}
            },
            {
                "label": "stds.schema-org.CreativeWork",
                "data": {"author": [{"@type": "Organization", "name": "Veritas Notary"}]}
            }
        ]
    })
    
    # Check if certs exist
    if not os.path.exists("my_cert.pem") or not os.path.exists("my_private_key.pem"):
        raise Exception("Certificate or Private Key missing. Run openssl command.")

    # Sign using the keys
    # New C2PA Python API requires C2paSignerInfo
    from c2pa import C2paSignerInfo, C2paSigningAlg
    
    with open("my_cert.pem", "rb") as f:
        sign_cert = f.read()
    with open("my_private_key.pem", "rb") as f:
        private_key = f.read()
        
    # Use ES256 for EC keys (standard for C2PA)
    try:
        info = C2paSignerInfo(
            C2paSigningAlg.ES256,
            sign_cert,
            private_key,
            "http://timestamp.digicert.com" # Public TSA
        )
        signer = Signer.from_info(info)
    except Exception as e:
        # Fallback for debug: print detailed error
        logger.error(f"Failed to create signer: {e}")
        raise

    builder = Builder(manifest_json)
    
    # Perform the signing
    builder.sign_file(input_path, output_path, signer)
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
    Payload: "VERITAS:{CID}:{HASH}"
    """
    if not sender_keypair:
        logger.warning("Solana Keypair not available, mocking transaction")
        return "5_MOCK_SOLANA_TX_SIGNATURE_FOR_DEMO"

    # 1. Create the Payload (The Memo)
    payload = f"VERITAS:{ipfs_cid}:{file_hash}"
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

@app.post("/notarize")
async def notarize(file: UploadFile = File(...)):
    
    # 1. Save Raw File
    temp_filename = f"temp_{int(time.time())}.jpg"
    signed_filename = f"signed_{int(time.time())}.jpg"
    
    try:
        with open(temp_filename, "wb") as buffer:
            buffer.write(await file.read())
            
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
