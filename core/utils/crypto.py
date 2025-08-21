from __future__ import annotations

from datetime import datetime
import secrets
import string
from typing import Dict

from eth_account import Account
from eth_account.messages import encode_defunct
from web3 import Web3  # noqa: F401  # imported for side-effects in eth_account


def sign_message_hex(private_key: str, message: str) -> str:
    """Signs arbitrary string and returns signature with 0x prefix."""
    message_hash = encode_defunct(text=message)
    signed = Account.sign_message(message_hash, private_key=private_key)
    signature = signed.signature.hex()
    if not signature.startswith("0x"):
        signature = "0x" + signature
    return signature


def sign_siwe_for_form(private_key: str) -> Dict[str, str]:
    """Creates message in format expected by deform:
    - No leading spaces in lines
    - Address in EIP-55 format (checksummed), same in message and address/ethAddress fields
    - Timestamp with milliseconds
    """
    account = Account.from_key(private_key)
    wallet = account.address  # checksummed
    # Generate nonce only from [A-Za-z0-9], as in sniffer examples
    alphabet = string.ascii_letters + string.digits
    nonce = ''.join(secrets.choice(alphabet) for _ in range(17))
    try:
        issued_at = datetime.utcnow().isoformat(timespec="milliseconds") + "Z"
    except TypeError:
        # fallback for old interpreters: manually truncate to milliseconds
        issued_at = datetime.utcnow().isoformat()  # may contain microseconds
        if "." in issued_at:
            base, frac = issued_at.split(".", 1)
            issued_at = base + "." + (frac[:3]) + "Z"
        else:
            issued_at = issued_at + ".000Z"

    message = (
        "extra-points.teneo.pro wants you to sign in with your Ethereum account:\n"
        f"{wallet}\n\n"
        "Sign this message to verify ownership of your wallet address. This request will not trigger a blockchain transaction or cost any gas fees. Form ID: 3ee8174c-5437-46e5-ab09-ce64d6e1b93e\n\n"
        "URI: https://extra-points.teneo.pro\n"
        "Version: 1\n"
        "Chain ID: 1\n"
        f"Nonce: {nonce}\n"
        f"Issued At: {issued_at}"
    )

    signature = sign_message_hex(private_key, message)
    return {"wallet_address": wallet, "signature": signature, "message": message}


