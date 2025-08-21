from __future__ import annotations

from typing import Optional

from colorama import Fore

from core.clients.teneo_api import (
    link_wallet as teneo_link_wallet,
    smart_id_requirements as teneo_smart_id_requirements,
    create_smart_account as teneo_create_smart_account,
)
from core.utils.crypto import sign_message_hex


async def link_wallet(
    email: str,
    token: str,
    wallet: str,
    private_key: str,
    proxy: Optional[str],
    log,
) -> bool:
    message = f"Permanently link wallet to Teneo account: {email} This can only be done once."
    signature = sign_message_hex(private_key, message)
    result = await teneo_link_wallet(token, wallet, signature, message, proxy)
    if result.get("status") == "success" or "wallet" in result:
        log(f"{Fore.GREEN}Wallet {wallet} connected successfully{Fore.RESET}")
        return True
    log(f"{Fore.RED}Failed to connect wallet: {result.get('message', 'Unknown error')}{Fore.RESET}")
    return False


async def get_wallet_status(email: str, token: str, proxy: Optional[str], log):
    result = await teneo_smart_id_requirements(token, proxy)
    wallet_status = result.get("wallet", False)
    hb = result.get("currentHeartbeats", 0)
    met = result.get("requirementsMet", False)
    smart = result.get("existingSmartAccount", False)
    status = result.get("status", "unknown")
    log(
        f"Wallet status: {'Connected' if wallet_status else 'Not connected'}, Heartbeats: {hb}, "
        f"Requirements met: {'Yes' if met else 'No'}, Smart Account: {'Exists' if smart else 'Not exists'}, Status: {status}"
    )
    return result


async def create_smart(
    email: str,
    token: str,
    wallet: str,
    private_key: str,
    proxy: Optional[str],
    log,
) -> bool:
    from datetime import datetime

    nonce = str(int(datetime.now().timestamp() * 1000))
    message = f"Create Teneo Smart Account with nonce: {nonce}"
    signature = sign_message_hex(private_key, message)

    result = await teneo_create_smart_account(token, wallet.lower(), nonce, signature, proxy)
    if result.get("success") is True:
        log(f"{Fore.GREEN}Smart account created. TX: {result.get('txHash', 'N/A')}{Fore.RESET}")
        return True
    log(f"{Fore.RED}Failed to create smart account: {result.get('message', 'Unknown error')}{Fore.RESET}")
    return False


