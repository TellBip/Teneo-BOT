from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from aiohttp import ClientSession, ClientTimeout
from aiohttp_socks import ProxyConnector


TENEO_DEFAULT_HEADERS = {
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "en-US,en;q=0.9,id;q=0.8",
    "Origin": "https://dashboard.teneo.pro",
    "Referer": "https://dashboard.teneo.pro/",
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-site",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
    "X-Api-Key": "OwAG3kib1ivOJG4Y0OCZ8lJETa6ypvsDtGmdhcjB",
}


def _merge_headers(extra: Optional[Dict[str, str]] = None, token: Optional[str] = None) -> Dict[str, str]:
    headers = {**TENEO_DEFAULT_HEADERS, **(extra or {})}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


async def api_post(
    url: str,
    payload: Dict[str, Any],
    headers: Optional[Dict[str, str]] = None,
    proxy: Optional[str] = None,
    timeout_seconds: int = 120,
) -> Dict[str, Any]:
    merged_headers = _merge_headers(headers)
    data = json.dumps(payload)
    merged_headers["Content-Length"] = str(len(data))
    merged_headers["Content-Type"] = "application/json"

    connector = ProxyConnector.from_url(proxy) if proxy else None
    async with ClientSession(connector=connector, timeout=ClientTimeout(total=timeout_seconds)) as session:
        async with session.post(url=url, headers=merged_headers, data=data) as response:
            response.raise_for_status()
            try:
                return await response.json()
            except Exception:
                text = await response.text()
                return {"raw": text}


async def api_get(
    url: str,
    headers: Optional[Dict[str, str]] = None,
    proxy: Optional[str] = None,
    timeout_seconds: int = 60,
) -> Dict[str, Any] | List[Any]:
    merged_headers = _merge_headers(headers)
    connector = ProxyConnector.from_url(proxy) if proxy else None
    async with ClientSession(connector=connector, timeout=ClientTimeout(total=timeout_seconds)) as session:
        async with session.get(url=url, headers=merged_headers) as response:
            response.raise_for_status()
            return await response.json()


# ---- High-level wrappers ----


async def login(email: str, password: str, captcha_token: str, proxy: Optional[str] = None) -> Dict[str, Any]:
    url = "https://auth.teneo.pro/api/login"
    payload = {"email": email, "password": password, "turnstileToken": captcha_token}
    return await api_post(url, payload, proxy=proxy, timeout_seconds=120)


async def signup(email: str, password: str, invite_code: str, captcha_token: str, proxy: Optional[str] = None) -> Dict[str, Any]:
    url = "https://auth.teneo.pro/api/signup"
    payload = {
        "email": email,
        "password": password,
        "invitedBy": invite_code,
        "turnstileToken": captcha_token,
    }
    return await api_post(url, payload, proxy=proxy, timeout_seconds=120)


async def verify_email(token: str, code: str, proxy: Optional[str] = None) -> Dict[str, Any]:
    url = "https://auth.teneo.pro/api/verify-email"
    payload = {"token": token, "verificationCode": code}
    return await api_post(url, payload, proxy=proxy, timeout_seconds=120)


async def isppaccepted(token: Optional[str] = None, proxy: Optional[str] = None) -> Dict[str, Any]:
    url = "https://api.teneo.pro/api/users/isppaccepted"
    headers = {"Authorization": f"Bearer {token}"} if token else None
    return await api_get(url, headers=headers, proxy=proxy, timeout_seconds=30)


async def accept_pp(token: str, proxy: Optional[str] = None) -> Dict[str, Any]:
    url = "https://api.teneo.pro/api/users/accept-pp"
    headers = {"Authorization": f"Bearer {token}"}
    return await api_post(url, {}, headers=headers, proxy=proxy, timeout_seconds=30)


async def smart_id_requirements(token: str, proxy: Optional[str] = None) -> Dict[str, Any]:
    url = "https://api.teneo.pro/api/users/smart-id-requirements"
    headers = {"Authorization": f"Bearer {token}"}
    return await api_get(url, headers=headers, proxy=proxy, timeout_seconds=60)


async def link_wallet(token: str, address: str, signature: str, message: str, proxy: Optional[str] = None) -> Dict[str, Any]:
    url = "https://api.teneo.pro/api/users/link-wallet"
    headers = {"Authorization": f"Bearer {token}"}
    payload = {"address": address, "signature": signature, "message": message}
    return await api_post(url, payload, headers=headers, proxy=proxy, timeout_seconds=60)


async def create_smart_account(token: str, machine_owner: str, nonce: str, signature: str, proxy: Optional[str] = None) -> Dict[str, Any]:
    url = "https://api.teneo.pro/api/peaq/create-smart-account"
    headers = {"Authorization": f"Bearer {token}"}
    payload = {"machineOwner": machine_owner, "nonce": nonce, "signature": signature}
    return await api_post(url, payload, headers=headers, proxy=proxy, timeout_seconds=60)


async def connect_smart_id(token: str, proxy: Optional[str] = None) -> Dict[str, Any]:
    url = "https://api.teneo.pro/api/users/connect-smart-id"
    headers = {"Authorization": f"Bearer {token}"}
    return await api_post(url, {}, headers=headers, proxy=proxy, timeout_seconds=60)


async def get_campaigns(token: str, proxy: Optional[str] = None):
    url = "https://api.teneo.pro/submissions/campaigns"
    headers = {"Authorization": f"Bearer {token}"}
    return await api_get(url, headers=headers, proxy=proxy, timeout_seconds=30)


async def claim_submission(token: str, campaign_type: str = "x", proxy: Optional[str] = None) -> Dict[str, Any]:
    """Claim reward for campaign (default X)."""
    url = "https://api.teneo.pro/api/deform/claim-submission"
    headers = {"Authorization": f"Bearer {token}"}
    payload = {"campaignType": campaign_type}
    return await api_post(url, payload, headers=headers, proxy=proxy, timeout_seconds=30)


