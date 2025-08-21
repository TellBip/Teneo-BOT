from __future__ import annotations

from typing import Optional

from core.clients.teneo_api import login as teneo_login, signup as teneo_signup, verify_email as teneo_verify_email


async def login(email: str, password: str, captcha_token: str, proxy: Optional[str]) -> Optional[str]:
    result = await teneo_login(email, password, captcha_token, proxy)
    return result.get("access_token")


async def signup(email: str, password: str, invite: str, captcha_token: str, proxy: Optional[str]):
    return await teneo_signup(email, password, invite, captcha_token, proxy)


async def verify(token: str, code: str, proxy: Optional[str]):
    return await teneo_verify_email(token, code, proxy)


