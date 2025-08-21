from __future__ import annotations

from typing import Optional

from core.clients.teneo_api import get_campaigns as teneo_get_campaigns


async def get_status(email: str, token: str, name: str, proxy: Optional[str], log):
    campaigns = await teneo_get_campaigns(token, proxy)
    for c in campaigns:
        if c.get("campaignName") == name:
            completed = c.get("completed", False)
            claimable = c.get("claimable", False)
            #log(f"Campaign '{name}' for {email}: completed={completed}, claimable={claimable}")
            if completed:
                return True
            if claimable:
                return "claimable"
            return False
            log(f"Campaign '{name}' not found for {email}")
    return False


