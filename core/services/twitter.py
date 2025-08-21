from __future__ import annotations

import base64
import hashlib
import os
import uuid
from typing import Optional

from aiohttp import ClientSession, ClientTimeout
from aiohttp_socks import ProxyConnector
from colorama import Fore
from Jam_Twitter_API.account_sync import TwitterAccountSync
from Jam_Twitter_API.errors import TwitterAccountSuspended, TwitterError, IncorrectData, RateLimitError


async def bind_and_get_one_time_token(email: str, auth_token: str, proxy: Optional[str], log) -> Optional[str]:
    try:
        def gen_verifier(length: int = 43) -> str:
            charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
            rb = os.urandom(length)
            return "".join(charset[b % len(charset)] for b in rb)

        def challenge(v: str) -> str:
            digest = hashlib.sha256(v.encode("ascii")).digest()
            return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")

        verifier = gen_verifier()
        code_challenge = challenge(verifier)

        unique_id = str(uuid.uuid4())
        redirect_url = "https://extra-points.teneo.pro/follow-us-on-x/"
        json_data = '{"oAuthVersion":2,"formId":"3ee8174c-5437-46e5-ab09-ce64d6e1b93e","pageNumber":0}'
        state_raw = f"{unique_id}::{redirect_url}::twitter::{json_data}"
        state_encoded = base64.urlsafe_b64encode(state_raw.encode()).decode()

        client_id = "cmlDZkdkVFRLOElHSVk5dnBOSXI6MTpjaQ"
        redirect_uri = "https://app.deform.cc/oauth2/twitter_callback"
        scope = "tweet.read users.read follows.read offline.access"

        account = TwitterAccountSync.run(auth_token=auth_token, proxy=proxy, setup_session=True)
        bind_result = account.bind_account_v2({
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": scope,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "state": state_encoded,
        })

        if not bind_result:
            log(f"{Fore.RED}Bind Twitter failed for {email}{Fore.RESET}")
            return None

        deform_url = "https://api.deform.cc/"
        payload = {
            "operationName": "FormResponseTwitterOAuth2",
            "variables": {
                "data": {
                    "oAuthToken": bind_result,
                    "oAuthVerifier": verifier,
                    "formFieldId": "221ae09a-68c2-4807-b70c-65bf4f988fd3",
                }
            },
            "query": "mutation FormResponseTwitterOAuth2($data: FormResponseTwitterOAuthInput!) {\n  formResponseTwitterOAuth2(data: $data) {\n    oneTimeToken\n    username\n    __typename\n  }\n}",
        }

        connector = ProxyConnector.from_url(proxy) if proxy else None
        async with ClientSession(connector=connector, timeout=ClientTimeout(total=30)) as session:
            async with session.post(deform_url, json=payload) as resp:
                resp.raise_for_status()
                data = await resp.json()
                if data.get("errors"):
                    msg = data["errors"][0].get("message", "Unknown error")
                    log(f"{Fore.RED}FormResponseTwitterOAuth2 error for {email}: {msg}{Fore.RESET}")
                    return None
                result = data.get("data", {}).get("formResponseTwitterOAuth2")
                if result:
                    return result.get("oneTimeToken")
                log(f"{Fore.RED}No oneTimeToken in deform response for {email}{Fore.RESET}")
                return None
    except TwitterAccountSuspended as error:
        log(f"{Fore.RED}Twitter account blocked for {email}: {error}{Fore.RESET}")
        return None
    except TwitterError as error:
        log(f"{Fore.RED}Twitter error for {email}: {error.error_message} | {error.error_code}{Fore.RESET}")
        return None
    except IncorrectData as error:
        log(f"{Fore.RED}Incorrect data for {email}: {error}{Fore.RESET}")
        return None
    except RateLimitError as error:
        log(f"{Fore.RED}Rate limit exceeded for {email}: {error}{Fore.RESET}")
        return None
    except Exception as e:
        log(f"{Fore.RED}Unexpected error connecting Twitter for {email}: {e}{Fore.RESET}")
        return None


