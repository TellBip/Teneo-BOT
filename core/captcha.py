import asyncio
import re
from typing import Optional
from capmonster_python import TurnstileTask, RecaptchaV2Task
from twocaptcha import TwoCaptcha
from httpx import AsyncClient
from core.config.config import (
    CFLSOLVER_BASE_URL,
    CAPTCHA_WEBSITE_KEY,
    CAPTCHA_WEBSITE_URL,
    CAPTCHA_WEBSITE_KEY2,
    CAPTCHA_WEBSITE_URL2
)

class ServiceCapmonster:
    def __init__(self, api_key):
        self.capmonster = TurnstileTask(api_key)

    def get_captcha_token(self):
        task_id = self.capmonster.create_task(
            website_key=CAPTCHA_WEBSITE_KEY,
            website_url=CAPTCHA_WEBSITE_URL
        )
        return self.capmonster.join_task_result(task_id).get("token")

    async def get_captcha_token_async(self):
        return await asyncio.to_thread(self.get_captcha_token)

    # Add alias for compatibility
    async def solve_captcha(self):
        return await self.get_captcha_token_async()

class ServiceCapmonster2:
    def __init__(self, api_key):
        self.capmonster = RecaptchaV2Task(api_key)

    def get_captcha_token(self):
        task_id = self.capmonster.create_task(
            website_key=CAPTCHA_WEBSITE_KEY2,
            website_url=CAPTCHA_WEBSITE_URL2
        )
        return self.capmonster.join_task_result(task_id).get("token")

    async def get_captcha_token_async(self):
        return await asyncio.to_thread(self.get_captcha_token)

    # Add alias for compatibility
    async def solve_captcha(self):
        return await self.get_captcha_token_async()
    
from anticaptchaofficial.turnstileproxyless import *
from anticaptchaofficial.recaptchav2proxyless import *
class ServiceAnticaptcha:
    def __init__(self, api_key):
        self.api_key = api_key
        self.solver = turnstileProxyless()
        self.solver.set_verbose(1)
        self.solver.set_key(self.api_key)
        self.solver.set_website_url(CAPTCHA_WEBSITE_URL)    
        self.solver.set_website_key(CAPTCHA_WEBSITE_KEY)
        self.solver.set_action("login")
    
    def get_captcha_token(self):
        captcha_token = self.solver.solve_and_return_solution()
        return captcha_token

    async def get_captcha_token_async(self):
        return await asyncio.to_thread(self.get_captcha_token)

    # Add alias for compatibility
    async def solve_captcha(self):
        return await self.get_captcha_token_async()
    
class ServiceAnticaptcha2:
    def __init__(self, api_key):
        self.api_key = api_key
        self.solver = recaptchaV2Proxyless()
        self.solver.set_verbose(1)
        self.solver.set_key(self.api_key)
        self.solver.set_website_url(CAPTCHA_WEBSITE_URL2)    
        self.solver.set_website_key(CAPTCHA_WEBSITE_KEY2)
    
    def get_captcha_token(self):
        captcha_token = self.solver.solve_and_return_solution()
        return captcha_token

    async def get_captcha_token_async(self):
        return await asyncio.to_thread(self.get_captcha_token)

    # Add alias for compatibility
    async def solve_captcha(self):
        return await self.get_captcha_token_async()
    
class Service2Captcha:
    def __init__(self, api_key):
        self.solver = TwoCaptcha(api_key)
    def get_captcha_token(self):
        captcha_token = self.solver.turnstile(sitekey=CAPTCHA_WEBSITE_KEY, url=CAPTCHA_WEBSITE_URL)

        if 'code' in captcha_token:
            captcha_token = captcha_token['code']

        return captcha_token

    async def get_captcha_token_async(self):
        return await asyncio.to_thread(self.get_captcha_token)

    # Add alias for compatibility
    async def solve_captcha(self):
        return await self.get_captcha_token_async()
    
class Service2Captcha2:
    def __init__(self, api_key):
        self.solver = TwoCaptcha(api_key)
    def get_captcha_token(self):
        captcha_token = self.solver.recaptcha(sitekey=CAPTCHA_WEBSITE_KEY2, url=CAPTCHA_WEBSITE_URL2)

        if 'code' in captcha_token:
            captcha_token = captcha_token['code']

        return captcha_token

    async def get_captcha_token_async(self):
        return await asyncio.to_thread(self.get_captcha_token)

    # Add alias for compatibility
    async def solve_captcha(self):
        return await self.get_captcha_token_async()

class CFLSolver:
    def __init__(
            self,
            api_key: str,
            session: AsyncClient,
            proxy: Optional[str] = None,
    ):
        self.api_key = api_key
        self.proxy = proxy
        self.base_url = CFLSOLVER_BASE_URL
        self.session = session

    def _format_proxy(self, proxy: str) -> str:
        if not proxy:
            return None
        if "@" in proxy:
            return proxy
        return f"http://{proxy}"

    async def create_turnstile_task(self, sitekey: str, pageurl: str) -> Optional[str]:
        """Creates task for solving Turnstile captcha using local API server"""
        url = f"{self.base_url}/turnstile?url={pageurl}&sitekey={sitekey}"

        try:
            response = await self.session.get(url, timeout=30)
            try:
                result = response.json()
            except ValueError as e:
                return None

            if "task_id" in result:
                return result["task_id"]

            return None

        except Exception:
            return None

    async def get_task_result(self, task_id: str) -> Optional[str]:
        """Gets captcha solution result from local API server"""
        max_attempts = 30
        for attempt in range(max_attempts):
            try:
                response = await self.session.get(
                    f"{self.base_url}/result?id={task_id}",
                    timeout=30,
                )

                if response.status_code not in (200, 202):
                    return None

                raw_response = response.text.strip()

                if raw_response == "CAPTCHA_NOT_READY":
                    await asyncio.sleep(10)
                    continue

                try:
                    result = response.json()
                except ValueError:
                    return None

                if result.get("value"):
                    solution = result["value"]

                    if re.match(r'^[a-zA-Z0-9\.\-_]+$', solution):
                        return solution
                    else:
                        return None

                if result.get("status") == "error":
                    return None

                await asyncio.sleep(10)
                continue

            except Exception:
                return None

        return None

    async def solve_captcha(self) -> Optional[str]:
        """Solves Cloudflare Turnstile captcha and returns token using local API server"""
        task_id = await self.create_turnstile_task(
            CAPTCHA_WEBSITE_KEY, 
            CAPTCHA_WEBSITE_URL
        )
        if not task_id:
            return None

        return await self.get_task_result(task_id)

    # Add alias for compatibility
    async def get_captcha_token_async(self):
        return await self.solve_captcha()