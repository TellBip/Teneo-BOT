import asyncio
from capmonster_python import TurnstileTask
from twocaptcha import TwoCaptcha

CAPTCHA_PARAMS = {
    'website_key': '0x4AAAAAAAkhmGkb2VS6MRU0',
    'website_url': 'https://dashboard.teneo.pro/auth'
}

class ServiceCapmonster:
    def __init__(self, api_key):
        self.capmonster = TurnstileTask(api_key)

    def get_captcha_token(self):
        task_id = self.capmonster.create_task(
            **CAPTCHA_PARAMS
        )
        return self.capmonster.join_task_result(task_id).get("token")

    async def get_captcha_token_async(self):
        return await asyncio.to_thread(self.get_captcha_token)

    # Add alias for compatibility
    async def solve_captcha(self):
        return await self.get_captcha_token_async()

from anticaptchaofficial.turnstileproxyless import *

class ServiceAnticaptcha:
    def __init__(self, api_key):
        self.api_key = api_key
        self.solver = turnstileProxyless()
        self.solver.set_verbose(1)
        self.solver.set_key(self.api_key)
        self.solver.set_website_url(CAPTCHA_PARAMS['website_url'])    
        self.solver.set_website_key(CAPTCHA_PARAMS['website_key'])
        self.solver.set_action("login")
    
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
        captcha_token = self.solver.turnstile(sitekey=CAPTCHA_PARAMS['website_key'], url=CAPTCHA_PARAMS['website_url'])

        if 'code' in captcha_token:
            captcha_token = captcha_token['code']

        return captcha_token

    async def get_captcha_token_async(self):
        return await asyncio.to_thread(self.get_captcha_token)

    # Add alias for compatibility
    async def solve_captcha(self):
        return await self.get_captcha_token_async()