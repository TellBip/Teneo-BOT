from aiohttp import (
    ClientResponseError,
    ClientSession,
    ClientTimeout
)
from aiohttp_socks import ProxyConnector
from fake_useragent import FakeUserAgent
from datetime import datetime
from colorama import *
from data.config import CAPTCHA_SERVICE, CAPTCHA_API_KEY, MAX_AUTH_THREADS
from core.captcha import ServiceCapmonster, ServiceAnticaptcha, Service2Captcha
import asyncio, json, os
from itertools import islice

# Initialize colorama for Windows
init(autoreset=True)

class Teneo:
    def __init__(self) -> None:
        self.headers = {
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "en-US,en;q=0.9,id;q=0.8",
            "Origin": "https://dashboard.teneo.pro",
            "Referer": "https://dashboard.teneo.pro/",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-site",
            "User-Agent": FakeUserAgent().random,
            "X-Api-Key": "OwAG3kib1ivOJG4Y0OCZ8lJETa6ypvsDtGmdhcjB"
        }
        self.proxies = []
        self.proxy_index = 0
        self.account_proxies = {}
        
        # Инициализация сервиса капчи
        if CAPTCHA_SERVICE.lower() == "2captcha":
            self.captcha_solver = Service2Captcha(CAPTCHA_API_KEY)
        elif CAPTCHA_SERVICE.lower() == "capmonster":
            self.captcha_solver = ServiceCapmonster(CAPTCHA_API_KEY)
        elif CAPTCHA_SERVICE.lower() == "anticaptcha":
            self.captcha_solver = ServiceAnticaptcha(CAPTCHA_API_KEY)
        else:
            raise ValueError(f"Неподдерживаемый сервис капчи: {CAPTCHA_SERVICE}")

    def clear_terminal(self):
        os.system('cls' if os.name == 'nt' else 'clear')

    def log(self, message):
        print(
            f"{Fore.CYAN + Style.BRIGHT}[ {datetime.now().strftime('%x %X')} ]{Style.RESET_ALL}"
            f"{Fore.WHITE + Style.BRIGHT} | {Style.RESET_ALL}{message}",
            flush=True
        )

    def welcome(self):
        telegram_link = "https://t.me/+1fc0or8gCHsyNGFi"
        print(f"""
        {Fore.GREEN + Style.BRIGHT}
        TTTTTT EEEE N   N EEEE  OOO  
          TT   E    NN  N E    O   O 
          TT   EEE  N N N EEE  O   O 
          TT   E    N  NN E    O   O 
          TT   EEEE N   N EEEE  OOO  
        {Style.RESET_ALL}
{Fore.GREEN + Style.BRIGHT}Developed by: @Tell_Bip{Style.RESET_ALL}
{Fore.GREEN + Style.BRIGHT}Our Telegram channel:{Style.RESET_ALL} {Fore.BLUE + Style.BRIGHT}\x1b]8;;{telegram_link}\x07{telegram_link}\x1b]8;;\x07{Style.RESET_ALL}
        """)

    def format_seconds(self, seconds):
        hours, remainder = divmod(seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        return f"{int(hours):02}:{int(minutes):02}:{int(seconds):02}"
    
    def load_accounts(self):
        try:
            if not os.path.exists('data/accounts.txt'):
                self.log(f"{Fore.RED}File 'data/accounts.txt' not found.{Style.RESET_ALL}")
                return []
            accounts = []
            with open('data/accounts.txt', 'r', encoding='utf-8') as file:
                for line in file:
                    line = line.strip()
                    if line and ':' in line:
                        email, password = line.split(':', 1)
                        accounts.append({"Email": email.strip(), "Password": password.strip()})
            return accounts
        except Exception as e:
            self.log(f"{Fore.RED}Error loading accounts: {e}{Style.RESET_ALL}")
            return []
    
    async def load_proxies(self):
        """Loading proxies from proxy.txt file"""
        filename = "data/proxy.txt"
        try:
            if not os.path.exists(filename):
                self.log(f"{Fore.RED + Style.BRIGHT}File {filename} not found.{Style.RESET_ALL}")
                return
                
            with open(filename, 'r') as f:
                self.proxies = f.read().splitlines()
            
            if not self.proxies:
                self.log(f"{Fore.RED + Style.BRIGHT}No proxies found in file.{Style.RESET_ALL}")
                return

            self.log(
                f"{Fore.GREEN + Style.BRIGHT}Loaded proxies: {Style.RESET_ALL}"
                f"{Fore.WHITE + Style.BRIGHT}{len(self.proxies)}{Style.RESET_ALL}"
            )
        except Exception as e:
            self.log(f"{Fore.RED + Style.BRIGHT}Error loading proxies: {str(e)}{Style.RESET_ALL}")

    def check_proxy_schemes(self, proxies):
        schemes = ["http://", "https://", "socks4://", "socks5://"]
        if any(proxies.startswith(scheme) for scheme in schemes):
            return proxies
        return f"http://{proxies}"

    def get_next_proxy_for_account(self, email):
        if email not in self.account_proxies:
            if not self.proxies:
                return None
            proxy = self.check_proxy_schemes(self.proxies[self.proxy_index])
            self.account_proxies[email] = proxy
            self.proxy_index = (self.proxy_index + 1) % len(self.proxies)
        return self.account_proxies[email]

    def rotate_proxy_for_account(self, email):
        if not self.proxies:
            return None
        proxy = self.check_proxy_schemes(self.proxies[self.proxy_index])
        self.account_proxies[email] = proxy
        self.proxy_index = (self.proxy_index + 1) % len(self.proxies)
        return proxy
    
    def mask_account(self, account):
        if "@" in account:
            local, domain = account.split('@', 1)
            mask_account = local[:3] + '*' * 3 + local[-3:]
            return f"{mask_account}@{domain}"

    def print_message(self, email, proxy, color, message):
        self.log(
            f"{Fore.CYAN + Style.BRIGHT}[ Account:{Style.RESET_ALL}"
            f"{Fore.WHITE + Style.BRIGHT} {self.mask_account(email)} {Style.RESET_ALL}"
            f"{Fore.MAGENTA + Style.BRIGHT}-{Style.RESET_ALL}"
            f"{Fore.CYAN + Style.BRIGHT} Proxy: {Style.RESET_ALL}"
            f"{Fore.WHITE + Style.BRIGHT}{proxy}{Style.RESET_ALL}"
            f"{Fore.MAGENTA + Style.BRIGHT} - {Style.RESET_ALL}"
            f"{Fore.CYAN + Style.BRIGHT}Status:{Style.RESET_ALL}"
            f"{color + Style.BRIGHT} {message} {Style.RESET_ALL}"
            f"{Fore.CYAN + Style.BRIGHT}]{Style.RESET_ALL}"
        )

    def print_question(self):
        while True:
            try:
                print("1. Registration")
                print("2. Authorization")
                print("3. Farm")
                choose = int(input("Choose action [1/2/3] -> ").strip())

                if choose in [1, 2, 3]:
                    action_type = (
                        "Registration" if choose == 1 else 
                        "Authorization" if choose == 2 else 
                        "Farm"
                    )
                    print(f"{Fore.GREEN + Style.BRIGHT}Selected: {action_type}{Style.RESET_ALL}")
                    return choose
                else:
                    print(f"{Fore.RED + Style.BRIGHT}Please enter a number from 1 to 3.{Style.RESET_ALL}")
            except ValueError:
                print(f"{Fore.RED + Style.BRIGHT}Invalid input. Enter a number (1, 2 or 3).{Style.RESET_ALL}")
    
    def save_token(self, email: str, token: str):
        """Saves authorization token to accounts.json file"""
        try:
            data = {}
            if os.path.exists('data/accounts.json'):
                with open('data/accounts.json', 'r', encoding='utf-8') as f:
                    data = json.load(f)
            
            data[email] = {"token": token}
            
            with open('data/accounts.json', 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=4, ensure_ascii=False)
                
            self.print_message(email, None, Fore.GREEN, "Token saved successfully")
        except Exception as e:
            self.print_message(email, None, Fore.RED, f"Error saving token: {str(e)}")

    async def user_login(self, email: str, password: str, proxy=None):
        try:
            captcha_token = await self.captcha_solver.solve_captcha()

            url = "https://auth.teneo.pro/api/login"
            data = json.dumps({"email":email, "password":password, "turnstileToken":captcha_token})
            headers = {
                **self.headers,
                "Content-Length": str(len(data)),
                "Content-Type": "application/json"
            }
            connector = ProxyConnector.from_url(proxy) if proxy else None
            try:
                async with ClientSession(connector=connector, timeout=ClientTimeout(total=120)) as session:
                    async with session.post(url=url, headers=headers, data=data) as response:
                        response.raise_for_status()
                        result = await response.json()
                        token = result['access_token']
                        self.save_token(email, token)
                        return token
            except (Exception, ClientResponseError) as e:
                return self.print_message(email, proxy, Fore.RED, f"GET Access Token Failed: {Fore.YELLOW + Style.BRIGHT}{str(e)}")
        except Exception as e:
            return self.print_message(email, proxy, Fore.RED, f"Captcha Error: {Fore.YELLOW + Style.BRIGHT}{str(e)}")
        
    async def connect_websocket(self, email: str, token: str, use_proxy: bool):
        wss_url = f"wss://secure.ws.teneo.pro/websocket?accessToken={token}&version=v0.2"
        headers = {
            "Accept-Language": "en-US,en;q=0.9,id;q=0.8",
            "Cache-Control": "no-cache",
            "Connection": "Upgrade",
            "Host": "secure.ws.teneo.pro",
            "Origin": "chrome-extension://emcclcoaglgcpoognfiggmhnhgabppkm",
            "Pragma": "no-cache",
            "Sec-WebSocket-Extensions": "permessage-deflate; client_max_window_bits",
            "Sec-WebSocket-Key": "g0PDYtLWQOmaBE5upOBXew==",
            "Sec-WebSocket-Version": "13",
            "Upgrade": "websocket",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36"
        }
        send_ping = None

        while True:
            proxy = self.get_next_proxy_for_account(email) if use_proxy else None
            connector = ProxyConnector.from_url(proxy) if proxy else None
            session = ClientSession(connector=connector, timeout=ClientTimeout(total=300))
            try:
                async with session:
                    async with session.ws_connect(wss_url, headers=headers) as wss:
                        self.print_message(email, proxy, Fore.GREEN, "WebSocket Connected")

                        async def send_ping_message():
                            while True:
                                await wss.send_json({"type":"PING"})
                                print(
                                    f"{Fore.CYAN + Style.BRIGHT}[ {datetime.now().strftime('%x %X')} ]{Style.RESET_ALL}"
                                    f"{Fore.WHITE + Style.BRIGHT} | {Style.RESET_ALL}"
                                    f"{Fore.BLUE + Style.BRIGHT}Node Connection Established...{Style.RESET_ALL}",
                                    end="\r",
                                    flush=True
                                )
                                await asyncio.sleep(10)

                        if send_ping is None or send_ping.done():
                            send_ping = asyncio.create_task(send_ping_message())

                        async for msg in wss:
                            try:
                                response = json.loads(msg.data)
                                if response.get("message") == "Connected successfully":
                                    today_point = response.get("pointsToday", 0)
                                    total_point = response.get("pointsTotal", 0)
                                    self.print_message(
                                        email, proxy, Fore.GREEN, 
                                        f"Connected Successfully "
                                        f"{Fore.MAGENTA + Style.BRIGHT}-{Style.RESET_ALL}"
                                        f"{Fore.CYAN + Style.BRIGHT} Earnings: {Style.RESET_ALL}"
                                        f"{Fore.WHITE + Style.BRIGHT}Today {today_point} PTS{Style.RESET_ALL}"
                                        f"{Fore.MAGENTA + Style.BRIGHT} - {Style.RESET_ALL}"
                                        f"{Fore.WHITE + Style.BRIGHT}Total {total_point} PTS{Style.RESET_ALL}"
                                    )

                                elif response.get("message") == "Pulse from server":
                                    today_point = response.get("pointsToday", 0)
                                    total_point = response.get("pointsTotal", 0)
                                    heartbeat_today = response.get("heartbeats", 0)
                                    self.print_message(
                                        email, proxy, Fore.GREEN, 
                                        f"Pulse From Server"
                                        f"{Fore.MAGENTA + Style.BRIGHT} - {Style.RESET_ALL}"
                                        f"{Fore.CYAN + Style.BRIGHT}Earnings:{Style.RESET_ALL}"
                                        f"{Fore.WHITE + Style.BRIGHT} Today {today_point} PTS {Style.RESET_ALL}"
                                        f"{Fore.MAGENTA + Style.BRIGHT}-{Style.RESET_ALL}"
                                        f"{Fore.WHITE + Style.BRIGHT} Total {total_point} PTS {Style.RESET_ALL}"
                                        f"{Fore.MAGENTA + Style.BRIGHT}-{Style.RESET_ALL}"
                                        f"{Fore.CYAN + Style.BRIGHT} Heartbeat: {Style.RESET_ALL}"
                                        f"{Fore.WHITE + Style.BRIGHT}Today {heartbeat_today} HB{Style.RESET_ALL}"
                                    )
                                else:
                                    raise Exception("Connection Timed Out")

                            except Exception as e:
                                self.print_message(email, proxy, Fore.RED, f"WebSocket Connection Closed: {Fore.YELLOW + Style.BRIGHT}{str(e)}")
                                if send_ping and not send_ping.done():
                                    send_ping.cancel()
                                    try:
                                        await send_ping
                                    except asyncio.CancelledError:
                                        self.print_message(email, proxy, Fore.YELLOW, f"Send Ping Cancelled")

                                break

            except Exception as e:
                self.print_message(email, proxy, Fore.RED, f"WebSocket Connection Failed: {Fore.YELLOW + Style.BRIGHT}{str(e)}")
                self.rotate_proxy_for_account(email) if use_proxy else None
                await asyncio.sleep(5)

            except asyncio.CancelledError:
                self.print_message(email, proxy, Fore.YELLOW, "WebSocket Connection Closed")
                break
            finally:
                await session.close()
            
    async def get_access_token(self, email: str, password: str, use_proxy: bool):
        proxy = self.get_next_proxy_for_account(email) if use_proxy else None
        token = None
        while token is None:
            token = await self.user_login(email, password, proxy)
            if not token:
                proxy = self.rotate_proxy_for_account(email) if use_proxy else None
                await asyncio.sleep(5)
                continue
            
            self.print_message(email, proxy, Fore.GREEN, "Access Token Obtained Successfully")
            return token
        
    def get_saved_token(self, email: str) -> str:
        """Получает сохраненный токен из accounts.json для указанного email"""
        try:
            if os.path.exists('data/accounts.json'):
                with open('data/accounts.json', 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    if email in data and "token" in data[email]:
                        return data[email]["token"]
        except Exception as e:
            self.log(f"{Fore.RED}Ошибка при чтении токена: {str(e)}{Style.RESET_ALL}")
        return None

    async def process_accounts(self, email: str, password: str, use_proxy: bool):
        token = self.get_saved_token(email)
        if token:
            self.print_message(email, None, Fore.GREEN, "Token loaded from accounts.json")
        else:
            token = await self.get_access_token(email, password, use_proxy)
        
        if token:
            await self.connect_websocket(email, token, use_proxy)
        
    def save_failed_accounts(self, accounts):
        """Saves failed authorization accounts to a file"""
        try:
            # Create result directory if it doesn't exist
            if not os.path.exists('result'):
                os.makedirs('result')
                
            with open('result/failed_accounts.txt', 'w', encoding='utf-8') as f:
                for account in accounts:
                    f.write(f"{account['Email']}:{account['Password']}\n")
            self.log(f"{Fore.YELLOW}Failed accounts saved to result/failed_accounts.txt{Style.RESET_ALL}")
        except Exception as e:
            self.log(f"{Fore.RED}Error saving failed accounts: {str(e)}{Style.RESET_ALL}")

    async def process_auth_batch(self, accounts_batch, use_proxy):
        """Process a batch of accounts for authorization"""
        tasks = []
        failed_accounts = []
        
        for account in accounts_batch:
            email = account.get('Email')
            password = account.get('Password')
            if "@" in email and password:
                tasks.append(self.get_access_token(email, password, use_proxy))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for account, result in zip(accounts_batch, results):
            if isinstance(result, Exception) or not result:
                failed_accounts.append(account)
        
        return failed_accounts

    async def main(self):
        try:
            self.welcome()
            use_proxy_choice = self.print_question()

            if use_proxy_choice == 1:
                self.log(f"{Fore.YELLOW + Style.BRIGHT}Coming soon...{Style.RESET_ALL}")
                return

            accounts = self.load_accounts()
            if not accounts:
                self.log(f"{Fore.RED+Style.BRIGHT}No accounts loaded.{Style.RESET_ALL}")
                return
            
            use_proxy = True  # Включаем прокси по умолчанию для всех режимов

            self.clear_terminal()
            self.welcome()
            self.log(
                f"{Fore.GREEN + Style.BRIGHT}Total accounts: {Style.RESET_ALL}"
                f"{Fore.WHITE + Style.BRIGHT}{len(accounts)}{Style.RESET_ALL}"
            )

            if use_proxy:
                await self.load_proxies()

            self.log(f"{Fore.CYAN + Style.BRIGHT}-{Style.RESET_ALL}"*75)

            if use_proxy_choice == 2:
                failed_accounts = []
                batch_size = MAX_AUTH_THREADS
                
                # Process accounts in batches
                for i in range(0, len(accounts), batch_size):
                    batch = list(islice(accounts, i, i + batch_size))
                    self.log(f"{Fore.CYAN}Processing batch {i//batch_size + 1}/{(len(accounts) + batch_size - 1)//batch_size}{Style.RESET_ALL}")
                    batch_failed = await self.process_auth_batch(batch, use_proxy)
                    failed_accounts.extend(batch_failed)
                
                if failed_accounts:
                    self.save_failed_accounts(failed_accounts)
                    self.log(f"{Fore.YELLOW}Failed authorizations: {len(failed_accounts)}/{len(accounts)}{Style.RESET_ALL}")
                else:
                    self.log(f"{Fore.GREEN}All authorizations successful!{Style.RESET_ALL}")
                return

            while True:
                tasks = []
                for account in accounts:
                    email = account.get('Email')
                    password = account.get('Password')

                    if "@" in email and password:
                        tasks.append(self.process_accounts(email, password, use_proxy))

                await asyncio.gather(*tasks)
                await asyncio.sleep(10)

        except Exception as e:
            self.log(f"{Fore.RED+Style.BRIGHT}Error: {e}{Style.RESET_ALL}")
            raise e

if __name__ == "__main__":
    try:
        bot = Teneo()
        asyncio.run(bot.main())
    except KeyboardInterrupt:
        print(
            f"{Fore.CYAN + Style.BRIGHT}[ {datetime.now().strftime('%x %X')} ]{Style.RESET_ALL}"
            f"{Fore.WHITE + Style.BRIGHT} | {Style.RESET_ALL}"
            f"{Fore.RED + Style.BRIGHT}[ EXIT ] Teneo - BOT{Style.RESET_ALL}                                       "                              
        )