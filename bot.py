from aiohttp import (
    ClientResponseError,
    ClientSession,
    ClientTimeout
)
from aiohttp_socks import ProxyConnector
from fake_useragent import FakeUserAgent
from datetime import datetime
from colorama import *
from core.config.config import CAPTCHA_SERVICE, CAPTCHA_API_KEY, MAX_AUTH_THREADS, MAX_REG_THREADS, INVITE_CODE
from core.config.mail_config import MailConfig
from core.captcha import ServiceCapmonster, ServiceAnticaptcha, Service2Captcha, CFLSolver
from core.mail import check_if_email_valid, check_email_for_code
import asyncio, json, os
from itertools import islice
from web3 import Web3
from eth_account import Account
from eth_account.messages import encode_defunct
from httpx import AsyncClient
import base64
import secrets

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
        self.session = None
        self.mail_config = MailConfig()
        
        # Captcha service initialization
        if CAPTCHA_SERVICE.lower() == "2captcha":
            self.captcha_solver = Service2Captcha(CAPTCHA_API_KEY)
        elif CAPTCHA_SERVICE.lower() == "capmonster":
            self.captcha_solver = ServiceCapmonster(CAPTCHA_API_KEY)
        elif CAPTCHA_SERVICE.lower() == "anticaptcha":
            self.captcha_solver = ServiceAnticaptcha(CAPTCHA_API_KEY)
        elif CAPTCHA_SERVICE.lower() == "cflsolver":
            self.http_client = AsyncClient()
            self.captcha_solver = CFLSolver(CAPTCHA_API_KEY, self.http_client)
        else:
            raise ValueError(f"Unsupported captcha service: {CAPTCHA_SERVICE}")


    async def start(self):
        """Инициализация сессии"""
        if self.session is None:
            self.session = ClientSession()
        return self

    async def stop(self):
        """Закрытие сессии"""
        if self.session:
            await self.session.close()
            self.session = None

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
    
    def load_accounts(self, operation_type: str = None):
        """Load accounts based on operation type (reg/auth/farm/wallet)"""
        filename = {
            "reg": "data/reg.txt",
            "auth": "data/auth.txt",
            "farm": "data/farm.txt",
            "wallet": "data/wallet.txt"
        }.get(operation_type, "data/accounts.txt")

        try:
            if not os.path.exists(filename):
                self.log(f"{Fore.RED}File '{filename}' not found.{Style.RESET_ALL}")
                return []
            accounts = []
            with open(filename, 'r', encoding='utf-8') as file:
                for line in file:
                    line = line.strip()
                    if not line:
                        continue
                    
                    parts = line.split(':', 2)  # Максимум 3 части
                    
                    if operation_type == "wallet" and len(parts) == 3:
                        # Формат login:pass:privatekey для wallet.txt
                        email, password, private_key = parts
                        # Получаем адрес кошелька из приватного ключа
                        try:
                            account = Account.from_key(private_key)
                            wallet_address = account.address
                            accounts.append({
                                "Email": email.strip(), 
                                "Password": password.strip(), 
                                "PrivateKey": private_key.strip(),
                                "Wallet": wallet_address
                            })
                        except Exception as e:
                            self.log(f"{Fore.RED}Error deriving wallet address from private key for {email}: {e}{Style.RESET_ALL}")
                    elif len(parts) >= 2:
                        # Стандартный формат login:pass
                        email, password = parts[0], parts[1]
                        accounts.append({"Email": email.strip(), "Password": password.strip()})
            return accounts
        except Exception as e:
            self.log(f"{Fore.RED}Error loading accounts from {filename}: {e}{Style.RESET_ALL}")
            return []

    def save_results(self, operation_type: str, success_accounts: list, failed_accounts: list):
        """Save operation results to appropriate files"""
        try:
            if not os.path.exists('result'):
                os.makedirs('result')

            # Define filenames based on operation type
            success_file = {
                "reg": "result/good_reg.txt",
                "auth": "result/good_auth.txt",
                "farm": "result/good_farm.txt",
                "wallet": "result/good_wallet.txt"
            }.get(operation_type)

            failed_file = {
                "reg": "result/bad_reg.txt",
                "auth": "result/bad_auth.txt",
                "farm": "result/bad_farm.txt",
                "wallet": "result/bad_wallet.txt"
            }.get(operation_type)

            # Всегда используем режим добавления (append) для всех типов операций
            file_mode = 'a'

            # Save successful accounts
            if success_accounts and success_file:
                with open(success_file, file_mode, encoding='utf-8') as f:
                    for account in success_accounts:
                        if operation_type == "wallet" and "PrivateKey" in account:
                            f.write(f"{account['Email']}:{account['Password']}:{account['PrivateKey']}\n")
                        else:
                            f.write(f"{account['Email']}:{account['Password']}\n")
                self.log(f"{Fore.GREEN}Successful accounts saved to {success_file}{Style.RESET_ALL}")

            # Save failed accounts
            if failed_accounts and failed_file:
                with open(failed_file, file_mode, encoding='utf-8') as f:
                    for account in failed_accounts:
                        if operation_type == "wallet" and "PrivateKey" in account:
                            f.write(f"{account['Email']}:{account['Password']}:{account['PrivateKey']}\n")
                        else:
                            f.write(f"{account['Email']}:{account['Password']}\n")
                self.log(f"{Fore.YELLOW}Failed accounts saved to {failed_file}{Style.RESET_ALL}")

        except Exception as e:
            self.log(f"{Fore.RED}Error saving results: {str(e)}{Style.RESET_ALL}")

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
                print("4. Wallet Connection & Creating smart account")
                print("5. Exit")
                choose = int(input("Choose action [1/2/3/4/5] -> ").strip())

                if choose in [1, 2, 3, 4, 5]:
                    if choose == 5:
                        print(f"{Fore.RED + Style.BRIGHT}Exiting program...{Style.RESET_ALL}")
                        exit(0)  # Завершаем программу
                        
                    action_type = (
                        "Registration" if choose == 1 else 
                        "Authorization" if choose == 2 else 
                        "Farm" if choose == 3 else
                        "Wallet Connection & Creating smart account"
                    )
                    print(f"{Fore.GREEN + Style.BRIGHT}Selected: {action_type}{Style.RESET_ALL}")
                    return choose
                else:
                    print(f"{Fore.RED + Style.BRIGHT}Please enter a number from 1 to 5.{Style.RESET_ALL}")
            except ValueError:
                print(f"{Fore.RED + Style.BRIGHT}Invalid input. Enter a number (1, 2, 3, 4 or 5).{Style.RESET_ALL}")
    
    def save_account_data(self, email: str, token: str = None, private_key: str = None):
        """Сохраняет данные аккаунта (токен, приватный ключ) в accounts.json файл"""
        try:
            data = {}
            if os.path.exists('data/accounts.json'):
                with open('data/accounts.json', 'r', encoding='utf-8') as f:
                    data = json.load(f)
            
            if email not in data:
                data[email] = {}
                
            if token:
                data[email]["token"] = token
                
            if private_key:
                data[email]["wallet"] = private_key
            
            with open('data/accounts.json', 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=4, ensure_ascii=False)
                
            self.print_message(email, None, Fore.GREEN, "Account data saved successfully")
        except Exception as e:
            self.print_message(email, None, Fore.RED, f"Error saving account data: {str(e)}")

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
                        if response.status == 401:
                            self.print_message(email, proxy, Fore.RED, "Invalid credentials")
                            return None
                        response.raise_for_status()
                        result = await response.json()
                        token = result.get('access_token')
                        if token:
                            self.save_account_data(email, token=token)
                            return token
                        return None
            except ClientResponseError as e:
                if e.status == 401:
                    self.print_message(email, proxy, Fore.RED, "Invalid credentials")
                    return None
                raise  # Пробрасываем остальные ошибки выше
            except Exception as e:
                raise  # Пробрасываем все остальные ошибки выше
        except Exception as e:
            raise  # Пробрасываем ошибки капчи выше
        
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
            "Sec-WebSocket-Key": base64.b64encode(secrets.token_bytes(16)).decode(),
            "Sec-WebSocket-Version": "13",
            "Upgrade": "websocket",
            "User-Agent": FakeUserAgent().random
        }
        send_ping = None

        while True:
            proxy = self.get_next_proxy_for_account(email) if use_proxy else None
            connector = ProxyConnector.from_url(proxy) if proxy else None
            session = ClientSession(connector=connector, timeout=ClientTimeout(total=300))
            try:
                async with session:
                    # Генерируем новый ключ для каждой попытки подключения
                    headers["Sec-WebSocket-Key"] = base64.b64encode(secrets.token_bytes(16)).decode()
                    
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
        try:
            token = await self.user_login(email, password, proxy)
            if token:
                self.print_message(email, proxy, Fore.GREEN, "Access Token Obtained Successfully")
                return token
            return None  # Если token None, значит была ошибка авторизации
        except Exception as e:
            if "401" in str(e) or "Unauthorized" in str(e):
                self.print_message(email, proxy, Fore.RED, "Invalid credentials")
                return None
            self.print_message(email, proxy, Fore.RED, f"Error: {str(e)}")
            return None

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
        success_accounts = []
        
        for account in accounts_batch:
            email = account.get('Email')
            password = account.get('Password')
            if "@" in email and password:
                tasks.append(self.get_access_token(email, password, use_proxy))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for account, result in zip(accounts_batch, results):
            if isinstance(result, Exception) or not result:
                failed_accounts.append(account)
            elif result:
                success_accounts.append(account)
        
        # Save results
        self.save_results("auth", success_accounts, failed_accounts)
        return failed_accounts

    async def sign_up(self, email: str, password: str, captcha_token: str, proxy=None):
        """Register a new account"""
        url = 'https://auth.teneo.pro/api/signup'
        register_data = json.dumps({
            "email": email,
            "password": password,
            "invitedBy": INVITE_CODE,
            "turnstileToken": captcha_token
        })

        headers = {
                **self.headers,
                "Content-Length": str(len(register_data)),
                "Content-Type": "application/json",
                'x-api-key': 'OwAG3kib1ivOJG4Y0OCZ8lJETa6ypvsDtGmdhcjB'
            }


        connector = ProxyConnector.from_url(proxy) if proxy else None
        async with ClientSession(connector=connector) as session:
            async with session.post(url=url,
                                  data=register_data, headers=headers) as response:
                return await response.json()

    async def verify_email(self, email: str, token: str, code: str, proxy=None):
        """Verify email with received code"""
        url = 'https://auth.teneo.pro/api/verify-email'
        verif_data = json.dumps({
            "token": token,
            "verificationCode": code
        })
        headers = {
                **self.headers,
                "Content-Length": str(len(verif_data)),
                "Content-Type": "application/json",
                'x-api-key': 'OwAG3kib1ivOJG4Y0OCZ8lJETa6ypvsDtGmdhcjB'
            }
        
        connector = ProxyConnector.from_url(proxy) if proxy else None
        async with ClientSession(connector=connector) as session:
            async with session.post(url=url,
                                  data=verif_data, headers=headers) as response:
                verify_response = await response.text()
                try:
                    response_data = json.loads(verify_response)
                    if "access_token" in response_data:
                        # Сохраняем токен
                        self.save_account_data(email, token=response_data["access_token"])
                except:
                    pass
                return verify_response

    def validate_email_domain(self, email: str) -> tuple[bool, str]:
        """
        Проверка домена почты на допустимость и получение IMAP сервера.
        
        Returns:
            tuple[bool, str]: (True/False, IMAP сервер или None)
        """
        try:
            if '@' not in email:
                self.log(f"{Fore.RED}Invalid email format (no @ symbol): {email}{Style.RESET_ALL}")
                return False, None

            domain = email.split('@')[-1].lower()
            if domain not in self.mail_config.IMAP_SETTINGS:
                #self.log(f"{Fore.RED}Unsupported email domain: {domain}{Style.RESET_ALL}")
                return False, None

            return True, self.mail_config.IMAP_SETTINGS[domain]

        except Exception as e:
            self.log(f"{Fore.RED}Error during domain validation for {email}: {str(e)}{Style.RESET_ALL}")
            return False, None

    async def process_registration(self, email: str, password: str, use_proxy: bool):
        """Process full registration flow for one account"""
        proxy = self.get_next_proxy_for_account(email) if use_proxy else None
        try:
            # Validate email domain and get IMAP server
            is_valid, imap_server = self.validate_email_domain(email)
            if not is_valid:
                self.print_message(email, proxy, Fore.RED, "Unsupported email domain")
                return False
            
            # Check if email is valid
            if not await check_if_email_valid(imap_server, email, password, log_func=self.log):
                self.print_message(email, proxy, Fore.RED, "Invalid email credentials")
                return False

            # Get captcha token
            try:
                captcha_token = await self.captcha_solver.solve_captcha()
            except Exception as e:
                self.print_message(email, proxy, Fore.RED, f"Captcha error: {str(e)}")
                return False

            self.print_message(email, proxy, Fore.CYAN, "Registering...")
            response = await self.sign_up(email, password, captcha_token, proxy)
            #print(response)
            
            # Если аккаунт уже существует, считаем его успешным
            if isinstance(response, dict) and response.get('message') == 'A user with this email address has already been registered':
                self.print_message(email, proxy, Fore.GREEN, "Account already exists")
                return True
                
            # Проверяем, что получили правильный ответ от сервера
            if isinstance(response, dict) and response.get('message') == 'Email with verification code sent':
                registration_token = response.get('token')
                self.print_message(email, proxy, Fore.CYAN, "Waiting for verification code...")
                code = await check_email_for_code(imap_server, email, password, log_func=self.log)
                
                if code is None:
                    self.print_message(email, proxy, Fore.RED, "Failed to get verification code")
                    return False

                self.print_message(email, proxy, Fore.CYAN, "Verifying email...")
                verify_response = await self.verify_email(email, registration_token, code, proxy)
                #print(f"verify_response: {verify_response}")
                try:
                    response_data = json.loads(verify_response)
                    if "access_token" in response_data:
                        # Токен сохраняется в методе verify_email
                        self.print_message(email, proxy, Fore.GREEN, "Registration successful")
                        return True
                    else:
                        self.print_message(email, proxy, Fore.RED, f"Email verification failed: {verify_response}")
                        return False
                except json.JSONDecodeError:
                    self.print_message(email, proxy, Fore.RED, f"Invalid response format: {verify_response}")
                    return False
            else:
                self.print_message(email, proxy, Fore.RED, f"Registration failed: {response.get('message', 'Unknown error')}")
                return False

        except Exception as e:
            self.print_message(email, proxy, Fore.RED, f"Registration error: {str(e)}")
            return False

    async def process_registration_batch(self, accounts_batch, use_proxy):
        """Process a batch of accounts for registration"""
        tasks = []
        failed_accounts = []
        success_accounts = []
        
        for account in accounts_batch:
            email = account.get('Email')
            password = account.get('Password')
            if "@" in email and password:
                tasks.append(self.process_registration(email, password, use_proxy))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for account, result in zip(accounts_batch, results):
            if isinstance(result, Exception) or not result:
                failed_accounts.append(account)
            elif result:
                success_accounts.append(account)
        
        # Save results
        self.save_results("reg", success_accounts, failed_accounts)
        return failed_accounts

    async def connect_wallet(self, email: str, token: str, wallet_address: str, private_key: str, proxy=None, max_retries=3):
        """Connects wallet to the account"""
        retry_count = 0
        current_proxy = proxy
        
        while retry_count <= max_retries:
            try:
                # Подготовка сообщения для подписи
                message = f"Permanently link wallet to Teneo account: {email} This can only be done once."
                
                # Создание подписи с использованием приватного ключа
                w3 = Web3()
                message_hash = encode_defunct(text=message)
                signed_message = Account.sign_message(message_hash, private_key=private_key)
                signature = "0x" + signed_message.signature.hex()  # Добавляем префикс 0x к подписи
                
                # Подготовка данных для запроса
                data = json.dumps({
                    "address": wallet_address,
                    "signature": signature,
                    "message": message
                })
                
                url = "https://api.teneo.pro/api/users/link-wallet"
                headers = {
                    **self.headers,
                    "Authorization": f"Bearer {token}",
                    "Content-Length": str(len(data)),
                    "Content-Type": "application/json"
                }
                
                connector = ProxyConnector.from_url(current_proxy) if current_proxy else None
                async with ClientSession(connector=connector, timeout=ClientTimeout(total=60)) as session:
                    async with session.post(url=url, headers=headers, data=data) as response:
                        response.raise_for_status()
                        result = await response.json()
                        if result.get('status') == 'success' or 'wallet' in result:
                            # Сохраняем приватный ключ в accounts.json
                            self.save_account_data(email, private_key=private_key)
                            self.print_message(email, current_proxy, Fore.GREEN, f"Wallet {wallet_address} connected successfully")
                            return True
                        else:
                            self.print_message(email, current_proxy, Fore.RED, f"Failed to connect wallet: {result.get('message', 'Unknown error')}")
                            return False
            except Exception as e:
                # Проверяем, связана ли ошибка с прокси
                if "Couldn't connect to proxy" in str(e) or "proxy" in str(e).lower() or "timeout" in str(e).lower() or "connection" in str(e).lower():
                    retry_count += 1
                    if retry_count <= max_retries:
                        current_proxy = self.rotate_proxy_for_account(email)
                        self.print_message(email, current_proxy, Fore.YELLOW, f"Proxy error, rotating to new proxy. Retry {retry_count}/{max_retries}")
                    else:
                        self.print_message(email, current_proxy, Fore.RED, f"Error connecting wallet after {max_retries} retries: {str(e)}")
                        return False
                else:
                    self.print_message(email, current_proxy, Fore.RED, f"Error connecting wallet: {str(e)}")
                    return False

    async def check_wallet_status(self, email: str, token: str, proxy=None, max_retries=3):
        """Проверяет статус привязки кошелька к аккаунту"""
        retry_count = 0
        current_proxy = proxy
        
        while retry_count <= max_retries:
            try:
                url = "https://api.teneo.pro/api/users/smart-id-requirements"
                headers = {
                    **self.headers,
                    "Authorization": f"Bearer {token}"
                }
                
                connector = ProxyConnector.from_url(current_proxy) if current_proxy else None
                async with ClientSession(connector=connector, timeout=ClientTimeout(total=60)) as session:
                    async with session.get(url=url, headers=headers) as response:
                        response.raise_for_status()
                        result = await response.json()
                        
                        wallet_status = result.get('wallet', False)
                        heartbeats = result.get('currentHeartbeats', 0)
                        requirements_met = result.get('requirementsMet', False)
                        existing_smart_account = result.get('existingSmartAccount', False)
                        status = result.get('status', 'unknown')
                        
                        status_message = (
                            f"Wallet status: {'Connected' if wallet_status else 'Not connected'}, "
                            f"Heartbeats: {heartbeats}, "
                            f"Requirements met: {'Yes' if requirements_met else 'No'}, "
                            f"Smart Account: {'Exists' if existing_smart_account else 'Not exists'}, "
                            f"Status: {status}"
                        )
                        
                        self.print_message(email, current_proxy, Fore.CYAN, status_message)
                        return result
            except Exception as e:
                # Проверяем, связана ли ошибка с прокси
                if "Couldn't connect to proxy" in str(e) or "proxy" in str(e).lower() or "timeout" in str(e).lower() or "connection" in str(e).lower():
                    retry_count += 1
                    if retry_count <= max_retries:
                        current_proxy = self.rotate_proxy_for_account(email)
                        self.print_message(email, current_proxy, Fore.YELLOW, f"Proxy error, rotating to new proxy. Retry {retry_count}/{max_retries}")
                    else:
                        self.print_message(email, current_proxy, Fore.RED, f"Error checking wallet status after {max_retries} retries: {str(e)}")
                        return None
                else:
                    self.print_message(email, current_proxy, Fore.RED, f"Error checking wallet status: {str(e)}")
                    return None

    async def create_smart_account(self, email: str, token: str, wallet_address: str, private_key: str, proxy=None, max_retries=3):
        """Creates a smart account using the peaq API"""
        retry_count = 0
        current_proxy = proxy
        
        while retry_count <= max_retries:
            try:
                # Генерируем nonce (текущее время в миллисекундах)
                nonce = str(int(datetime.now().timestamp() * 1000))
                
                # Подготавливаем сообщение для подписи
                # Предполагаем, что сообщение включает nonce
                message = f"Create Teneo Smart Account with nonce: {nonce}"
                
                # Подписываем сообщение
                w3 = Web3()
                message_hash = encode_defunct(text=message)
                signed_message = Account.sign_message(message_hash, private_key=private_key)
                signature = signed_message.signature.hex()
                
                # Добавляем префикс 0x, если его нет
                if not signature.startswith("0x"):
                    signature = "0x" + signature
                
                # Подготовка данных для запроса
                data = json.dumps({
                    "machineOwner": wallet_address.lower(),  # Адрес в нижнем регистре
                    "nonce": nonce,
                    "signature": signature
                })
                
                url = "https://api.teneo.pro/api/peaq/create-smart-account"
                headers = {
                    **self.headers,
                    "Authorization": f"Bearer {token}",
                    "Content-Length": str(len(data)),
                    "Content-Type": "application/json"
                }
                
                connector = ProxyConnector.from_url(current_proxy) if current_proxy else None
                async with ClientSession(connector=connector, timeout=ClientTimeout(total=60)) as session:
                    async with session.post(url=url, headers=headers, data=data) as response:
                        response.raise_for_status()
                        result = await response.json()
                        if result.get('success') == True:
                            self.print_message(email, current_proxy, Fore.GREEN, f"Smart account created successfully. TX Hash: {result.get('txHash', 'N/A')}")
                            return True
                        else:
                            self.print_message(email, current_proxy, Fore.RED, f"Failed to create smart account: {result.get('message', 'Unknown error')}")
                            return False
                
            except Exception as e:
                # Проверяем, связана ли ошибка с прокси
                if "Couldn't connect to proxy" in str(e) or "proxy" in str(e).lower() or "timeout" in str(e).lower() or "connection" in str(e).lower():
                    retry_count += 1
                    if retry_count <= max_retries:
                        current_proxy = self.rotate_proxy_for_account(email)
                        self.print_message(email, current_proxy, Fore.YELLOW, f"Proxy error, rotating to new proxy. Retry {retry_count}/{max_retries}")
                    else:
                        self.print_message(email, current_proxy, Fore.RED, f"Error creating smart account after {max_retries} retries: {str(e)}")
                        return False
                else:
                    self.print_message(email, current_proxy, Fore.RED, f"Error creating smart account: {str(e)}")
                    return False

    async def connect_wallet_to_dashboard(self, email: str, token: str, proxy=None, max_retries=3):
        """Connects the linked wallet to the Teneo dashboard"""
        retry_count = 0
        current_proxy = proxy
        
        while retry_count <= max_retries:
            try:
                url = "https://api.teneo.pro/api/users/connect-smart-id"
                headers = {
                    **self.headers,
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json"
                }
                
                connector = ProxyConnector.from_url(current_proxy) if current_proxy else None
                async with ClientSession(connector=connector, timeout=ClientTimeout(total=60)) as session:
                    async with session.post(url=url, headers=headers) as response:
                        response.raise_for_status()
                        result = await response.json()
                        if result.get('status') == 'success' or result.get('connected') == True:
                            self.print_message(email, current_proxy, Fore.GREEN, "Wallet successfully connected to dashboard")
                            return True
                        else:
                            self.print_message(email, current_proxy, Fore.RED, f"Failed to connect wallet to dashboard: {result.get('message', 'Unknown error')}")
                            return False
                        
            except Exception as e:
                # Проверяем, связана ли ошибка с прокси
                if "Couldn't connect to proxy" in str(e) or "proxy" in str(e).lower() or "timeout" in str(e).lower() or "connection" in str(e).lower():
                    retry_count += 1
                    if retry_count <= max_retries:
                        current_proxy = self.rotate_proxy_for_account(email)
                        self.print_message(email, current_proxy, Fore.YELLOW, f"Proxy error, rotating to new proxy. Retry {retry_count}/{max_retries}")
                    else:
                        self.print_message(email, current_proxy, Fore.RED, f"Error connecting wallet to dashboard after {max_retries} retries: {str(e)}")
                        return False
                else:
                    self.print_message(email, current_proxy, Fore.RED, f"Error connecting wallet to dashboard: {str(e)}")
                    return False

    async def process_wallet_connection(self, email: str, password: str, wallet_address: str, private_key: str, use_proxy: bool):
        """Process wallet connection for one account"""
        proxy = self.get_next_proxy_for_account(email) if use_proxy else None
        try:
            # Try to get saved token
            token = self.get_saved_token(email)
            
            # If no token, get it through authorization
            if not token:
                self.print_message(email, proxy, Fore.YELLOW, "No saved token, authorizing...")
                token = await self.get_access_token(email, password, use_proxy)
                
            if not token:
                self.print_message(email, proxy, Fore.RED, "Failed to get token for wallet connection")
                return False
                
            # Проверяем текущий статус кошелька
            wallet_status = await self.check_wallet_status(email, token, proxy)
            
            # Если кошелек уже привязан
            if wallet_status and wallet_status.get('wallet', False):
                self.print_message(email, proxy, Fore.GREEN, "Wallet already connected to account")
                
                # Проверяем, существует ли уже смарт-аккаунт
                existing_smart_account = wallet_status.get('existingSmartAccount', False)
                if existing_smart_account:
                    self.print_message(email, proxy, Fore.GREEN, "Smart account already exists")
                    return True
                
                # Создаем смарт-аккаунт, если его еще нет
                self.print_message(email, proxy, Fore.CYAN, "Creating smart account...")
                return await self.create_smart_account(email, token, wallet_address, private_key, proxy)
                
            # Connect wallet
            wallet_linked = await self.connect_wallet(email, token, wallet_address, private_key, proxy)
            
            # Если кошелек успешно привязан, проверяем и создаем смарт-аккаунт при необходимости
            if wallet_linked:
                # Повторно проверяем статус после привязки кошелька
                wallet_status = await self.check_wallet_status(email, token, proxy)
                
                # Проверяем, существует ли уже смарт-аккаунт
                existing_smart_account = wallet_status.get('existingSmartAccount', False)
                if existing_smart_account:
                    self.print_message(email, proxy, Fore.GREEN, "Smart account already exists")
                    return True
                
                # Создаем смарт-аккаунт, если его еще нет
                self.print_message(email, proxy, Fore.CYAN, "Creating smart account...")
                return await self.create_smart_account(email, token, wallet_address, private_key, proxy)
                
            return wallet_linked
            
        except Exception as e:
            self.print_message(email, proxy, Fore.RED, f"Error in wallet connection process: {str(e)}")
            return False
            
    async def process_wallet_batch(self, accounts_batch, use_proxy):
        """Process a batch of accounts for wallet connection"""
        tasks = []
        failed_accounts = []
        success_accounts = []
        
        for account in accounts_batch:
            email = account.get('Email')
            password = account.get('Password')
            wallet = account.get('Wallet')
            private_key = account.get('PrivateKey')
            
            if "@" in email and password and wallet and private_key:
                tasks.append(self.process_wallet_connection(email, password, wallet, private_key, use_proxy))
            else:
                self.log(f"{Fore.RED}Invalid account format for {email}: missing wallet address or private key{Style.RESET_ALL}")
                failed_accounts.append(account)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        i = 0
        for account in accounts_batch:
            if account.get('Wallet') and account.get('PrivateKey'):  # Обрабатываем только аккаунты с кошельком и приватным ключом
                if isinstance(results[i], Exception) or not results[i]:
                    failed_accounts.append(account)
                elif results[i]:
                    success_accounts.append(account)
                i += 1
        
        # Save results
        self.save_results("wallet", success_accounts, failed_accounts)
        return failed_accounts

    async def main(self):
        try:
            self.welcome()
            use_proxy_choice = self.print_question()

            if use_proxy_choice == 1:
                accounts = self.load_accounts("reg")
                if not accounts:
                    self.log(f"{Fore.RED+Style.BRIGHT}No accounts loaded from data/reg.txt{Style.RESET_ALL}")
                    return

                use_proxy = True
                self.clear_terminal()
                self.welcome()
                self.log(
                    f"{Fore.GREEN + Style.BRIGHT}Total accounts for registration: {Style.RESET_ALL}"
                    f"{Fore.WHITE + Style.BRIGHT}{len(accounts)}{Style.RESET_ALL}"
                )

                if use_proxy:
                    await self.load_proxies()

                self.log(f"{Fore.CYAN + Style.BRIGHT}-{Style.RESET_ALL}"*75)

                failed_accounts = []
                batch_size = min(MAX_REG_THREADS, len(accounts))
                total_batches = (len(accounts) + batch_size - 1) // batch_size
                total_accounts = len(accounts)

                self.log(f"{Fore.CYAN}Starting registration of {total_accounts} accounts in batches of {batch_size}{Style.RESET_ALL}")

                for i in range(0, len(accounts), batch_size):
                    current_batch = i // batch_size + 1
                    batch = list(islice(accounts, i, i + batch_size))
                    accounts_processed = min(i + batch_size, total_accounts)
                    self.log(
                        f"{Fore.CYAN}Processing batch {current_batch}/{total_batches} "
                        f"({len(batch)} accounts, progress: {accounts_processed}/{total_accounts}){Style.RESET_ALL}"
                    )
                    batch_failed = await self.process_registration_batch(batch, use_proxy)
                    failed_accounts.extend(batch_failed)

                if failed_accounts:
                    self.log(f"{Fore.YELLOW}Failed registrations: {len(failed_accounts)}/{len(accounts)}{Style.RESET_ALL}")
                else:
                    self.log(f"{Fore.GREEN}All registrations successful!{Style.RESET_ALL}")
                return

            if use_proxy_choice == 2:
                accounts = self.load_accounts("auth")
                if not accounts:
                    self.log(f"{Fore.RED+Style.BRIGHT}No accounts loaded from data/auth.txt{Style.RESET_ALL}")
                    return

                use_proxy = True
                self.clear_terminal()
                self.welcome()
                self.log(
                    f"{Fore.GREEN + Style.BRIGHT}Total accounts for authorization: {Style.RESET_ALL}"
                    f"{Fore.WHITE + Style.BRIGHT}{len(accounts)}{Style.RESET_ALL}"
                )

                if use_proxy:
                    await self.load_proxies()

                self.log(f"{Fore.CYAN + Style.BRIGHT}-{Style.RESET_ALL}"*75)

                failed_accounts = []
                batch_size = min(MAX_AUTH_THREADS, len(accounts))
                total_batches = (len(accounts) + batch_size - 1) // batch_size
                total_accounts = len(accounts)
                
                self.log(f"{Fore.CYAN}Starting authorization of {total_accounts} accounts in batches of {batch_size}{Style.RESET_ALL}")
                
                for i in range(0, len(accounts), batch_size):
                    current_batch = i // batch_size + 1
                    batch = list(islice(accounts, i, i + batch_size))
                    accounts_processed = min(i + batch_size, total_accounts)
                    self.log(
                        f"{Fore.CYAN}Processing batch {current_batch}/{total_batches} "
                        f"({len(batch)} accounts, progress: {accounts_processed}/{total_accounts}){Style.RESET_ALL}"
                    )
                    batch_failed = await self.process_auth_batch(batch, use_proxy)
                    failed_accounts.extend(batch_failed)
                
                if failed_accounts:
                    self.log(f"{Fore.YELLOW}Failed authorizations: {len(failed_accounts)}/{len(accounts)}{Style.RESET_ALL}")
                else:
                    self.log(f"{Fore.GREEN}All authorizations successful!{Style.RESET_ALL}")
                return
            
            if use_proxy_choice == 4:
                accounts = self.load_accounts("wallet")
                if not accounts:
                    self.log(f"{Fore.RED+Style.BRIGHT}No accounts loaded from data/wallet.txt{Style.RESET_ALL}")
                    return

                # Проверяем, что есть аккаунты с кошельками
                accounts_with_wallet = [acc for acc in accounts if acc.get('Wallet')]
                if not accounts_with_wallet:
                    self.log(f"{Fore.RED+Style.BRIGHT}No accounts with wallet addresses found. Format should be email:password:wallet{Style.RESET_ALL}")
                    return
                
                use_proxy = True
                self.clear_terminal()
                self.welcome()
                self.log(
                    f"{Fore.GREEN + Style.BRIGHT}Total accounts for wallet connection: {Style.RESET_ALL}"
                    f"{Fore.WHITE + Style.BRIGHT}{len(accounts_with_wallet)}{Style.RESET_ALL}"
                )

                if use_proxy:
                    await self.load_proxies()

                self.log(f"{Fore.CYAN + Style.BRIGHT}-{Style.RESET_ALL}"*75)

                failed_accounts = []
                batch_size = min(MAX_AUTH_THREADS, len(accounts_with_wallet))
                total_batches = (len(accounts_with_wallet) + batch_size - 1) // batch_size
                total_accounts = len(accounts_with_wallet)
                
                self.log(f"{Fore.CYAN}Starting wallet connection for {total_accounts} accounts in batches of {batch_size}{Style.RESET_ALL}")
                
                for i in range(0, len(accounts_with_wallet), batch_size):
                    current_batch = i // batch_size + 1
                    batch = list(islice(accounts_with_wallet, i, i + batch_size))
                    accounts_processed = min(i + batch_size, total_accounts)
                    self.log(
                        f"{Fore.CYAN}Processing batch {current_batch}/{total_batches} "
                        f"({len(batch)} accounts, progress: {accounts_processed}/{total_accounts}){Style.RESET_ALL}"
                    )
                    batch_failed = await self.process_wallet_batch(batch, use_proxy)
                    failed_accounts.extend(batch_failed)
                
                if failed_accounts:
                    self.log(f"{Fore.YELLOW}Failed wallet connections: {len(failed_accounts)}/{len(accounts_with_wallet)}{Style.RESET_ALL}")
                else:
                    self.log(f"{Fore.GREEN}All wallet connections successful!{Style.RESET_ALL}")
                return

            # Farm mode
            accounts = self.load_accounts("farm")
            if not accounts:
                self.log(f"{Fore.RED+Style.BRIGHT}No accounts loaded from data/farm.txt{Style.RESET_ALL}")
                return

            use_proxy = True
            self.clear_terminal()
            self.welcome()
            self.log(
                f"{Fore.GREEN + Style.BRIGHT}Total accounts for farming: {Style.RESET_ALL}"
                f"{Fore.WHITE + Style.BRIGHT}{len(accounts)}{Style.RESET_ALL}"
            )

            if use_proxy:
                await self.load_proxies()

            self.log(f"{Fore.CYAN + Style.BRIGHT}-{Style.RESET_ALL}"*75)

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
        async def run():
            bot = Teneo()
            await bot.start()
            try:
                await bot.main()
            finally:
                await bot.stop()
        
        asyncio.run(run())
    except KeyboardInterrupt:
        print(
            f"{Fore.CYAN + Style.BRIGHT}[ {datetime.now().strftime('%x %X')} ]{Style.RESET_ALL}"
            f"{Fore.WHITE + Style.BRIGHT} | {Style.RESET_ALL}"
            f"{Fore.RED + Style.BRIGHT}[ EXIT ] Teneo - BOT{Style.RESET_ALL}                                       "                              
        )