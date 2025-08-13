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
from core.captcha import ServiceCapmonster, ServiceAnticaptcha, Service2Captcha, CFLSolver, Service2Captcha2, ServiceCapmonster2, ServiceAnticaptcha2
from core.utils.accounts import (
    load_accounts as load_accounts_util,
    save_results as save_results_util,
    save_account_data as save_account_data_util,
    get_saved_token as get_saved_token_util,
)
from core.mail import check_if_email_valid, check_email_for_code
from core.services import auth as auth_service
from core.services import wallet as wallet_service
from core.services import campaigns as campaign_service
from core.utils.crypto import sign_siwe_for_form
from core.clients.teneo_api import (
    login as teneo_login,
    signup as teneo_signup,
    verify_email as teneo_verify_email,
    smart_id_requirements as teneo_smart_id_requirements,
    link_wallet as teneo_link_wallet,
    create_smart_account as teneo_create_smart_account,
    connect_smart_id as teneo_connect_smart_id,
    isppaccepted as teneo_isppaccepted,
    accept_pp as teneo_accept_pp,
    get_campaigns as teneo_get_campaigns,
    claim_submission as teneo_claim_submission,
)
import asyncio, json, os
from itertools import islice
from web3 import Web3
from eth_account import Account
from eth_account.messages import encode_defunct
from httpx import AsyncClient
import base64
import secrets
import hashlib
import uuid
from Jam_Twitter_API.account_sync import TwitterAccountSync
from Jam_Twitter_API.errors import TwitterAccountSuspended, TwitterError, IncorrectData, RateLimitError
from core.services import twitter as twitter_service

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
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
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
            self.captcha_solver2 = Service2Captcha2(CAPTCHA_API_KEY)
        elif CAPTCHA_SERVICE.lower() == "capmonster":   
            self.captcha_solver = ServiceCapmonster(CAPTCHA_API_KEY)
            self.captcha_solver2 = ServiceCapmonster2(CAPTCHA_API_KEY)
        elif CAPTCHA_SERVICE.lower() == "anticaptcha":
            self.captcha_solver = ServiceAnticaptcha(CAPTCHA_API_KEY)
            self.captcha_solver2 = ServiceAnticaptcha2(CAPTCHA_API_KEY)
        elif CAPTCHA_SERVICE.lower() == "cflsolver":
            self.http_client = AsyncClient()
            self.captcha_solver = CFLSolver(CAPTCHA_API_KEY, self.http_client)
        else:
            raise ValueError(f"Unsupported captcha service: {CAPTCHA_SERVICE}")


    async def start(self):
        """Initialize session"""
        if self.session is None:
            self.session = ClientSession()
        return self

    async def stop(self):
        """Close session"""
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
        telegram_link = "https://t.me/cry_batya"
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
        """Load accounts through utility module (supports reg/auth/farm/wallet/twitter)."""
        try:
            return load_accounts_util(operation_type, log=self.log)
        except Exception as e:
            self.log(f"{Fore.RED}Error loading accounts: {e}{Style.RESET_ALL}")
            return []

    def save_results(self, operation_type: str, success_accounts: list, failed_accounts: list):
        """Save results through utility."""
        return save_results_util(operation_type, success_accounts, failed_accounts, log=self.log)

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
                print("5. Connect Twitter & Claim X Campaign")
                print("6. Exit")
                choose = int(input("Choose action [1/2/3/4/5/6] -> ").strip())

                if choose in [1, 2, 3, 4, 5, 6]:
                    if choose == 6:
                        print(f"{Fore.RED + Style.BRIGHT}Exiting program...{Style.RESET_ALL}")
                        exit(0)  # Exit program
                        
                    action_type = (
                        "Registration" if choose == 1 else 
                        "Authorization" if choose == 2 else 
                        "Farm" if choose == 3 else
                        "Wallet Connection & Creating smart account" if choose == 4 else
                        "Connect Twitter"
                    )
                    print(f"{Fore.GREEN + Style.BRIGHT}Selected: {action_type}{Style.RESET_ALL}")
                    return choose
                else:
                    print(f"{Fore.RED + Style.BRIGHT}Please enter a number from 1 to 6.{Style.RESET_ALL}")
            except ValueError:
                print(f"{Fore.RED + Style.BRIGHT}Invalid input. Enter a number (1, 2, 3, 4, 5 or 6).{Style.RESET_ALL}")
    
    def save_account_data(self, email: str, token: str = None, private_key: str = None):
        """Saves token/key through utility."""
        return save_account_data_util(email, token=token, private_key=private_key, log=self.log)

    async def user_login(self, email: str, password: str, proxy=None):
        try:
            captcha_token = await self.captcha_solver.solve_captcha()
            try:
                result = await teneo_login(email, password, captcha_token, proxy)
                token = result.get('access_token')
                if token:
                    self.save_account_data(email, token=token)
                    return token
                return None
            except ClientResponseError as e:
                if e.status == 401:
                    self.print_message(email, proxy, Fore.RED, "Invalid credentials")
                    return None
                raise  # Pass other errors up
            except Exception as e:
                raise  # Pass all other errors up
        except Exception as e:
            raise  # Pass captcha errors up
        
    async def connect_websocket(self, email: str, token: str, use_proxy: bool):
        wss_url = f"wss://secure.ws.teneo.pro/websocket?accessToken={token}&version=v0.2"
        headers = {
            "Accept-Language": "en-US,en;q=0.9,id;q=0.8",
            "Cache-Control": "no-cache",
            "Connection": "Upgrade",
            "Accept-Encoding":	"gzip, deflate, br, zstd",
            "Origin": "chrome-extension://emcclcoaglgcpoognfiggmhnhgabppkm",
            "Pragma": "no-cache",
            "Sec-WebSocket-Extensions": "permessage-deflate; client_max_window_bits",
            #"Sec-WebSocket-Key": base64.b64encode(secrets.token_bytes(16)).decode(),
            "Sec-WebSocket-Version": "13",
            "Upgrade": "websocket",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"
        }
        send_ping = None

        while True:
            proxy = self.get_next_proxy_for_account(email) if use_proxy else None
            connector = ProxyConnector.from_url(proxy) if proxy else None
            session = ClientSession(connector=connector, timeout=ClientTimeout(total=300))
            try:
                async with session:
                    # Generate new key for each connection attempt
                    headers["Sec-WebSocket-Key"] = base64.b64encode(secrets.token_bytes(16)).decode()
                    
                    async with session.ws_connect(wss_url, headers=headers) as wss:
                        self.print_message(email, proxy, Fore.GREEN, "WebSocket Connected")
                        ping_task = None

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

                        async for msg in wss:
                            try:
                                response = json.loads(msg.data)
                                if response.get("message") == "Connected! Loading your points...":
                                    self.print_message(
                                        email, proxy, Fore.GREEN, 
                                        f"Received message: Connected! Loading your points..."
                                    )
                                elif response.get("message") == "Points loaded successfully":
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
                                    if ping_task is None or ping_task.done():
                                        ping_task = asyncio.create_task(send_ping_message())

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
                                    # Log unknown messages instead of closing the connection
                                    self.print_message(
                                        email, proxy, Fore.YELLOW, 
                                        f"Unknown message: {response.get('message', 'No message in response')}"
                                    )

                            except Exception as e:
                                self.print_message(email, proxy, Fore.RED, f"WebSocket Connection Closed: {Fore.YELLOW + Style.BRIGHT}{str(e)}")
                                if ping_task and not ping_task.done():
                                    ping_task.cancel()
                                    try:
                                        await ping_task
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
            return None              # If token is None, there was an authorization error
        except Exception as e:
            if "401" in str(e) or "Unauthorized" in str(e):
                self.print_message(email, proxy, Fore.RED, "Invalid credentials")
                return None
            self.print_message(email, proxy, Fore.RED, f"Error: {str(e)}")
            return None

    def get_saved_token(self, email: str) -> str:
        """Returns saved token through utility."""
        return get_saved_token_util(email)

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

    def save_error(self, filename: str, email: str, message: str) -> None:
        """Saves error string to result/<filename> with timestamp."""
        try:
            if not os.path.exists('result'):
                os.makedirs('result')
            path = os.path.join('result', filename)
            ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            with open(path, 'a', encoding='utf-8') as f:
                f.write(f"[{ts}] {email} | {message}\n")
        except Exception as e:
            self.log(f"{Fore.RED}Error writing error log {filename}: {e}{Style.RESET_ALL}")

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
        return await teneo_signup(email, password, INVITE_CODE, captcha_token, proxy)

    async def verify_email(self, email: str, token: str, code: str, proxy=None):
        """Verify email with received code"""
        result = await teneo_verify_email(token, code, proxy)
        if isinstance(result, dict) and result.get("access_token"):
            self.save_account_data(email, token=result["access_token"])
        return result

    def validate_email_domain(self, email: str) -> tuple[bool, str]:
        """
        Check email domain validity and get IMAP server.
        
        Returns:
            tuple[bool, str]: (True/False, IMAP server or None)
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
            response = await auth_service.signup(email, password, INVITE_CODE, captcha_token, proxy)
            #print(response)
            
            # If account already exists, consider it successful
            if isinstance(response, dict) and response.get('message') == 'A user with this email address has already been registered':
                self.print_message(email, proxy, Fore.GREEN, "Account already exists")
                return True
                
            # Check that we received correct response from server
            if isinstance(response, dict) and response.get('message') == 'Email with verification code sent':
                registration_token = response.get('token')
                self.print_message(email, proxy, Fore.CYAN, "Waiting for verification code...")
                code = await check_email_for_code(imap_server, email, password, log_func=self.log)
                
                if code is None:
                    self.print_message(email, proxy, Fore.RED, "Failed to get verification code")
                    return False

                self.print_message(email, proxy, Fore.CYAN, "Verifying email...")
                verify_response = await auth_service.verify(registration_token, code, proxy)
                if isinstance(verify_response, dict) and verify_response.get("access_token"):
                    self.print_message(email, proxy, Fore.GREEN, "Registration successful")
                    return True
                else:
                    self.print_message(email, proxy, Fore.RED, f"Email verification failed: {verify_response}")
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
                # Prepare message for signing
                message = f"Permanently link wallet to Teneo account: {email} This can only be done once."
                
                # Create signature using private key
                w3 = Web3()
                message_hash = encode_defunct(text=message)
                signed_message = Account.sign_message(message_hash, private_key=private_key)
                signature = "0x" + signed_message.signature.hex()  # Add 0x prefix to signature
                
                ok = await wallet_service.link_wallet(email, token, wallet_address, private_key, current_proxy, self.log)
                if ok:
                    self.save_account_data(email, private_key=private_key)
                return ok
            except Exception as e:
                # Check if error is related to proxy
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
        """Checks wallet binding status to account"""
        retry_count = 0
        current_proxy = proxy
        
        while retry_count <= max_retries:
            try:
                result = await teneo_smart_id_requirements(token, current_proxy)

                wallet_status = result.get('wallet', False)
                heartbeats = result.get('currentHeartbeats', 0)
                requirements_met = result.get('requirementsMet', False)
                existing_smart_account = result.get('existingSmartAccount', False)
                status = result.get('status', 'unknown')

                return await wallet_service.get_wallet_status(email, token, current_proxy, lambda m: self.print_message(email, current_proxy, Fore.CYAN, m))
            except Exception as e:
                # Check if error is related to proxy
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
                # Generate nonce (current time in milliseconds)
                nonce = str(int(datetime.now().timestamp() * 1000))
                
                # Prepare message for signing
                # Assume message includes nonce
                message = f"Create Teneo Smart Account with nonce: {nonce}"
                
                # Sign message
                w3 = Web3()
                message_hash = encode_defunct(text=message)
                signed_message = Account.sign_message(message_hash, private_key=private_key)
                signature = signed_message.signature.hex()
                
                # Add 0x prefix if not present
                if not signature.startswith("0x"):
                    signature = "0x" + signature
                
                return await wallet_service.create_smart(email, token, wallet_address, private_key, current_proxy, self.log)
                
            except Exception as e:
                # Check if error is related to proxy
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
                result = await teneo_connect_smart_id(token, current_proxy)
                if result.get('status') == 'success' or result.get('connected') == True:
                    self.print_message(email, current_proxy, Fore.GREEN, "Wallet successfully connected to dashboard")
                    return True
                else:
                    self.print_message(email, current_proxy, Fore.RED, f"Failed to connect wallet to dashboard: {result.get('message', 'Unknown error')}")
                    return False
                        
            except Exception as e:
                # Check if error is related to proxy
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
                
            # Check current wallet status
            wallet_status = await self.check_wallet_status(email, token, proxy)
            
            # If wallet is already connected
            if wallet_status and wallet_status.get('wallet', False):
                self.print_message(email, proxy, Fore.GREEN, "Wallet already connected to account")
                
                # Check if smart account already exists
                existing_smart_account = wallet_status.get('existingSmartAccount', False)
                if existing_smart_account:
                    self.print_message(email, proxy, Fore.GREEN, "Smart account already exists")
                    return True
                
                # Create smart account if it doesn't exist yet
                self.print_message(email, proxy, Fore.CYAN, "Creating smart account...")
                return await self.create_smart_account(email, token, wallet_address, private_key, proxy)
                
            # Connect wallet
            wallet_linked = await self.connect_wallet(email, token, wallet_address, private_key, proxy)
            
            # If wallet successfully connected, check and create smart account if needed
            if wallet_linked:
                # Re-check status after wallet connection
                wallet_status = await self.check_wallet_status(email, token, proxy)
                
                # Check if smart account already exists
                existing_smart_account = wallet_status.get('existingSmartAccount', False)
                if existing_smart_account:
                    self.print_message(email, proxy, Fore.GREEN, "Smart account already exists")
                    return True
                
                # Create smart account if it doesn't exist yet
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
            if account.get('Wallet') and account.get('PrivateKey'):  # Process only accounts with wallet and private key
                if isinstance(results[i], Exception) or not results[i]:
                    failed_accounts.append(account)
                elif results[i]:
                    success_accounts.append(account)
                i += 1
        
        # Save results
        self.save_results("wallet", success_accounts, failed_accounts)
        return failed_accounts

    async def get_isppaccepted(self):
        """
        Makes GET request to https://api.teneo.pro/api/users/isppaccepted and returns result.
        """
        try:
            result = await teneo_isppaccepted()
            #self.log(f"Response from /isppaccepted: {result}")
            return result
        except Exception as e:
            self.log(f"{Fore.RED}Error requesting /isppaccepted: {e}{Style.RESET_ALL}")
            return None

    def load_twitter_accounts(self):
        """
        Loads accounts from data/twitter.txt in format login:pass:private_key:twitter_token
        Returns list of dictionaries with keys: Email, Password, PrivateKey, TwitterToken
        """
        filename = "data/twitter.txt"
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
                    parts = line.split(':', 3)
                    if len(parts) == 4:
                        email, password, private_key, twitter_token = parts
                        accounts.append({
                            "Email": email.strip(),
                            "Password": password.strip(),
                            "PrivateKey": private_key.strip(),
                            "TwitterToken": twitter_token.strip()
                        })
                    else:
                        self.log(f"{Fore.YELLOW}Invalid line in twitter.txt: {line}{Style.RESET_ALL}")
            return accounts
        except Exception as e:
            self.log(f"{Fore.RED}Error loading accounts from {filename}: {e}{Style.RESET_ALL}")
            return []


    async def connect_twitter(self, email=None, private_key=None, twitter_token=None, proxy=None):
        
        #print(token)
        if email:
            token = self.get_saved_token(email)
            if token:
                token = token.strip()
                self.log(f"{Fore.YELLOW}Token for {email} loaded from accounts.json (length: {len(token)}){Style.RESET_ALL}")
            else:
                self.log(f"{Fore.RED}Token for {email} not found in accounts.json! Skipping...{Style.RESET_ALL}")
                return None
        else:
            self.log(f"{Fore.RED}Email not provided for token search! Skipping...{Style.RESET_ALL}")
            return None
        try:
            result = await teneo_isppaccepted(token, proxy)
            #self.log(f"Response from /isppaccepted for {email or ''}: {result}")
            if isinstance(result, dict) and result.get('isppAccepted') is False:
                post_result = await teneo_accept_pp(token, proxy)
                #self.log(f"POST /accept-pp for {email or ''}: {post_result}")
        except Exception as e:
            msg = f"Error requesting /isppaccepted: {e}"
            self.log(f"{Fore.RED}{msg} for {email or ''}{Style.RESET_ALL}")
            self.save_error('error_twitter.txt', email or '-', msg)
            return None
        # Check campaign status: if claim is already available — claim immediately
        company_name = "Engage with Teneo on X"
        self.log(f"{Fore.CYAN}Checking campaign status '{company_name}' for {email}...{Style.RESET_ALL}")

        campaign_status = await self.check_campaign_status(email, token, company_name, proxy)
        
        if campaign_status == True:
            self.log(f"{Fore.GREEN}Campaign 'Engage with Teneo on X' completed for {email}{Style.RESET_ALL}")
            return True
        elif campaign_status == "claimable":
            self.log(f"{Fore.YELLOW}Campaign 'Engage with Teneo on X' available for completion for {email}{Style.RESET_ALL}")
            claimed = await self.claim_x_campaign(email, token, proxy)
            if claimed:
                return True
            return "claimable"
        else:
            self.log(f"{Fore.CYAN}Campaign 'Engage with Teneo on X' not yet completed for {email}{Style.RESET_ALL}")
            #return False
        # Make POST request to api.deform.cc to get form information
        """try:
            deform_url = "https://api.deform.cc/"
            deform_data = {
                "operationName": "Form",
                "variables": {
                    "formId": "3ee8174c-5437-46e5-ab09-ce64d6e1b93e"
                },
                "query": "query Form($formId: String!) {\n  form(id: $formId) {\n    isCaptchaEnabled\n    isEmailCopyOfResponseEnabled\n    workspace {\n      billingTier {\n        name\n        __typename\n      }\n      __typename\n    }\n    fields {\n      id\n      required\n      title\n      type\n      description\n      fieldOrder\n      properties\n      TMP_isWaitlistIdentity\n      __typename\n    }\n    pageGroups {\n      id\n      isRandomizable\n      numOfPages\n      __typename\n    }\n    pages {\n      id\n      title\n      description\n      timerInSeconds\n      fields {\n        id\n        required\n        title\n        type\n        description\n        fieldOrder\n        properties\n        TMP_isWaitlistIdentity\n        __typename\n      }\n      formPageGroup {\n        id\n        __typename\n      }\n      __typename\n    }\n    workspace {\n      billingTier {\n        name\n        __typename\n      }\n      __typename\n    }\n    formConditionSets {\n      id\n      logicalOperator\n      name\n      createdAt\n      updatedAt\n      fieldConditions {\n        id\n        operator\n        values\n        formField {\n          id\n          type\n          properties\n          __typename\n        }\n        __typename\n      }\n      fieldActions {\n        id\n        action\n        formField {\n          id\n          __typename\n        }\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n}"
            }
            connector = ProxyConnector.from_url(proxy) if proxy else None
            async with ClientSession(connector=connector, timeout=ClientTimeout(total=30)) as session:
                async with session.post(deform_url, json=deform_data) as deform_response:
                    deform_response.raise_for_status()
                    deform_result = await deform_response.json()
                    #self.log(f"POST api.deform.cc Form query for {email or ''}: {deform_result}")
        except Exception as e:
            self.log(f"{Fore.RED}Error requesting api.deform.cc Form query for {email or ''}: {e}{Style.RESET_ALL}")
            return None
        """
        # Connect Twitter account
        try:
            one_time_token = await twitter_service.bind_and_get_one_time_token(email, twitter_token, proxy, self.log)
            if not one_time_token:
                msg = "Failed to get oneTimeToken"
                self.log(f"{Fore.RED}{msg} for {email}{Style.RESET_ALL}")
                self.save_error('error_twitter.txt', email, msg)
                return None
            #print("Twitter account successfully connected")
        except Exception as e:
            msg = f"Error connecting Twitter: {e}"
            self.log(f"{Fore.RED}{msg} for {email or ''}{Style.RESET_ALL}")
            self.save_error('error_twitter.txt', email, msg)
            return None
        

        # Create wallet signature
        try:
            wallet_data = await self.submit_form_with_wallet_signature(email, private_key, proxy)
            if not wallet_data:
                self.log(f"{Fore.RED}Failed to get wallet data for {email}{Style.RESET_ALL}")
                return None
            
            #self.log(f"Wallet successfully connected for {email}: {wallet_data['wallet_address']}")
        except Exception as e:
            self.log(f"{Fore.RED}Error working with wallet for {email}{Style.RESET_ALL}")
            return None
        #print("requesting captcha")
        self.log(f"{Fore.CYAN}Requesting captcha for {email}{Style.RESET_ALL}")
        captcha_token = await self.captcha_solver2.solve_captcha()
        #captcha_token = "0cAFcWeA70VCZn9-tniN2n8n9ugZtpyu0k8Q8mb7al1emfSoQKNLY4z38nDuC2yPIJrntbaXSpDJpBynyIUzwPxMS09dyLYbWnEpzIg04CjvecFAbxXkx2XBWsCcSwGV6ordcD0idFju5CtbQiWRA5_q6OqwraqsVFvCQ93ecgtVKzf0bgClXdn8aSivl53hJEH-zG_b1qCQ0MjIvDT1mTetWMGLN0NbsTlJdBi98W4phq3xxgggHoT_9hmUebdw53iP5lTHA1vwLhb7H98q40WrZik018P98EMTaiQnTc9WgfstAPavOUxVMNf3u_eC1FpALcIfuhreMjf9IbwklHCM-178ETsPb1uLxqtAOkKzj4jQa4Em1Pnhl4JRVzAh5FVg5oUenFuTZSBDn86XUqCz-78YTjSixEu1zWFWS5gMJKOXUL8vqilgVemFOwaEDMBhlm2OPQO2wxtCc55mykAWIdXY0SsW_3ayFIGs0QFOsa9N4TQQKhadiBctO5kTFqPYLEqgsY2S_NrGbH-Y59HQWsZiJSkJ57UzG2_k2gY3yVkQiaI-CeJEIlJoq2ZBondV4dklih3XRHWVJ5WlSiSPa_PsZ7-KQ-vRAAV2F9Hyr4oxEnI0j329zTSFe6PZz5bMIdaENumwxTClugJQNqyYhEVkNNGrgb350TSkoNJ8S1qCGd9RH1rXcsLC7XHLBy-1OlHesiXM2JXGM08gfuJnZXLNRagsixJ3Z-nUUVDBkRoGjJ4Z-OtnszRyksWpg50oF99ZqsbriKHbi4Izf_jt5F3KS5-WzuShnDULazAMH3QNcrNBxAEwk"
        #print(f"captcha received: {captcha_token}")
        # Make POST request to api.deform.cc
        try:
            deform_url = "https://api.deform.cc/"
            deform_data =  {
                "operationName": "AddFormResponse",
                "variables": {
                    "data": {
                        "addFormResponseItems": [{
                            "formFieldId": "2a52b0ef-6098-4982-a1d5-6d7e6466a5f4",
                            "inputValue": {
                                "address": wallet_data["wallet_address"],
                                "signature": wallet_data["signature"],
                                "message": wallet_data["message"],
                                "ethAddress": wallet_data["wallet_address"]
                            }
                        }, {
                            "formFieldId": "3ab37c3e-ca1a-4684-a970-64b5c0628521",
                            "inputValue": {
                                "choiceRefs": ["0b92ab28-121e-4206-8c26-7d28676080df"]
                            }
                        }, {
                            "formFieldId": "221ae09a-68c2-4807-b70c-65bf4f988fd3",
                            "inputValue": {
                                "oneTimeToken": one_time_token
                            }
                        }],
                        "formId": "3ee8174c-5437-46e5-ab09-ce64d6e1b93e",
                        "captchaToken": captcha_token,   # Need to get
                        "browserFingerprint": "31ef7106755ab8df6624eb1da47a4a8c",
                        "referralCode": ""
                    }
                },
                "query": "mutation AddFormResponse($data: AddFormResponseInput!) {\n  addFormResponse(data: $data) {\n    id\n    createdAt\n    tagOutputs {\n      tag {\n        id\n        __typename\n      }\n      queryOutput\n      __typename\n    }\n    form {\n      type\n      __typename\n    }\n    campaignSpot {\n      identityType\n      identityValue\n      __typename\n    }\n    __typename\n  }\n}"
            }
            connector = ProxyConnector.from_url(proxy) if proxy else None
            async with ClientSession(connector=connector, timeout=ClientTimeout(total=30)) as session:
                async with session.post(deform_url, json=deform_data) as deform_response:
                    deform_response.raise_for_status()
                    deform_result = await deform_response.json()
                    #self.log(f"POST api.deform.cc for {email or ''}: {deform_result}")
                    
                    # Check for errors in response
                    if deform_result.get('errors'):
                        error_message = deform_result['errors'][0].get('message', 'Unknown error')
                        self.log(f"{Fore.RED}Error sending form for {email}: {error_message}{Style.RESET_ALL}")
                        return False
                    
                    # Check response success
                    if (deform_result.get('data', {}).get('addFormResponse', {}).get('id') and 
                        deform_result.get('data', {}).get('addFormResponse', {}).get('createdAt')):
                        
                        response_id = deform_result['data']['addFormResponse']['id']
                        created_at = deform_result['data']['addFormResponse']['createdAt']
                        self.log(f"{Fore.GREEN}Form successfully sent for {email}! ID: {response_id}, created: {created_at}{Style.RESET_ALL}")
                        
                        # Check campaign status with retries (until claim)
                        attempts = 5
                        for i in range(attempts):
                            self.log(
                                f"{Fore.CYAN}Checking campaign status for {email}... attempt {i+1}/{attempts}{Style.RESET_ALL}"
                            )
                            campaign_status = await self.check_campaign_status(email, token, company_name, proxy)
                            if campaign_status == "claimable":
                                self.log(
                                    f"{Fore.YELLOW}Campaign 'Engage with Teneo on X' available for completion for {email}{Style.RESET_ALL}"
                                )
                                # Try to claim
                                claimed = await self.claim_x_campaign(email, token, proxy)
                                if claimed:
                                    return True
                                return "claimable"
                            if campaign_status is True:
                                self.log(
                                    f"{Fore.GREEN}Campaign 'Engage with Teneo on X' completed for {email}{Style.RESET_ALL}"
                                )
                                return True
                            if i < attempts - 1:
                                self.log(
                                    f"{Fore.CYAN}Claim not available. Waiting 60 seconds before next check...{Style.RESET_ALL}"
                                )
                                await asyncio.sleep(60)
                        self.log(
                            f"{Fore.YELLOW}Claim did not become available after {attempts} attempts for {email}{Style.RESET_ALL}"
                        )
                        return False
                        #else:
                           # self.log(f"{Fore.CYAN}Campaign 'Engage with Teneo on X' not yet completed for {email}, continuing execution...{Style.RESET_ALL}")
                            # DON'T return False, continue execution
                    else:
                        msg = "Error sending form: invalid response"
                        self.log(f"{Fore.RED}{msg} for {email}{Style.RESET_ALL}")
                        self.save_error('error_twitter.txt', email, msg)
                        return False
                        
        except Exception as e:
            msg = f"Error requesting api.deform.cc: {e}"
            self.log(f"{Fore.RED}{msg} for {email or ''}{Style.RESET_ALL}")
            self.save_error('error_twitter.txt', email, msg)
            return None

    async def claim_x_campaign(self, email: str, token: str, proxy=None) -> bool:
        """Attempts to claim X-campaign."""
        try:
            result = await teneo_claim_submission(token, "x", proxy)
            if isinstance(result, dict) and result.get("success") is True:
                self.log(f"{Fore.GREEN}Claim successful for {email}: {result.get('message', '')}{Style.RESET_ALL}")
                return True
            self.log(f"{Fore.YELLOW}Claim not completed for {email}: {result}{Style.RESET_ALL}")
            self.save_error('error_twitter.txt', email, f"Claim failed: {result}")
            return False
        except Exception as e:
            msg = f"Error claiming X-campaign: {e}"
            self.log(f"{Fore.RED}{msg} for {email}{Style.RESET_ALL}")
            self.save_error('error_twitter.txt', email, msg)
            return False
        
    async def connect_twitter_account(self, email, auth_token, proxy=None):
        # Moved to core/services/twitter.py (kept for backward compatibility if called elsewhere)
        return await twitter_service.bind_and_get_one_time_token(email, auth_token, proxy, self.log)
    
    async def check_campaign_status(self, email, token, company_name, proxy=None):
        """
        Checks status of specific campaign
        Returns True if campaign is completed, False if not
        """
        try:
            return await campaign_service.get_status(email, token, company_name, proxy, self.log)
                    
        except Exception as e:
            self.log(f"{Fore.RED}Error checking campaign status '{company_name}' for {email}: {e}{Style.RESET_ALL}")
            return False
    
    def get_twitter_auth_token(self, email):
        """Get Twitter auth_token for email from twitter.txt file"""
        twitter_accounts = self.load_accounts("twitter")
        for account in twitter_accounts:
            if len(account) >= 2 and account[0] == email:
                return account[1]  # auth_token
        return None

    async def submit_form_with_wallet_signature(self, email, private_key, proxy=None):
        """Create wallet signature (unified format, address in lower-case)."""
        try:
            data = sign_siwe_for_form(private_key)
            # Strict signature verification (recover must match address from private key)
            try:
                recovered = Account.recover_message(
                    encode_defunct(text=data["message"]),
                    signature=bytes.fromhex(data["signature"][2:])
                )
                if recovered != data["wallet_address"]:
                    self.log(
                        f"{Fore.RED}Signature verification failed for {email}: recovered={recovered} addr={data['wallet_address']}{Style.RESET_ALL}"
                    )
                    return None
            except Exception as e:
                self.log(f"{Fore.RED}Error in signature verification for {email}: {e}{Style.RESET_ALL}")
                return None
            return data
        except Exception as e:
            self.log(f"{Fore.RED}Error signing wallet for {email}: {e}{Style.RESET_ALL}")
            return None
    
    def get_wallet_data(self, email):
        """Get wallet address and private key for email from wallet.txt file"""
        wallet_accounts = self.load_accounts("wallet")
        self.log(f"Loaded {len(wallet_accounts)} wallets, searching for {email}")
        
        for account in wallet_accounts:
            if account.get("Email") == email:
                wallet_data = {
                    "address": account.get("Wallet"),  # wallet address
                    "private_key": account.get("PrivateKey")  # private key
                }
                self.log(f"Found wallet for {email}: address={wallet_data['address'][:10]}..., private_key={'*' * 10}")
                return wallet_data
        
        self.log(f"Wallet for {email} not found in {len(wallet_accounts)} loaded accounts")
        return None

    async def process_twitter_batch(self, accounts_batch, use_proxy):
        """
        Processes batch of accounts from twitter.txt: makes get request with token and proxy, collects failed ones.
        If token not found — tries to get it through get_access_token (as in other modes).
        """
        tasks = []
        failed_accounts = []
        success_accounts = []
        for account in accounts_batch:
            email = account.get("Email")
            password = account.get("Password")
            pkey = account.get("PrivateKey")
            t_token = account.get("TwitterToken")
            if not t_token:
                t_token = self.get_saved_token(email)
            proxy = self.get_next_proxy_for_account(email) if use_proxy else None
            if not t_token:
                if password:
                    self.log(f"{Fore.YELLOW}Trying to get token for {email} through authorization...{Style.RESET_ALL}")
                    t_token = await self.get_access_token(email, password, use_proxy)
                if not t_token:
                    self.log(f"{Fore.RED}Token for {email} not found and failed to get through authorization! Skipping...{Style.RESET_ALL}")
                    failed_accounts.append(account)
                    continue
            tasks.append(self.connect_twitter(email, pkey,t_token,proxy))
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for account, result in zip(accounts_batch, results):
            if isinstance(result, Exception) or not result:
                failed_accounts.append(account)
            else:
                success_accounts.append(account)
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

                # Check that there are accounts with wallets
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

            if use_proxy_choice == 5:
                self.clear_terminal()
                self.welcome()
                self.log(f"{Fore.GREEN + Style.BRIGHT}Connect Twitter mode selected.{Style.RESET_ALL}")
                accounts = self.load_twitter_accounts()
                if not accounts:
                    self.log(f"{Fore.RED}No accounts in data/twitter.txt{Style.RESET_ALL}")
                    return
                use_proxy = True
                await self.load_proxies()
                self.log(f"{Fore.CYAN + Style.BRIGHT}-{Style.RESET_ALL}"*75)
                failed_accounts = []
                batch_size = min(MAX_AUTH_THREADS, len(accounts))
                total_batches = (len(accounts) + batch_size - 1) // batch_size
                total_accounts = len(accounts)
                self.log(f"{Fore.CYAN}Starting Twitter check for {total_accounts} accounts in batches of {batch_size}{Style.RESET_ALL}")
                for i in range(0, len(accounts), batch_size):
                    current_batch = i // batch_size + 1
                    batch = list(islice(accounts, i, i + batch_size))
                    accounts_processed = min(i + batch_size, total_accounts)
                    self.log(
                        f"{Fore.CYAN}Processing batch {current_batch}/{total_batches} "
                        f"({len(batch)} accounts, progress: {accounts_processed}/{total_accounts}){Style.RESET_ALL}"
                    )
                    batch_failed = await self.process_twitter_batch(batch, use_proxy)
                    failed_accounts.extend(batch_failed)
                if failed_accounts:
                    self.log(f"{Fore.YELLOW}Failed Twitter checks: {len(failed_accounts)}/{len(accounts)}{Style.RESET_ALL}")
                else:
                    self.log(f"{Fore.GREEN}All Twitter checks successful!{Style.RESET_ALL}")
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