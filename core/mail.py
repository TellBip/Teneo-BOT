import re
from typing import Optional
import asyncio
from bs4 import BeautifulSoup
from imap_tools import MailBox, AND, A
from colorama import Fore, Style

async def check_if_email_valid(imap_server: str, email: str, password: str, log_func=print) -> bool:
    log_func(f"{Fore.CYAN + Style.BRIGHT}[ Account:{Style.RESET_ALL}"
             f"{Fore.WHITE + Style.BRIGHT} {email} {Style.RESET_ALL}"
             f"{Fore.MAGENTA + Style.BRIGHT}-{Style.RESET_ALL}"
             f"{Fore.CYAN + Style.BRIGHT} Status:{Style.RESET_ALL}"
             f"{Fore.WHITE + Style.BRIGHT} Checking if email is valid...{Style.RESET_ALL}"
             f"{Fore.CYAN + Style.BRIGHT} ]{Style.RESET_ALL}")
    try:
        await asyncio.to_thread(lambda: MailBox(imap_server).login(email, password))
        return True
    except Exception as error:
        log_func(f"{Fore.CYAN + Style.BRIGHT}[ Account:{Style.RESET_ALL}"
                f"{Fore.WHITE + Style.BRIGHT} {email} {Style.RESET_ALL}"
                f"{Fore.MAGENTA + Style.BRIGHT}-{Style.RESET_ALL}"
                f"{Fore.CYAN + Style.BRIGHT} Status:{Style.RESET_ALL}"
                f"{Fore.RED + Style.BRIGHT} Email is invalid (IMAP): {error}{Style.RESET_ALL}"
                f"{Fore.CYAN + Style.BRIGHT} ]{Style.RESET_ALL}")
        return False

async def check_email_for_code(imap_server: str, email: str, password: str, max_attempts: int=8, delay_seconds: int=15, log_func=print) -> Optional[str]:
    await asyncio.sleep(15)
    code_pattern = r'<strong>(\d{6})</strong>'

    log_func(f"{Fore.CYAN + Style.BRIGHT}[ Account:{Style.RESET_ALL}"
             f"{Fore.WHITE + Style.BRIGHT} {email} {Style.RESET_ALL}"
             f"{Fore.MAGENTA + Style.BRIGHT}-{Style.RESET_ALL}"
             f"{Fore.CYAN + Style.BRIGHT} Status:{Style.RESET_ALL}"
             f"{Fore.WHITE + Style.BRIGHT} Checking email for code...{Style.RESET_ALL}"
             f"{Fore.CYAN + Style.BRIGHT} ]{Style.RESET_ALL}")
    try:
        async def search_in_mailbox():
            return await asyncio.to_thread(lambda: search_for_code_sync(MailBox(imap_server).login(email, password), code_pattern, email, log_func))
        
        for attempt in range(max_attempts):
            code = await search_in_mailbox()
            if code:
                log_func(f"{Fore.CYAN + Style.BRIGHT}[ Account:{Style.RESET_ALL}"
                        f"{Fore.WHITE + Style.BRIGHT} {email} {Style.RESET_ALL}"
                        f"{Fore.MAGENTA + Style.BRIGHT}-{Style.RESET_ALL}"
                        f"{Fore.CYAN + Style.BRIGHT} Status:{Style.RESET_ALL}"
                        f"{Fore.GREEN + Style.BRIGHT} Code found: {code}{Style.RESET_ALL}"
                        f"{Fore.CYAN + Style.BRIGHT} ]{Style.RESET_ALL}")
                return code
            if attempt < max_attempts - 1:
                log_func(f"{Fore.CYAN + Style.BRIGHT}[ Account:{Style.RESET_ALL}"
                        f"{Fore.WHITE + Style.BRIGHT} {email} {Style.RESET_ALL}"
                        f"{Fore.MAGENTA + Style.BRIGHT}-{Style.RESET_ALL}"
                        f"{Fore.CYAN + Style.BRIGHT} Status:{Style.RESET_ALL}"
                        f"{Fore.YELLOW + Style.BRIGHT} Code not found. Waiting {delay_seconds} seconds before next attempt...{Style.RESET_ALL}"
                        f"{Fore.CYAN + Style.BRIGHT} ]{Style.RESET_ALL}")
                await asyncio.sleep(delay_seconds)
        else:
            log_func(f"{Fore.CYAN + Style.BRIGHT}[ Account:{Style.RESET_ALL}"
                    f"{Fore.WHITE + Style.BRIGHT} {email} {Style.RESET_ALL}"
                    f"{Fore.MAGENTA + Style.BRIGHT}-{Style.RESET_ALL}"
                    f"{Fore.CYAN + Style.BRIGHT} Status:{Style.RESET_ALL}"
                    f"{Fore.YELLOW + Style.BRIGHT} Code not found after {max_attempts} attempts, searching in spam folder...{Style.RESET_ALL}"
                    f"{Fore.CYAN + Style.BRIGHT} ]{Style.RESET_ALL}")
            spam_folders = ('SPAM', 'Spam', 'spam', 'Junk', 'junk')
            for spam_folder in spam_folders:
                async def search_in_spam():
                    return await asyncio.to_thread(lambda: search_for_code_in_spam_sync(MailBox(imap_server).login(email, password), code_pattern, spam_folder, email, log_func))
                code = await search_in_spam()
                if code:
                    return code
            else:
                log_func(f"{Fore.CYAN + Style.BRIGHT}[ Account:{Style.RESET_ALL}"
                        f"{Fore.WHITE + Style.BRIGHT} {email} {Style.RESET_ALL}"
                        f"{Fore.MAGENTA + Style.BRIGHT}-{Style.RESET_ALL}"
                        f"{Fore.CYAN + Style.BRIGHT} Status:{Style.RESET_ALL}"
                        f"{Fore.RED + Style.BRIGHT} Code not found in spam folder after multiple attempts{Style.RESET_ALL}"
                        f"{Fore.CYAN + Style.BRIGHT} ]{Style.RESET_ALL}")
    except Exception as error:
        log_func(f"{Fore.CYAN + Style.BRIGHT}[ Account:{Style.RESET_ALL}"
                f"{Fore.WHITE + Style.BRIGHT} {email} {Style.RESET_ALL}"
                f"{Fore.MAGENTA + Style.BRIGHT}-{Style.RESET_ALL}"
                f"{Fore.CYAN + Style.BRIGHT} Status:{Style.RESET_ALL}"
                f"{Fore.RED + Style.BRIGHT} Failed to check email for code: {error}{Style.RESET_ALL}"
                f"{Fore.CYAN + Style.BRIGHT} ]{Style.RESET_ALL}")

def search_for_code_sync(mailbox: MailBox, code_pattern: str, email: str, log_func=print) -> Optional[str]:
    # First look for emails from specific sender
    messages = list(mailbox.fetch(AND(from_='mail@norply.teneo.pro', seen=False)))
    log_func(f"{Fore.CYAN + Style.BRIGHT}[ Account:{Style.RESET_ALL}"
            f"{Fore.WHITE + Style.BRIGHT} {email} {Style.RESET_ALL}"
            f"{Fore.MAGENTA + Style.BRIGHT}-{Style.RESET_ALL}"
            f"{Fore.CYAN + Style.BRIGHT} Status:{Style.RESET_ALL}"
            f"{Fore.WHITE + Style.BRIGHT} Searching messages from mail@norply.teneo.pro: {len(messages)} found{Style.RESET_ALL}"
            f"{Fore.CYAN + Style.BRIGHT} ]{Style.RESET_ALL}")

    # If no emails found from specific sender, search in all emails
    if not messages:
        messages = list(mailbox.fetch(AND(seen=False)))
        log_func(f"{Fore.CYAN + Style.BRIGHT}[ Account:{Style.RESET_ALL}"
                f"{Fore.WHITE + Style.BRIGHT} {email} {Style.RESET_ALL}"
                f"{Fore.MAGENTA + Style.BRIGHT}-{Style.RESET_ALL}"
                f"{Fore.CYAN + Style.BRIGHT} Status:{Style.RESET_ALL}"
                f"{Fore.WHITE + Style.BRIGHT} Searching all unread messages: {len(messages)} found{Style.RESET_ALL}"
                f"{Fore.CYAN + Style.BRIGHT} ]{Style.RESET_ALL}")

    for msg in messages:
        body = msg.text or msg.html
        if body:
            match = re.search(code_pattern, body)
            if match:
                code = match.group(1)
                log_func(f"{Fore.CYAN + Style.BRIGHT}[ Account:{Style.RESET_ALL}"
                        f"{Fore.WHITE + Style.BRIGHT} {email} {Style.RESET_ALL}"
                        f"{Fore.MAGENTA + Style.BRIGHT}-{Style.RESET_ALL}"
                        f"{Fore.CYAN + Style.BRIGHT} Status:{Style.RESET_ALL}"
                        f"{Fore.GREEN + Style.BRIGHT} Found verification code: {code}{Style.RESET_ALL}"
                        f"{Fore.CYAN + Style.BRIGHT} ]{Style.RESET_ALL}")
                return code
    return None

def search_for_code_in_spam_sync(mailbox: MailBox, link_pattern: str, spam_folder: str, email: str, log_func=print) -> Optional[str]:
    if mailbox.folder.exists(spam_folder):
        mailbox.folder.set(spam_folder)
        return search_for_code_sync(mailbox, link_pattern, email, log_func)
    return None