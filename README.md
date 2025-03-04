# Teneo Community Node BOT
Teneo Community Node BOT

- Register Here : [Teneo Community Node Dashboard](https://dashboard.teneo.pro/auth/signup)
- Download Extension Here : [Teneo Community Node Extension](https://chromewebstore.google.com/detail/teneo-community-node/emcclcoaglgcpoognfiggmhnhgabppkm)
- Use Code : V5mx3

## Features

  - Auto Registration with Email Verification
  - Auto Authorization and Token Management
  - Auto Get Account Information
  - Auto Claim Refferal Reward
  - Auto Claim Refferal & Heartbeat Campaigns Reward
  - Auto Connect and Reconnect Websocket
  - Auto Receive Message Every 15 Minutes
  - Multi Accounts With Threads
  - Proxy Support for All Operations
  - Email Support for Registration (IMAP)
  - Smart Token Management System

## Requirements

- Make sure you have Python3.9 or higher installed and pip.
- Required Python packages (installed via requirements.txt):
  - aiohttp
  - beautifulsoup4
  - imap-tools
  - colorama
  - fake-useragent
  - aiohttp-socks

## Installation

1. **Clone The Repositories:**
   ```bash
   git clone https://github.com/TellBip/Teneo-BOT.git
   ```
   ```bash
   cd Teneo-BOT
   ```

2. **Install Requirements:**
   ```bash
   pip install -r requirements.txt #or pip3 install -r requirements.txt
   ```

## Configuration

1. **Create data folder:**
   ```bash
   mkdir data
   ```

2. **Registration accounts:** Create `data/reg.txt` for registration with format:
   ```
   email1@example.com:password1
   email2@example.com:password2
   ```

3. **Authorization accounts:** Create `data/auth.txt` for authorization with format:
   ```
   email1@example.com:password1
   email2@example.com:password2
   ```

4. **Farming accounts:** Create `data/farm.txt` for farming with format:
   ```
   email1@example.com:password1
   email2@example.com:password2
   ```

5. **proxy.txt:** Create `data/proxy.txt` with your proxies in the following format:
   ```
   ip:port # Default Protocol HTTP
   protocol://ip:port
   protocol://user:pass@ip:port
   ```
   Supported protocols: http, https, socks4, socks5

6. **config.py:** Configure captcha service and threads in `core/config/config.py`:
   ```python
   CAPTCHA_SERVICE = "2captcha"  # Available: 2captcha, capmonster, anticaptcha
   CAPTCHA_API_KEY = "your_api_key"
   MAX_AUTH_THREADS = 5  # Maximum threads for authorization
   MAX_REG_THREADS = 3   # Maximum threads for registration
   INVITE_CODE = "V5mx3" # Referral code
   ```

7. **mail_config.py:** Configure email settings in `core/config/mail_config.py` for supported email domains.

## Usage

Run the bot:
```bash
python bot.py #or python3 bot.py
```

The bot has 3 modes:
1. Registration
   - Supports automatic email verification
   - Saves successful registrations to result/good_reg.txt
   - Saves failed registrations to result/bad_reg.txt
   - Automatically saves tokens to data/accounts.json
2. Authorization
   - Gets and saves tokens
   - Saves successful authorizations to result/good_auth.txt
   - Saves failed authorizations to result/bad_auth.txt
3. Farming
   - Connects to WebSocket and earns points
   - Automatic reconnection on disconnects
   - Real-time points and heartbeat tracking

## Results

The bot creates a `result` folder with the following files:
- good_reg.txt: Successfully registered accounts
- bad_reg.txt: Failed registration attempts
- good_auth.txt: Successfully authorized accounts
- bad_auth.txt: Failed authorization attempts
- good_farm.txt: Successfully farming accounts
- bad_farm.txt: Failed farming attempts

Tokens are stored in `data/accounts.json` for future use.

## Telegram http://t.me/+1fc0or8gCHsyNGFi

Thank you for visiting this repository, don't forget to contribute in the form of follows and stars.
If you have questions, find an issue, or have suggestions for improvement, feel free to contact me or open an *issue* in this GitHub repository.

