# Teneo Community Node BOT
Teneo Community Node BOT

- Register Here : [Teneo Community Node Dashboard](https://dashboard.teneo.pro/auth/signup)
- Download Extension Here : [Teneo Community Node Extension](https://chromewebstore.google.com/detail/teneo-community-node/emcclcoaglgcpoognfiggmhnhgabppkm)
- Use Code : V5mx3

## Features

  - Auto Authorization and Token Management
  - Auto Get Account Information
  - Auto Claim Refferal Reward
  - Auto Claim Refferal & Heartbeat Campaigns Reward
  - Auto Connect and Reconnect Websocket
  - Auto Receive Message Every 15 Minutes
  - Multi Accounts With Threads
  - Proxy Support for All Operations

## Requirements

- Make sure you have Python3.9 or higher installed and pip.

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

2. **accounts.txt:** Create `data/accounts.txt` with your accounts in the following format:
   ```
   email1@example.com:password1
   email2@example.com:password2
   ```

3. **proxy.txt:** Create `data/proxy.txt` with your proxies in the following format:
   ```
   ip:port # Default Protocol HTTP
   protocol://ip:port
   protocol://user:pass@ip:port
   ```
   Supported protocols: http, https, socks4, socks5

4. **config.py:** Configure captcha service in `data/config.py`:
   ```python
   CAPTCHA_SERVICE = "2captcha"  # Available: 2captcha, capmonster, anticaptcha
   CAPTCHA_API_KEY = "your_api_key"
   ```

## Usage

Run the bot:
```bash
python bot.py #or python3 bot.py
```

The bot has 3 modes:
1. Registration (Coming soon...)
2. Authorization (Get and save tokens)
3. Farming (Connect to WebSocket and earn points)

## Telegram http://t.me/+1fc0or8gCHsyNGFi

Thank you for visiting this repository, don't forget to contribute in the form of follows and stars.
If you have questions, find an issue, or have suggestions for improvement, feel free to contact me or open an *issue* in this GitHub repository.

