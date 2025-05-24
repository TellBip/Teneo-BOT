# Captcha service settings
CAPTCHA_SERVICE = "cflsolver"  # Captcha solving service (available: 2captcha, capmonster, anticaptcha, cflsolver)
CAPTCHA_API_KEY = "api"  # API key for the service

CFLSOLVER_BASE_URL = "http://localhost:5000"  # URL для локального API CFLSolver

CAPTCHA_WEBSITE_KEY = "0x4AAAAAAAkhmGkb2VS6MRU0"  # Ключ Cloudflare Turnstile капчи
CAPTCHA_WEBSITE_URL = "https://dashboard.teneo.pro/auth"  # URL сайта для капчи


# Authorization settings
MAX_AUTH_THREADS = 5  # Maximum number of concurrent authorization threads
MAX_REG_THREADS = 3   # Maximum number of concurrent registration threads (lower due to email verification)

INVITE_CODE = "Svaag"  # Invite code for registration
