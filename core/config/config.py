# Captcha service settings
CAPTCHA_SERVICE = "2captcha"  # Captcha solving service (available: 2captcha, capmonster, anticaptcha, cflsolver)
CAPTCHA_API_KEY = "api"  # API key for the service

CFLSOLVER_BASE_URL = "http://localhost:5000"  # URL for local CFLSolver API

CAPTCHA_WEBSITE_KEY = "0x4AAAAAAAkhmGkb2VS6MRU0"  # Cloudflare Turnstile captcha key
CAPTCHA_WEBSITE_URL = "https://dashboard.teneo.pro/auth"  # Site URL for captcha

CAPTCHA_WEBSITE_KEY2 = "6LfYWucjAAAAAIAKO0PT4fkjfGddTgyIDqId_hR7"  # recaptcha2 captcha key
CAPTCHA_WEBSITE_URL2 = "https://extra-points.teneo.pro"  # Site URL for captcha

# Authorization settings
MAX_AUTH_THREADS = 5  # Maximum number of concurrent authorization threads
MAX_REG_THREADS = 3   # Maximum number of concurrent registration threads (lower due to email verification)

INVITE_CODE = "Svaag"  # Invite code for registration
