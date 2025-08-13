"""
Mail configuration settings.
"""
from dataclasses import dataclass, field
from typing import Dict, Set


@dataclass
class MailConfig:
    """Settings for working with mail."""

    IMAP_SETTINGS: Dict[str, str] = field(default_factory=lambda: {
        # Standard email providers
        'rambler.ru': 'imap.rambler.ru',
        'hotmail.com': 'imap-mail.outlook.com',
        'outlook.com': 'imap-mail.outlook.com',
        'mail.ru': 'imap.mail.ru',
        'gmail.com': 'imap.gmail.com',
        'gmx.com': 'imap.gmx.com',
        'yahoo.com': 'imap.mail.yahoo.com',
        'gmx.net': 'imap.gmx.net',
        'gmx.de': 'imap.gmx.net',

        # Onet domains
        'onet.pl': 'imap.poczta.onet.pl',
        'onet.com.pl': 'imap.poczta.onet.pl',
        'op.pl': 'imap.poczta.onet.pl',
        'onet.eu': 'imap.poczta.onet.pl',
        'gazeta.pl': 'imap.gazeta.pl',

        # Additional Rambler domains
        'ro.ru': 'imap.rambler.ru',
        'lenta.ru': 'imap.rambler.ru',
        'autorambler.ru': 'imap.rambler.ru',
        'myrambler.ru': 'imap.rambler.ru',

        # Notletters domains
        'prefarcedemail.com': 'imap.notletters.com',
        'prefarmencmail.com': 'imap.notletters.com',
        'consaltemail.com': 'imap.notletters.com',
        'pragresivemail.com': 'imap.notletters.com',
        'belettersmail.com': 'imap.notletters.com',
        'onelettersmail.com': 'imap.notletters.com',
        'notlettersmail.com': 'imap.notletters.com',

        # Firstmail domains
        'fumesmail.com': 'imap.firstmail.ltd',
        'limandomail.com': 'imap.firstmail.ltd',
        'desedumail.com': 'imap.firstmail.ltd',
        'derrenmail.com': 'imap.firstmail.ltd',
        'chromomail.com': 'imap.firstmail.ltd',

        # T-Online
        't-online.de': 'secureimap.t-online.de'
    })

    ALLOWED_DOMAINS: Set[str] = field(default_factory=lambda: set())

    def __post_init__(self) -> None:
        """Initialization after object creation."""
        self.ALLOWED_DOMAINS = set(self.IMAP_SETTINGS.keys()) 