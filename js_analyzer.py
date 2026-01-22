# -*- coding: utf-8 -*-
"""
JS Analyzer - Burp Suite Extension
Focused JavaScript analysis with strict endpoint filtering to reduce noise.
"""

from burp import IBurpExtender, IContextMenuFactory, ITab

from javax.swing import JMenuItem
from java.awt.event import ActionListener
from java.util import ArrayList
from java.io import PrintWriter

import sys
import os
import re
import inspect

# Add extension directory to path
try:
    _frame = inspect.currentframe()
    if _frame and hasattr(_frame, 'f_code'):
        ext_dir = os.path.dirname(os.path.abspath(_frame.f_code.co_filename))
    else:
        ext_dir = os.getcwd()
except:
    ext_dir = os.getcwd()

if ext_dir and ext_dir not in sys.path:
    sys.path.insert(0, ext_dir)

from ui.results_panel import ResultsPanel


# ==================== ENDPOINT PATTERNS ====================
# Focus on high-value API endpoints only

ENDPOINT_PATTERNS = [
    re.compile(
        r'["\'`]((?:https?:)?//[^"\'`]+?/api(?:/v\d+)?/[A-Za-z0-9/_\-\.~!$&\'()*+,;=:@%{}:\[\]\?=#]+)["\'`]',
        re.IGNORECASE
    ),

    re.compile(
        r'["\'`](/api(?:/v\d+)?/[A-Za-z0-9/_\-\.~!$&\'()*+,;=:@%{}:\[\]\?=#]+)["\'`]',
        re.IGNORECASE
    ),

    re.compile(
        r'["\'`](/v\d+/[A-Za-z0-9/_\-\.~!$&\'()*+,;=:@%{}:\[\]\?=#]+)["\'`]',
        re.IGNORECASE
    ),

    re.compile(
        r'["\'`](/rest/[A-Za-z0-9/_\-\.~!$&\'()*+,;=:@%{}:\[\]\?=#]+)["\'`]',
        re.IGNORECASE
    ),

    re.compile(
        r'["\'`](/graphql[^\s"\'`<>]*)["\'`]',
        re.IGNORECASE
    ),

    re.compile(
        r'["\'`](/oauth[0-9]*/[A-Za-z0-9/_\-\.~!$&\'()*+,;=:@%{}:\[\]\?=#]+)["\'`]',
        re.IGNORECASE
    ),
    re.compile(
        r'["\'`](/auth[A-Za-z0-9/_\-\.~!$&\'()*+,;=:@%{}:\[\]\?=#]*)["\'`]',
        re.IGNORECASE
    ),
    re.compile(
        r'["\'`](/login[A-Za-z0-9/_\-\.~!$&\'()*+,;=:@%{}:\[\]\?=#]*)["\'`]',
        re.IGNORECASE
    ),
    re.compile(
        r'["\'`](/logout[A-Za-z0-9/_\-\.~!$&\'()*+,;=:@%{}:\[\]\?=#]*)["\'`]',
        re.IGNORECASE
    ),
    re.compile(
        r'["\'`](/token[A-Za-z0-9/_\-\.~!$&\'()*+,;=:@%{}:\[\]\?=#]*)["\'`]',
        re.IGNORECASE
    ),

    re.compile(
        r'["\'`](/admin[A-Za-z0-9/_\-\.~!$&\'()*+,;=:@%{}:\[\]\?=#]*)["\'`]',
        re.IGNORECASE
    ),
    re.compile(
        r'["\'`](/dashboard[A-Za-z0-9/_\-\.~!$&\'()*+,;=:@%{}:\[\]\?=#]*)["\'`]',
        re.IGNORECASE
    ),
    re.compile(
        r'["\'`](/internal[A-Za-z0-9/_\-\.~!$&\'()*+,;=:@%{}:\[\]\?=#]*)["\'`]',
        re.IGNORECASE
    ),
    re.compile(
        r'["\'`](/debug[A-Za-z0-9/_\-\.~!$&\'()*+,;=:@%{}:\[\]\?=#]*)["\'`]',
        re.IGNORECASE
    ),
    re.compile(
        r'["\'`](/config[A-Za-z0-9/_\-\.~!$&\'()*+,;=:@%{}:\[\]\?=#]*)["\'`]',
        re.IGNORECASE
    ),
    re.compile(
        r'["\'`](/backup[A-Za-z0-9/_\-\.~!$&\'()*+,;=:@%{}:\[\]\?=#]*)["\'`]',
        re.IGNORECASE
    ),
    re.compile(
        r'["\'`](/private[A-Za-z0-9/_\-\.~!$&\'()*+,;=:@%{}:\[\]\?=#]*)["\'`]',
        re.IGNORECASE
    ),
    re.compile(
        r'["\'`](/upload[A-Za-z0-9/_\-\.~!$&\'()*+,;=:@%{}:\[\]\?=#]*)["\'`]',
        re.IGNORECASE
    ),
    re.compile(
        r'["\'`](/download[A-Za-z0-9/_\-\.~!$&\'()*+,;=:@%{}:\[\]\?=#]*)["\'`]',
        re.IGNORECASE
    ),

    re.compile(
        r'["\'`](/\.well-known/[A-Za-z0-9/_\-\.~]+)["\'`]',
        re.IGNORECASE
    ),
    re.compile(
        r'["\'`](/idp/[A-Za-z0-9/_\-\.~]+)["\'`]',
        re.IGNORECASE
    ),

    re.compile(
        r'(?:(?:=|\(|,|\s|:))(/(?:api|admin|auth|internal|rest)(?:/v\d+)?/[A-Za-z0-9/_\-\.~!$&\'()*+,;=:@%{}:\[\]\?=#]+)',
        re.IGNORECASE
    ),

    re.compile(
        r'["\'`](/(?:api|admin|internal|auth|rest)/[A-Za-z0-9/_\-\.~]+)["\'`]\s*\+',
        re.IGNORECASE
    ),

    re.compile(
        r'(?:fetch|axios\.(?:get|post|put|delete|patch)|open)\s*\(\s*["\'`](/[^"\'`]+)["\'`]',
        re.IGNORECASE
    ),

    re.compile(
        r'["\'`]((?:\/\/|wss?:\/\/)[^\s"\'`<>]+?/api(?:/v\d+)?/[A-Za-z0-9/_\-\.~!$&\'()*+,;=:@%{}:\[\]\?=#]+)["\'`]',
        re.IGNORECASE
    ),
]


# URL patterns - full URLs
URL_PATTERNS = [
    re.compile(r'["\'](https?://[^\s"\'<>]{10,})["\']'),
    re.compile(r'["\'](wss?://[^\s"\'<>]{10,})["\']'),
    re.compile(r'["\'](sftp://[^\s"\'<>]{10,})["\']'),
    # Cloud storage
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.s3[a-zA-Z0-9.-]*\.amazonaws\.com[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.blob\.core\.windows\.net[^\s"\'<>]*)'),
    re.compile(r'(https?://storage\.googleapis\.com/[^\s"\'<>]*)'),
]

# Enhanced secret patterns - high coverage, context-aware where useful
SECRET_PATTERNS = [
    # AWS Access Key ID (classic)
    (re.compile(r'(AKIA[0-9A-Z]{16})'), "AWS Access Key ID"),

    # AWS Secret Access Key (context-aware: look for common keywords near the key)
    (re.compile(r'(?i)(?:aws_secret_access_key|aws_secret|secret_access_key|aws_secret_key|aws_key|aws.secret).{0,80}([A-Za-z0-9/+=]{40})', re.IGNORECASE | re.DOTALL), "AWS Secret Access Key (context)"),

    # AWS session token prefix (temporary credentials)
    (re.compile(r'(ASIA[0-9A-Z]{16})'), "AWS Session Token (ASIA)"),

    # Google API key (public-ish key)
    (re.compile(r'(AIza[0-9A-Za-z\-_]{35})'), "Google API Key (AIza...)"),

    # GCP service account private key presence (JSON style)
    (re.compile(r'\"private_key\"\s*:\s*\"-----BEGIN (?:RSA )?PRIVATE KEY-----', re.IGNORECASE), "GCP Service Account Private Key (JSON)"),

    # Google OAuth tokens / Access tokens (ya29.)
    (re.compile(r'\b(ya29\.[A-Za-z0-9\-_]{20,})\b'), "Google OAuth2 Access Token (ya29.)"),

    # Firebase Server Key (legacy) and Android/iOS keys (context-aware)
    (re.compile(r'(?i)(?:firebase|server_key|fcm).{0,40}([A-Za-z0-9:\-_]{20,200})', re.IGNORECASE | re.DOTALL), "Firebase / FCM Key (context)"),

    # Stripe secret keys (live/test)
    (re.compile(r'\b(sk_live_[0-9a-zA-Z]{24,})\b'), "Stripe Secret Key (live)"),
    (re.compile(r'\b(sk_test_[0-9a-zA-Z]{24,})\b'), "Stripe Secret Key (test)"),

    # Stripe publishable keys (less sensitive but useful)
    (re.compile(r'\b(pk_live_[0-9a-zA-Z]{24,})\b'), "Stripe Publishable Key (live)"),
    (re.compile(r'\b(pk_test_[0-9a-zA-Z]{24,})\b'), "Stripe Publishable Key (test)"),

    # SendGrid API Key
    (re.compile(r'\b(SG\.[A-Za-z0-9_-]{16,})\b'), "SendGrid API Key (SG.)"),

    # Mailgun API key style
    (re.compile(r'\b(key-[0-9a-zA-Z]{32})\b'), "Mailgun API Key (key-)"),

    # GitHub tokens (modern prefixes)
    (re.compile(r'\b(ghp_[0-9A-Za-z]{36,}|gho_[0-9A-Za-z]{36,}|ghs_[0-9A-Za-z]{36,}|ghu_[0-9A-Za-z]{36,}|ghr_[0-9A-Za-z]{36,})\b'), "GitHub Token (ghp_/gho_/ghs_/ghu_/ghr_)"),

    # GitHub older style personal access token (40 hex) - only if context contains 'github' or 'ghp' nearby
    (re.compile(r'(?i)(?:github|ghp|personal[_\- ]token|github_token).{0,60}([0-9a-fA-F]{40})', re.IGNORECASE | re.DOTALL), "GitHub PAT (40hex, context)"),

    # GitHub Gist / OAuth patterns
    (re.compile(r'\b(gitlab-ci-token:[A-Za-z0-9\-_]{10,})\b', re.IGNORECASE), "GitLab CI Token (gitlab-ci-token:)"),

    # Slack tokens (covers xoxp, xoxb, xoxa, xoxr, xapp)
    (re.compile(r'\b(xox[pboa|r|a]?-[0-9A-Za-z\-]{10,64})\b'), "Slack Token (xox...)"),

    # Discord bot tokens (Bot token style)
    (re.compile(r'([A-Za-z0-9_-]{24}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27})'), "Discord Bot Token"),

    # JWT (rough pattern)
    (re.compile(r'(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+)'), "JWT"),

    # PGP / OpenSSL / RSA private key blocks (multi-line)
    (re.compile(r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----[\s\S]{20,}-----END (?:RSA |EC )?PRIVATE KEY-----'), "Private Key Block (PEM)"),

    # PGP private key block (-----BEGIN PGP PRIVATE KEY BLOCK-----)
    (re.compile(r'-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]{100,}-----END PGP PRIVATE KEY BLOCK-----'), "PGP Private Key Block"),

    # Generic PEM private key (context)
    (re.compile(r'(?i)private_key.{0,40}-----BEGIN (?:RSA |EC )?PRIVATE KEY-----', re.IGNORECASE | re.DOTALL), "Private Key (context)"),

    # MongoDB / MongoDB+SRV URIs with credentials
    (re.compile(r'(mongodb(?:\+srv)?://[^\s"\'<>]+)'), "MongoDB URI (with creds?)"),

    # Postgres / MySQL / Redis URIs with credentials
    (re.compile(r'(postgres(?:ql)?://[^\s"\'<>]+)'), "PostgreSQL URI"),
    (re.compile(r'(mysql:\/\/[a-z0-9._%+\-]+:[^\s:@]+@(?:\[[0-9a-f:.]+\]|[a-z0-9.-]+)(?::\d{2,5})?(?:\/[^\s"\'?:]+)?(?:\?[^\s"\']*)?)', re.IGNORECASE), "MySQL URI with Credentials"),
    (re.compile(r'(redis:\/\/(?:[^:\s@]+:[^@\s]+@)?[^\s"\'<>]+)'), "Redis URI (with creds)"),

    # Generic Basic Auth in URL (user:pass@host)
    (re.compile(r'([a-zA-Z0-9._%+\-]+:[^@\s]{6,}@(?:[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|localhost))'), "URL with Basic Auth (user:pass@host)"),

    # Heroku API key (HEROKU_API_KEY often 32 hex)
    (re.compile(r'(?i)(?:heroku|HEROKU_API_KEY).{0,40}([0-9a-f]{32})', re.IGNORECASE | re.DOTALL), "Heroku API Key (context)"),

    # Twilio Account SID and Auth Token (SID starts with AC, Auth Token hex)
    (re.compile(r'\b(AC[0-9a-fA-F]{32})\b'), "Twilio Account SID (AC...)"),
    (re.compile(r'(?i)(?:twilio).{0,40}([0-9a-fA-F]{32})', re.IGNORECASE | re.DOTALL), "Twilio Auth Token (context)"),

    # Firebase Web API key (AIza... covered) and Firebase config keys (context)
    (re.compile(r'(?i)firebase.{0,40}([A-Za-z0-9:_\-\.\$]{20,200})', re.IGNORECASE | re.DOTALL), "Firebase config key (context)"),

    # Cloudflare API tokens (context aware)
    (re.compile(r'(?i)(?:cloudflare|cfapi|CF_API_TOKEN|cloudflare_token).{0,40}([A-Za-z0-9_\-]{16,64})', re.IGNORECASE | re.DOTALL), "Cloudflare API Token (context)"),

    # Azure Storage Account Key (base64-like, context)
    (re.compile(r'(?i)(?:azure|storage|account_key|storage_access_key).{0,40}([A-Za-z0-9+/=]{40,120})', re.IGNORECASE | re.DOTALL), "Azure Storage Key (context, base64-like)"),

    # Generic high-entropy base64/hex tokens—but only if preceded by common keywords (to reduce false positives)
    (re.compile(r'(?i)(?:api[_\- ]?key|apikey|access[_\- ]?token|access[_\- ]?key|client[_\- ]?secret|client[_\- ]?id|secret[_\- ]?key|auth[_\- ]?token|bearer|credential|private[_\- ]?key).{0,80}([A-Za-z0-9+/=]{20,300})', re.IGNORECASE | re.DOTALL), "High-entropy token (context-aware)"),

    # Facebook tokens and app ids (various formats)
    (re.compile(r'(EAACEdEose0cBA[A-Z0-9]{20,})\b'), "Facebook Access Token"),
    (re.compile(r'(?i)(?:facebook|fb).{0,32}(?:api|app|application|client|consumer|secret|key).{0,32}([a-z0-9]{32})\b', re.IGNORECASE | re.DOTALL), "Facebook Secret Key (context)"),
    (re.compile(r'(?i)(?:facebook|fb).{0,8}(?:app|application).{0,16}(\d{15})\b', re.IGNORECASE | re.DOTALL), "Facebook App ID (context)"),

    # Segment / Analytics tokens
    (re.compile(r'\b(sgp_[A-Z0-9_-]{60,70})\b'), "Segment Public API Token"),
    (re.compile(r'(?i)(?:segment|sgmt).{0,16}(?:secret|private|access|key|token).{0,16}([A-Z0-9_-]{40,50}\.[A-Z0-9_-]{40,50})', re.IGNORECASE | re.DOTALL), "Segment API Key (context)"),

    # Generic OAuth Bearer tokens (Bearer <token>) - capture token part
    (re.compile(r'(?i)bearer\s+([A-Za-z0-9\-_\.]{20,300})', re.IGNORECASE), "Bearer Token (Authorization header)"),
]


# Email pattern
EMAIL_PATTERN = re.compile(r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6})')

# File patterns - Pro
FILE_PATTERNS = re.compile(
    r'(?:["\'`]|^)'  # optional quote or line start
    r'('
    r'(?:[A-Za-z0-9_\-./%\\]+?\.(?:'
    r'sql|db|sqlite3?|bak|backup|old|orig|copy|'
    r'csv|tsv|xlsx|xls|ods|odt|json|ndjson|ndj|xml|'
    r'yaml|yml|toml|props|properties|env|ini|conf|config|cfg|credentials|secrets|passwd|htpasswd|git-credentials|'
    r'pem|key|crt|cer|p12|pfx|jks|keystore|asc|gpg|pub|ovpn|ovpn\.conf|pem\.enc|pem\.bak|'
    r'db|db3|sql\.gz|sql\.zip|log|txt|rtf|md|'
    r'zip|tar|tgz|tar\.gz|gz|bz2|rar|7z|cab|war|jar|ear|apk|ipa|'
    r'doc|docx|pdf|ppt|pptx|xlsm|xlsb|msg|pst|'
    r'sh|bash|zsh|bat|cmd|ps1|py|php|rb|pl|go|java|class)'
    r')'
    r'(?:\?[^\s"\'`<>]*)?(?:#[^\s"\'`<>]*)?'
    r')'
    r'(?:["\'`]|$)',
    re.IGNORECASE
)



# ==================== NOISE FILTERS ====================
# Extensive list of patterns to EXCLUDE

# Domains to exclude from URLs (XML namespaces, standards, etc.)
NOISE_DOMAINS = {
    'www.w3.org', 'schemas.openxmlformats.org', 'schemas.microsoft.com',
    'purl.org', 'purl.oclc.org', 'openoffice.org', 'docs.oasis-open.org',
    'sheetjs.openxmlformats.org', 'ns.adobe.com', 'www.xml.org',
    'example.com', 'test.com', 'localhost', '127.0.0.1',
    'fusioncharts.com', 'jspdf.default.namespaceuri',
    'npmjs.org', 'registry.npmjs.org',
    'github.com/indutny', 'github.com/crypto-browserify',
    'jqwidgets.com', 'ag-grid.com',
}

# Path prefixes that indicate module imports (NOT real endpoints)
MODULE_PREFIXES = (
    './', '../', '.../', 
    './lib', '../lib', './utils', '../utils',
    './node_modules', '../node_modules',
    './src', '../src', './dist', '../dist',
)

# Patterns that are clearly internal JS/build artifacts
NOISE_PATTERNS = [
    # Module/library imports
    re.compile(r'^\.\.?/'),  # Starts with ./ or ../
    re.compile(r'^[a-z]{2}(-[a-z]{2})?\.js$'),  # Locale files: en.js, en-gb.js
    re.compile(r'^[a-z]{2}(-[a-z]{2})?$'),  # Just locale: en, en-gb
    re.compile(r'-xform$'),  # Excel xform modules
    re.compile(r'^sha\d*$'),  # sha, sha1, sha256
    re.compile(r'^aes$|^des$|^md5$'),  # Crypto modules
    
    # PDF internal structure
    re.compile(r'^/[A-Z][a-z]+\s'),  # /Type /Font, /Filter /Standard
    re.compile(r'^/[A-Z][a-z]+$'),  # /Parent, /Kids, /Resources
    re.compile(r'^\d+ \d+ R$'),  # PDF object references
    
    # Excel/XML internal paths
    re.compile(r'^xl/'),  # Excel internal
    re.compile(r'^docProps/'),  # Document properties
    re.compile(r'^_rels/'),  # Relationships
    re.compile(r'^META-INF/'),  # Manifest
    re.compile(r'\.xml$'),  # XML files
    re.compile(r'^worksheets/'),
    re.compile(r'^theme/'),
    
    # Build/bundler artifacts
    re.compile(r'^webpack'),
    re.compile(r'^zone\.js$'),
    re.compile(r'^readable-stream/'),
    re.compile(r'^process/'),
    re.compile(r'^stream/'),
    re.compile(r'^buffer$'),
    re.compile(r'^events$'),
    re.compile(r'^util$'),
    re.compile(r'^path$'),
    
    # Generic noise
    re.compile(r'^\+'),  # Starts with +
    re.compile(r'^\$\{'),  # Template literal
    re.compile(r'^#'),  # Fragment only
    re.compile(r'^\?\ref='),
    re.compile(r'^/[a-z]$'),  # Single letter paths
    re.compile(r'^/[A-Z]$'),  # Single letter paths
    re.compile(r'^http://$'),  # Empty http://
    re.compile(r'_ngcontent'),  # Angular internals
]

# Specific strings to exclude
NOISE_STRINGS = {
    'http://', 'https://', '/a', '/P', '/R', '/V', '/W',
    'zone.js', 'bn.js', 'hash.js', 'md5.js', 'sha.js', 'des.js',
    'asn1.js', 'declare.js', 'elliptic.js',
}


class BurpExtender(IBurpExtender, IContextMenuFactory, ITab):
    """JS Analyzer with noise-reduced endpoint detection."""
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        callbacks.setExtensionName("JS Analyzer")
        
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)
        
        # Results storage
        self.all_findings = []
        self.seen_values = set()
        
        # Initialize UI
        self.panel = ResultsPanel(callbacks, self)
        
        callbacks.registerContextMenuFactory(self)
        callbacks.addSuiteTab(self)
        
        self._log("JS Analyzer loaded - Right-click JS responses to analyze")
    
    def _log(self, msg):
        self._stdout.println("[JS Analyzer] " + str(msg))
    
    def getTabCaption(self):
        return "JS Analyzer"
    
    def getUiComponent(self):
        return self.panel
    
    def createMenuItems(self, invocation):
        menu = ArrayList()
        try:
            messages = invocation.getSelectedMessages()
            if messages and len(messages) > 0:
                item = JMenuItem("Analyze JS with JS Analyzer")
                item.addActionListener(AnalyzeAction(self, invocation))
                menu.add(item)
        except Exception as e:
            self._log("Menu error: " + str(e))
        return menu
    
    def analyze_response(self, message_info):
        """Analyze a response."""
        response = message_info.getResponse()
        if not response:
            return
        
        # Get source URL
        try:
            req_info = self._helpers.analyzeRequest(message_info)
            url = str(req_info.getUrl())
            source_name = url.split('/')[-1].split('?')[0] if '/' in url else url
            if len(source_name) > 40:
                source_name = source_name[:40] + "..."
        except:
            url = "Unknown"
            source_name = "Unknown"
        
        # Get response body
        resp_info = self._helpers.analyzeResponse(response)
        body_offset = resp_info.getBodyOffset()
        body = self._helpers.bytesToString(response[body_offset:])
        
        if len(body) < 50:
            return
        
        self._log("Analyzing: " + source_name)
        
        new_findings = []
        
        # 1. Extract endpoints
        for pattern in ENDPOINT_PATTERNS:
            for match in pattern.finditer(body):
                value = match.group(1).strip()
                if self._is_valid_endpoint(value):
                    finding = self._add_finding("endpoints", value, source_name)
                    if finding:
                        new_findings.append(finding)
        
        # 2. URLs
        for pattern in URL_PATTERNS:
            for match in pattern.finditer(body):
                value = match.group(1).strip() if match.lastindex else match.group(0).strip()
                if self._is_valid_url(value):
                    finding = self._add_finding("urls", value, source_name)
                    if finding:
                        new_findings.append(finding)
        
        # 3. Secrets
        for pattern, _ in SECRET_PATTERNS:
            for match in pattern.finditer(body):
                value = match.group(1).strip()
                if self._is_valid_secret(value):
                    masked = value[:10] + "..." + value[-4:] if len(value) > 20 else value
                    finding = self._add_finding("secrets", masked, source_name)
                    if finding:
                        new_findings.append(finding)
        
        # 4. Emails
        for match in EMAIL_PATTERN.finditer(body):
            value = match.group(1).strip()
            if self._is_valid_email(value):
                finding = self._add_finding("emails", value, source_name)
                if finding:
                    new_findings.append(finding)
        
        # 5. Files (sensitive file references)
        for match in FILE_PATTERNS.finditer(body):
            value = match.group(1).strip()
            if self._is_valid_file(value):
                finding = self._add_finding("files", value, source_name)
                if finding:
                    new_findings.append(finding)
        
        # Update UI
        if new_findings:
            self._log("Found %d new items" % len(new_findings))
            self.panel.add_findings(new_findings, source_name)
        else:
            self._log("No new findings")
    
    def _add_finding(self, category, value, source):
        """Add a finding if not duplicate."""
        key = category + ":" + value
        if key in self.seen_values:
            return None
        
        self.seen_values.add(key)
        finding = {
            "category": category,
            "value": value,
            "source": source,
        }
        self.all_findings.append(finding)
        return finding
    
    def _is_valid_endpoint(self, value):
        """Strict endpoint validation - reject noise."""
        if not value or len(value) < 3:
            return False
        
        # Check exact matches first
        if value in NOISE_STRINGS:
            return False
        
        # Check noise patterns
        for pattern in NOISE_PATTERNS:
            if pattern.search(value):
                return False
        
        # Must start with / and have some path
        if not value.startswith('/'):
            return False
        
        # Skip if just a single segment with no meaning
        parts = value.split('/')
        if len(parts) < 2 or all(len(p) < 2 for p in parts if p):
            return False
        
        return True
    
    def _is_valid_url(self, value):
        """Strict URL validation."""
        if not value or len(value) < 15:
            return False
        
        val_lower = value.lower()
        
        # Check for noise domains
        for domain in NOISE_DOMAINS:
            if domain in val_lower:
                return False
        
        # Skip if contains placeholder patterns
        if '{' in value or 'undefined' in val_lower or 'null' in val_lower:
            return False
        
        # Skip data URIs
        if val_lower.startswith('data:'):
            return False
        
        # Skip if ends with common static extensions
        if any(val_lower.endswith(ext) for ext in ['.css', '.png', '.jpg', '.gif', '.svg', '.woff', '.ttf']):
            return False
        
        return True
    
    def _is_valid_secret(self, value):
        """Validate secrets."""
        if not value or len(value) < 10:
            return False
        
        val_lower = value.lower()
        if any(x in val_lower for x in ['example', 'placeholder', 'your', 'xxxx', 'test']):
            return False
        
        return True
    
    def _is_valid_email(self, value):
        """Validate emails."""
        if not value or '@' not in value:
            return False
        
        val_lower = value.lower()
        domain = value.split('@')[-1].lower()
        
        if domain in {'example.com', 'test.com', 'domain.com', 'placeholder.com'}:
            return False
        
        if any(x in val_lower for x in ['example', 'test', 'placeholder', 'noreply']):
            return False
        
        return True
    
    def _is_valid_file(self, value):
        """Validate file references."""
        if not value or len(value) < 3:
            return False
        
        val_lower = value.lower()
        
        # Skip common JS/build files
        if any(x in val_lower for x in [
            'package.json', 'tsconfig.json', 'webpack', 'babel',
            'eslint', 'prettier', 'node_modules', '.min.',
            'polyfill', 'vendor', 'chunk', 'bundle'
        ]):
            return False
        
        # Skip source maps
        if val_lower.endswith('.map'):
            return False
        
        # Skip common locale/language files
        if val_lower.endswith('.json') and len(value.split('/')[-1]) <= 7:
            return False
        
        return True
    
    def clear_results(self):
        self.all_findings = []
        self.seen_values = set()
    
    def get_all_findings(self):
        return self.all_findings


class AnalyzeAction(ActionListener):
    def __init__(self, extender, invocation):
        self.extender = extender
        self.invocation = invocation
    
    def actionPerformed(self, event):
        messages = self.invocation.getSelectedMessages()
        for msg in messages:
            self.extender.analyze_response(msg)
