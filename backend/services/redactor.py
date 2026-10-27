import re
from typing import Any

# Regex untuk token rahasia
SECRET_PATTERNS = [
    # OpenAI key
    (re.compile(r'(sk-[a-zA-Z0-9_\-]{6})([a-zA-Z0-9_\-]+)([a-zA-Z0-9_\-]{4})'), r'\1' + '*' * 20 + r'\3'),
    # GitHub personal access token
    (re.compile(r'(ghp_[a-zA-Z0-9]{4})([a-zA-Z0-9]{28})([a-zA-Z0-9]{4})'), r'\1' + '*' * 28 + r'\3'),
    # AWS Access Key ID
    (re.compile(r'(AKIA[0-9A-Z]{4})([0-9A-Z]{8})([0-9A-Z]{4})'), r'\1' + '*' * 8 + r'\3'),
    # Generic bearer / auth token
    (re.compile(r'(Bearer\s+[a-zA-Z0-9_\-\.]{6})([a-zA-Z0-9_\-\.]+)([a-zA-Z0-9_\-\.]{4})'), r'\1' + '*' * 16 + r'\3'),
]

# Regex untuk email
EMAIL_PATTERN = re.compile(r'([a-zA-Z0-9_.+-]{1,2})([a-zA-Z0-9_.+-]+)@([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)')

def redact_secret(text: str) -> str:
    """
    Menyamarkan token rahasia (API key, bearer token, AWS key) menjadi pola bintang.
    """
    if not text:
        return text

    redacted = text
    for pattern, replacement in SECRET_PATTERNS:
        redacted = pattern.sub(replacement, redacted)

    # Fallback jika ada sk-proj yang panjang
    if "sk-proj-" in redacted and not "********************" in redacted:
        redacted = re.sub(r'(sk-proj-[a-zA-Z0-9_\-]{4})([a-zA-Z0-9_\-]+)([a-zA-Z0-9_\-]{4})', r'\1' + '*' * 20 + r'\3', redacted)

    return redacted

# Alias untuk kemudahan pemanggilan modul
redact_token = redact_secret

def redact_email(text: str) -> str:
    """
    Menyamarkan alamat email menjadi format de***@domain.id.
    """
    if not text:
        return text

    def _replace_email(match):
        prefix = match.group(1)
        domain = match.group(3)
        return f"{prefix}***@{domain}"

    return EMAIL_PATTERN.sub(_replace_email, text)

def auto_redact_all(text: str) -> str:
    """
    Menjalankan sanitasi penuh (secret + email) pada string.
    """
    if not isinstance(text, str):
        return text
    return redact_email(redact_secret(text))

def sanitize_dict_or_list(obj: Any) -> Any:
    """
    Rekursif melakukan auto-redaction pada nested dictionary atau list sebelum persistensi.
    """
    if isinstance(obj, str):
        return auto_redact_all(obj)
    elif isinstance(obj, dict):
        return {k: sanitize_dict_or_list(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [sanitize_dict_or_list(item) for item in obj]
    return obj
