import email
from email import policy
import re

def parse_raw_email(raw_email_str: str):
    """
    Parses raw email text and extracts fields required for SPF, DKIM, and DMARC.
    """
    # Parse email using standard Python library with strict policy
    msg = email.message_from_string(raw_email_str, policy=policy.default)
    
    # 1. Extract RFC5322 From header
    from_header = msg.get('From', '')
    from_domain = ""
    if from_header:
        # Match email addresses within <...> or raw strings
        email_match = re.search(r'[\w\.-]+@([\w\.-]+\.\w+)', from_header)
        if email_match:
            from_domain = email_match.group(1).lower()

    # 2. Extract Return-Path (Envelope Sender) for SPF
    return_path = msg.get('Return-Path', '')
    spf_domain = ""
    if return_path:
        email_match = re.search(r'[\w\.-]+@([\w\.-]+\.\w+)', return_path)
        if email_match:
            spf_domain = email_match.group(1).lower()
    else:
        # Fallback to from_domain if Return-Path is missing
        spf_domain = from_domain

    # 3. Extract Connecting IP (Look at the latest Received header)
    received_headers = msg.get_all('Received', [])
    connecting_ip = "127.0.0.1" # Default fallback
    if received_headers:
        # Regex to find IPv4 addresses
        ip_matches = re.findall(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', received_headers[0])
        if ip_matches:
            connecting_ip = ip_matches[0]

    # 4. Extract and parse DKIM-Signature header
    dkim_header = msg.get('DKIM-Signature', '')
    dkim_tags = {}
    if dkim_header:
        # Standard DKIM signature parser: semicolon separated tag=value pairs
        clean_dkim = "".join(dkim_header.splitlines()).replace(" ", "")
        parts = clean_dkim.split(';')
        for part in parts:
            if '=' in part:
                tag, val = part.split('=', 1)
                dkim_tags[tag.strip()] = val.strip()

    return {
        "spf_domain": spf_domain,
        "from_domain": from_domain,
        "connecting_ip": connecting_ip,
        "dkim_tags": dkim_tags,
        "headers": dict(msg.items())
    }