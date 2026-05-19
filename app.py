from flask import Flask, render_template, request
from parser import parse_raw_email
from engine import evaluate_spf, verify_dkim_signature, get_dns_record, evaluate_alignment

app = Flask(__name__)

# Sample raw email template to pre-populate the text area on first load
DEMO_EMAIL_TEMPLATE = """Return-Path: <bounce@example.com>
Received: from mail.example.com ([203.0.113.10])
        by mx.google.com with ESMTPS id x123si;
        Tue, 28 Mar 2026 14:30:11 -0700
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=example.com; s=s1;
        h=from:to:subject;
        b=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv1N3ZcZ...
From: Omena Austen <sender@example.com>
To: recipient@lcu.edu.ng
Subject: BSc Thesis Demo Authentication System

This is a demonstration raw email payload representing healthy validation.
"""

@app.route('/', methods=['GET', 'POST'])
def index():
    raw_email_input = DEMO_EMAIL_TEMPLATE
    results = None
    use_live_dns = False

    if request.method == 'POST':
        raw_email_input = request.form.get('raw_email', '')
        use_live_dns = 'use_live_dns' in request.form
        
        # 1. Parse Raw Headers
        parsed_data = parse_raw_email(raw_email_input)
        
        # 2. Evaluate SPF
        spf_data = evaluate_spf(parsed_data["connecting_ip"], parsed_data["spf_domain"], use_live_dns)
        
        # 3. Evaluate DKIM
        dkim_data = verify_dkim_signature(parsed_data["dkim_tags"], use_live_dns)
        
        # 4. Process DMARC Record & Alignment
        from_domain = parsed_data["from_domain"]
        dmarc_record, dmarc_log = get_dns_record(f"_dmarc.{from_domain}", "TXT", use_live_dns)
        
        # Extract DMARC tags
        dmarc_policy = "none" # Default fallback
        aspf_mode = "r"
        adkim_mode = "r"
        
        if dmarc_record:
            tags = {}
            for param in dmarc_record.split(';'):
                if '=' in param:
                    k, v = param.split('=', 1)
                    tags[k.strip().lower()] = v.strip().lower()
            dmarc_policy = tags.get('p', 'none')
            aspf_mode = tags.get('aspf', 'r')
            adkim_mode = tags.get('adkim', 'r')

        # Evaluate Alignment rules
        spf_aligned = evaluate_alignment(from_domain, parsed_data["spf_domain"], aspf_mode)
        dkim_aligned = evaluate_alignment(from_domain, parsed_data["dkim_tags"].get('d', ''), adkim_mode)
        
        # Core alignment decision rule (From Chapter 3 formulas)
        spf_pass = (spf_data["result"] == "Pass")
        dkim_pass = dkim_data["result"]
        
        dmarc_pass = (spf_pass and spf_aligned) or (dkim_pass and dkim_aligned)
        
        # Choose action disposition
        final_disposition = "Deliver Normally"
        if not dmarc_pass:
            if dmarc_policy == "reject":
                final_disposition = "Rejected (Blocked by DMARC Policy)"
            elif dmarc_policy == "quarantine":
                final_disposition = "Quarantine (Spam Folder Enforced)"
            else:
                final_disposition = "Deliver Normally (DMARC Audit 'none' Monitoring Mode)"

        results = {
            "parsed": parsed_data,
            "spf": spf_data,
            "dkim": dkim_data,
            "dmarc": {
                "record": dmarc_record or "No DMARC Record Found",
                "policy": dmarc_policy,
                "aspf": aspf_mode,
                "adkim": adkim_mode,
                "spf_aligned": spf_aligned,
                "dkim_aligned": dkim_aligned,
                "passed": dmarc_pass,
                "disposition": final_disposition,
                "log": dmarc_log
            }
        }

    return render_template('index.html', raw_email=raw_email_input, results=results, use_live_dns=use_live_dns)

if __name__ == '__main__':
    app.run(debug=True, port=5050)