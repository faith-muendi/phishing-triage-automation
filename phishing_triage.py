#!/usr/bin/env python3
import os, re, csv, sys, base64, hashlib
from email import policy
from email.parser import BytesParser
from html import unescape

# --- Configuration ---
SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".click", ".support", ".monster", ".shop",
    ".live", ".rest", ".buzz", ".gq", ".tk", ".ml", ".cf", ".ga"
}
URGENT_WORDS = r"(urgent|suspend|verify|invoice|unpaid|account.*locked|password.*reset|pay now|immediately)"
URL_REGEX = re.compile(r'(?i)\b((?:https?://|www\.)[^\s<>"\)\]]+)')
B64_HINT = re.compile(r'(?i)frombase64string|encodedcommand|base64')


# --- Helpers ---
def strip_html(html):
    """Convert HTML to plain text (basic cleanup)."""
    text = re.sub(r'(?is)<(script|style).*?>.*?</\1>', '', html)
    text = re.sub(r'(?is)<br\s*/?>', '\n', text)
    text = re.sub(r'(?is)<[^>]+>', ' ', text)
    text = unescape(text)
    return re.sub(r'\s+', ' ', text).strip()


def extract_text_and_urls(msg):
    """Extract visible text and URLs from email message."""
    texts, urls = [], []
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            payload = part.get_payload(decode=True) or b""
            try:
                text = payload.decode(part.get_content_charset() or 'utf-8', errors='ignore')
            except:
                text = payload.decode('utf-8', errors='ignore')
            if ctype == 'text/html':
                texts.append(strip_html(text))
                urls.extend(URL_REGEX.findall(text))
            elif ctype == 'text/plain':
                texts.append(text)
                urls.extend(URL_REGEX.findall(text))
    else:
        payload = msg.get_payload(decode=True) or b""
        text = payload.decode(msg.get_content_charset() or 'utf-8', errors='ignore')
        if msg.get_content_type() == 'text/html':
            texts.append(strip_html(text))
        else:
            texts.append(text)
        urls.extend(URL_REGEX.findall(text))
    urls = [u.strip().rstrip(').,;]>"') for u in urls]
    return " ".join(texts), sorted(set(urls))


def domain_from_email(addr):
    if not addr:
        return ""
    m = re.search(r'@([A-Za-z0-9\.\-\_]+)', addr)
    return m.group(1).lower() if m else ""


def effective_tld(domain):
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            return tld
    return ""


# --- Core Scoring Function ---
def score_email(from_addr, reply_to, subject, body, urls):
    score = 0
    notes = []
    fdom = domain_from_email(from_addr)
    rdom = domain_from_email(reply_to)

    if reply_to and rdom and fdom and rdom != fdom:
        score += 2
        notes.append(f"Reply-To domain differs from From ({rdom} vs {fdom})")

    if any(effective_tld(u.split('/')[2].lower()) for u in urls if '://' in u):
        score += 2
        notes.append("URLs include suspicious TLDs")

    if re.search(URGENT_WORDS, (subject or "") + " " + (body or ""), re.I):
        score += 1
        notes.append("Urgent/pressure language")

    if B64_HINT.search((body or "")):
        score += 1
        notes.append("Base64/obfuscation hints in message")

    if re.search(r'(micros0ft|paypa1|faceb00k|app1e)', (from_addr or ""), re.I):
        score += 1
        notes.append("Lookalike brand in sender")

    if urls and not any("company.local" in u for u in urls):
        score += 1
        notes.append("External URLs present")

    risk = "Benign"
    if score >= 4:
        risk = "High"
    elif score >= 2:
        risk = "Medium"

    return score, risk, notes


# --- Save reports ---
def save_reports(rows, urls_rows, att_rows, outdir):
    os.makedirs(outdir, exist_ok=True)
    with open(os.path.join(outdir, "emails_summary.csv"), "w", newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    if urls_rows:
        with open(os.path.join(outdir, "urls.csv"), "w", newline='', encoding='utf-8') as f:
            w = csv.DictWriter(f, fieldnames=list(urls_rows[0].keys()))
            w.writeheader()
            w.writerows(urls_rows)

    if att_rows:
        with open(os.path.join(outdir, "attachments.csv"), "w", newline='', encoding='utf-8') as f:
            w = csv.DictWriter(f, fieldnames=list(att_rows[0].keys()))
            w.writeheader()
            w.writerows(att_rows)


def write_per_email_markdown(outdir, rec):
    md_dir = os.path.join(outdir, "reports")
    os.makedirs(md_dir, exist_ok=True)
    safe_name = (rec['MessageID'] or rec['Subject'] or rec['File']).replace('/', '_')
    fname = os.path.join(md_dir, f"{safe_name}.md")

    with open(fname, "w", encoding="utf-8") as f:
        f.write(f"# Email Report\n\n")
        f.write(f"**File:** {rec['File']}\n\n")
        f.write(f"**From:** {rec['From']}\n\n")
        f.write(f"**Reply-To:** {rec['ReplyTo']}\n\n")
        f.write(f"**Subject:** {rec['Subject']}\n\n")
        f.write(f"**Date:** {rec['Date']}\n\n")
        f.write(f"**MessageID:** {rec['MessageID']}\n\n")
        f.write(f"**Risk:** {rec['Risk']} (score: {rec['Score']})\n\n")
        f.write(f"**Notes:** {rec['Notes']}\n\n")
        f.write(f"**URL count:** {rec['URLCount']}\n\n")
        f.write(f"**Attachment count:** {rec['AttachmentCount']}\n\n")


# --- Main logic ---
def main():
    import argparse
    ap = argparse.ArgumentParser(description="Phishing Triage Automation Tool")
    ap.add_argument("path", help="Folder containing .eml files")
    ap.add_argument("-o", "--out", default="outputs", help="Output folder")
    args = ap.parse_args()

    rows, urls_rows, att_rows = [], [], []
    email_files = [os.path.join(root, fn)
                   for root, _, files in os.walk(args.path)
                   for fn in files if fn.lower().endswith(".eml")]

    if not email_files:
        print("❌ No .eml files found.")
        sys.exit(0)

    print(f"🔍 Analyzing {len(email_files)} email(s)...\n")

    for idx, p in enumerate(email_files, 1):
        print(f"[{idx}/{len(email_files)}] Processing {os.path.basename(p)}...")
        with open(p, "rb") as f:
            msg = BytesParser(policy=policy.default).parse(f)

        from_addr = str(msg.get("From") or "")
        reply_to  = str(msg.get("Reply-To") or "")
        subject   = str(msg.get("Subject") or "")
        date      = str(msg.get("Date") or "")
        msgid     = str(msg.get("Message-ID") or "")

        body_text, urls = extract_text_and_urls(msg)

        attachments = []
        for part in msg.walk():
            if part.get_content_disposition() == 'attachment':
                att_name = part.get_filename() or "attachment"
                data = part.get_payload(decode=True) or b""
                sha256 = hashlib.sha256(data).hexdigest() if data else ""
                attachments.append({
                    "name": att_name,
                    "type": part.get_content_type(),
                    "sha256": sha256
                })

        score, risk, notes = score_email(from_addr, reply_to, subject, body_text, urls)

        rec = {
            "File": os.path.relpath(p),
            "From": from_addr,
            "ReplyTo": reply_to,
            "Subject": subject,
            "Date": date,
            "MessageID": msgid,
            "Score": score,
            "Risk": risk,
            "Notes": "; ".join(notes),
            "URLCount": len(urls),
            "AttachmentCount": len(attachments)
        }

        rows.append(rec)
        for u in urls:
            urls_rows.append({"File": rec["File"], "URL": u})
        for a in attachments:
            att_rows.append({
                "File": rec["File"],
                "AttachmentName": a["name"],
                "MimeType": a["type"],
                "SHA256": a["sha256"]
            })

        write_per_email_markdown(args.out, rec)

    save_reports(rows, urls_rows, att_rows, args.out)
    print(f"\n✅ Wrote {len(rows)} email records to {os.path.join(args.out, 'emails_summary.csv')}")
    print(f"📄 URLs: {len(urls_rows)} | Attachments: {len(att_rows)}")
    print(f"📁 Per-email markdown reports in {os.path.join(args.out, 'reports')}/")


if __name__ == "__main__":
    main()
