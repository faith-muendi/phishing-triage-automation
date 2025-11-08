#!/usr/bin/env python3
import os, re, csv, hashlib
from email import policy
from email.parser import BytesParser
from html import unescape

SUSPICIOUS_TLDS = {
    ".xyz",".top",".click",".support",".monster",".shop",".live",
    ".rest",".buzz",".gq",".tk",".ml",".cf",".ga"
}
URGENT_WORDS = r"(urgent|suspend|verify|invoice|unpaid|account.*locked|password.*reset|pay now|immediately)"
URL_REGEX = re.compile(r'(?i)\b((?:https?://|www\.)[^\s<>"\)\]]+)')
B64_HINT = re.compile(r'(?i)frombase64string|encodedcommand|base64')

def strip_html(html):
    text = re.sub(r'(?is)<(script|style).*?>.*?</\1>', '', html)
    text = re.sub(r'(?is)<br\s*/?>', '\n', html)
    text = re.sub(r'(?is)<[^>]+>', ' ', html)
    return re.sub(r'\s+', ' ', unescape(text)).strip()

def extract_text_and_urls(msg):
    texts, urls = [], []
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            payload = part.get_payload(decode=True) or b""
            text = payload.decode(part.get_content_charset() or 'utf-8', errors='ignore')
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
    m = re.search(r'@([A-Za-z0-9\.\-\_]+)', addr or "")
    return m.group(1).lower() if m else ""

def effective_tld(domain):
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            return tld
    return ""

def score_email(from_addr, reply_to, subject, body, urls):
    score, notes = 0, []
    fdom, rdom = domain_from_email(from_addr), domain_from_email(reply_to)

    if reply_to and rdom and fdom and rdom != fdom:
        score += 2; notes.append(f"Reply-To domain differs ({rdom} vs {fdom})")
    if any(effective_tld(u.split('/')[2].lower()) for u in urls if '://' in u):
        score += 2; notes.append("URLs use suspicious TLDs")
    if re.search(URGENT_WORDS, f"{subject} {body}", re.I):
        score += 1; notes.append("Urgent or pressure wording")
    if B64_HINT.search(body or ""):
        score += 1; notes.append("Base64/obfuscation hints")
    if re.search(r'(micros0ft|paypa1|faceb00k|app1e)', from_addr or "", re.I):
        score += 1; notes.append("Lookalike brand sender")
    if len(urls) > 0:
        score += 1; notes.append("External URLs present")

    risk = "High" if score >= 4 else "Medium" if score >= 2 else "Benign"
    return score, risk, notes

def write_markdown_report(outdir, rec):
    md_dir = os.path.join(outdir, "reports")
    os.makedirs(md_dir, exist_ok=True)
    safe_name = (rec['Subject'] or rec['File']).replace('/', '_').replace(' ', '_')
    with open(os.path.join(md_dir, f"{safe_name}.md"), "w", encoding="utf-8") as f:
        f.write(f"# Email Report\n\n")
        for k, v in rec.items():
            f.write(f"**{k}:** {v}\n\n")

def main():
    import argparse
    ap = argparse.ArgumentParser(description="Phishing Triage Automation")
    ap.add_argument("path", help="Folder with .eml files")
    ap.add_argument("-o", "--out", default="outputs", help="Output folder")
    args = ap.parse_args()

    rows, urls_rows, att_rows = [], [], []
    for root, _, files in os.walk(args.path):
        for fn in files:
            if not fn.lower().endswith(".eml"): continue
            path = os.path.join(root, fn)
            with open(path, "rb") as fh:
                msg = BytesParser(policy=policy.default).parse(fh)
            from_addr, reply_to = str(msg.get("From","")), str(msg.get("Reply-To",""))
            subject, date, msgid = str(msg.get("Subject","")), str(msg.get("Date","")), str(msg.get("Message-ID",""))
            body, urls = extract_text_and_urls(msg)
            attachments = []

            for part in msg.walk():
                if part.get_content_disposition() == 'attachment':
                    name = part.get_filename() or "attachment"
                    data = part.get_payload(decode=True) or b""
                    attachments.append({
                        "name": name, "type": part.get_content_type(),
                        "sha256": hashlib.sha256(data).hexdigest() if data else ""
                    })

            score, risk, notes = score_email(from_addr, reply_to, subject, body, urls)
            rec = {
                "File": fn, "From": from_addr, "ReplyTo": reply_to, "Subject": subject,
                "Date": date, "MessageID": msgid, "Score": score, "Risk": risk,
                "Notes": "; ".join(notes), "URLCount": len(urls), "AttachmentCount": len(attachments)
            }
            rows.append(rec)
            for u in urls: urls_rows.append({"File": fn, "URL": u})
            for a in attachments: att_rows.append({
                "File": fn, "AttachmentName": a["name"],
                "MimeType": a["type"], "SHA256": a["sha256"]
            })
            write_markdown_report(args.out, rec)

    os.makedirs(args.out, exist_ok=True)
    if rows:
        with open(os.path.join(args.out, "emails_summary.csv"), "w", newline='', encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=rows[0].keys())
            w.writeheader(); w.writerows(rows)
    if urls_rows:
        with open(os.path.join(args.out, "urls.csv"), "w", newline='', encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=urls_rows[0].keys())
            w.writeheader(); w.writerows(urls_rows)
    if att_rows:
        with open(os.path.join(args.out, "attachments.csv"), "w", newline='', encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=att_rows[0].keys())
            w.writeheader(); w.writerows(att_rows)

if __name__ == "__main__":
    main()
