import re
import logging
from email import policy
from email.parser import BytesParser
from email.utils import parsedate_to_datetime
from datetime import datetime, UTC
from urllib.parse import urlparse

import tldextract
from bs4 import BeautifulSoup

try:
    import whois  # type: ignore
except ImportError:
    whois = None

# Setup logging
logger = logging.getLogger(__name__)

# Regex patterns
URL_REGEX = re.compile(r"https?://[\w\-._~:/%?#\[\]@!$&'()*+,;=]+", re.I)
EMAIL_ADDR_REGEX = re.compile(r"([\w.+\-]+)@([\w\-.]+)")

SAFE_TLDS = {"com", "org", "net", "edu", "gov", "gh"}
BRAND_KEYWORDS = {"microsoft", "apple", "google", "amazon", "facebook", "whatsapp", "bank", "paypal"}


def parse_eml_bytes(data: bytes) -> dict:
    msg = BytesParser(policy=policy.default).parsebytes(data)
    subject = msg.get('subject', '') or ''
    from_addr = msg.get('from', '') or ''
    date_header = msg.get('date')
    try:
        received_at = parsedate_to_datetime(date_header) if date_header else None
    except (TypeError, ValueError):
        received_at = None

    body = ''
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype == 'text/plain':
                try:
                    body = part.get_content()  # type: ignore[attr-defined]
                    break
                except (LookupError, AttributeError):
                    continue
        if not body:
            for part in msg.walk():
                if part.get_content_type() == 'text/html':
                    try:
                        html = part.get_content()  # type: ignore[attr-defined]
                        body = BeautifulSoup(html, 'lxml').get_text(" ")
                        break
                    except (LookupError, AttributeError, ValueError):
                        continue
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            try:
                body = payload.decode(errors='ignore')
            except (UnicodeDecodeError, AttributeError):
                body = str(payload)

    headers_text = str(msg)
    return {
        "subject": subject,
        "from_addr": from_addr,
        "received_at": received_at,
        "body": body,
        "headers": headers_text,
    }


def extract_urls(text: str):
    return list(set(URL_REGEX.findall(text or '')))


def domain_info(url: str):
    p = urlparse(url)
    ext = tldextract.extract(p.netloc)
    root = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
    return {
        "netloc": p.netloc,
        "root": root.lower(),
        "tld": ext.suffix.lower() if ext.suffix else '',
        "domain": ext.domain.lower(),
        "subdomain": ext.subdomain.lower(),
    }


def whois_domain_age_days(root_domain: str):
    if not whois:
        return None
    try:
        w = whois.whois(root_domain)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        if not created:
            return None
        if isinstance(created, str):
            try:
                created = datetime.fromisoformat(created)
            except ValueError:
                return None
        if created.tzinfo is None:
            created = created.replace(tzinfo=UTC)
        delta = datetime.now(UTC) - created
        return max(delta.days, 0)
    except Exception as e:
        logger.warning("WHOIS lookup failed for %s: %s", root_domain, e)
        return None


def detect_display_name_spoof(from_header: str) -> bool:
    lower = (from_header or '').lower()
    name_part = lower.split('<')[0]
    return any(b in name_part for b in BRAND_KEYWORDS) and not any(
        b in lower for b in ("@microsoft.com", "@apple.com", "@google.com", "@amazon.com", "@facebook.com", "@paypal.com")
    )


def link_text_mismatch(html_or_text: str) -> bool:
    try:
        soup = BeautifulSoup(html_or_text or '', 'lxml')
        anchors = soup.find_all('a')
        for a in anchors:
            text = (a.get_text() or '').lower()
            href = (a.get('href') or '').lower()
            if any(b in text for b in BRAND_KEYWORDS):
                if href and not any(b in href for b in BRAND_KEYWORDS):
                    return True
    except (LookupError, AttributeError, ValueError) as e:
        logger.debug("HTML parsing failed: %s", e)
        return False
    return False


def header_anomalies(headers_text: str):
    anomalies = []
    ht = (headers_text or '').lower()
    if 'reply-to' in ht and 'from' in ht:
        from_match = EMAIL_ADDR_REGEX.search(headers_text or '')
        reply_match = re.search(r"Reply-To:.*?<([^>]+)>", headers_text or '', re.IGNORECASE)
        if from_match and reply_match:
            from_domain = from_match.group(2).split('.')[-2:]
            reply_domain = reply_match.group(1).split('@')[-1].split('.')[-2:]
            if from_domain != reply_domain:
                anomalies.append("Reply-To domain differs from From domain")
    if re.search(r"spf\s*=\s*(fail|softfail)", ht, re.IGNORECASE):
        anomalies.append("SPF fail")
    if 'dkim=fail' in ht:
        anomalies.append('DKIM fail')
    if 'dmarc=fail' in ht:
        anomalies.append('DMARC fail')
    return anomalies


def score_email(parsed: dict, full_text: str):
    urls = extract_urls(full_text)
    roots = [domain_info(u)['root'] for u in urls]
    unique_roots = set(roots)

    explanations = []
    indicators = {
        'urls': urls,
        'unique_domains': sorted(unique_roots),
    }

    score = 0.0

    if len(urls) >= 3:
        score += 15
        explanations.append(f"Contains {len(urls)} links")

    for r in unique_roots:
        ext = tldextract.extract(r)
        tld = ext.suffix.lower()
        if tld and tld not in SAFE_TLDS:
            score += 10
            explanations.append(f"Uses uncommon TLD: .{tld}")

    if detect_display_name_spoof(parsed.get('from_addr', '')):
        score += 20
        explanations.append("Brand name in display name but not email domain")

    anomalies = header_anomalies(parsed.get('headers', ''))
    if anomalies:
        score += 15
        explanations += anomalies
        indicators['header_anomalies'] = anomalies

    if link_text_mismatch(parsed.get('headers', '') + "\n" + parsed.get('body', '')):
        score += 15
        explanations.append("Anchor text mentions brand but links elsewhere")

    ages = []
    for r in unique_roots:
        age = whois_domain_age_days(r)
        if age is not None:
            ages.append(age)
    if ages:
        min_age = min(ages)
        indicators['youngest_domain_age_days'] = min_age
        if min_age < 30:
            score += 25
            explanations.append(f"References very young domain ({min_age} days)")

    score = max(0.0, min(100.0, score))

    verdict = (
        'malicious' if score >= 70 else
        'suspicious' if score >= 40 else
        'safe'
    )

    return score, explanations, indicators | {"verdict": verdict}


def analyze_email(raw_text: str | None, eml_bytes: bytes | None) -> dict:
    parsed = {"subject": "", "from_addr": "", "received_at": None, "body": "", "headers": ""}

    full_text = (raw_text or '')

    if eml_bytes:
        eml_parsed = parse_eml_bytes(eml_bytes)
        parsed.update(eml_parsed)
        full_text = "\n".join([full_text, eml_parsed.get('headers', ''), eml_parsed.get('body', '')])

    score, explanations, indicators = score_email(parsed, full_text)

    return {
        "parsed": parsed,
        "score": score,
        "explanations": explanations,
        "indicators": indicators,
    }
