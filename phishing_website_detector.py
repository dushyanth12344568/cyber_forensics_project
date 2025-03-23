import re
import whois
import requests
import tkinter as tk
from tkinter import messagebox
from urllib.parse import urlparse


def check_url_blacklist(url):
    google_safe_browsing_api_key = "YOUR_GOOGLE_API_KEY"  # Replace with your API key
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={google_safe_browsing_api_key}"
    payload = {
        "client": {"clientId": "fake-website-detector", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    response = requests.post(api_url, json=payload)
    return response.json().get("matches") is not None


def check_domain_age(url):
    try:
        domain = urlparse(url).netloc
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        return creation_date
    except:
        return None


def check_suspicious_patterns(url):
    patterns = [r"-", r"\.ru", r"\.cn", r"\.tk", r"free", r"login", r"secure"]
    return any(re.search(pattern, url) for pattern in patterns)


def detect_fake_website():
    url = url_entry.get()
    if not url:
        messagebox.showerror("Error", "Please enter a URL")
        return

    result_text.set("Checking URL...")
    results = []

    # 1. Check if the URL is blacklisted
    if check_url_blacklist(url):
        results.append("⚠️ This website is flagged as unsafe by Google Safe Browsing!")

    # 2. Check domain age
    domain_age = check_domain_age(url)
    if domain_age:
        results.append(f"🕵️ Domain was created on: {domain_age}")
    else:
        results.append("⚠️ Could not retrieve domain information. It may be suspicious!")

    # 3. Check for suspicious patterns in URL
    if check_suspicious_patterns(url):
        results.append("⚠️ The URL contains suspicious keywords or patterns!")
    else:
        results.append("✅ No obvious suspicious patterns detected.")

    result_text.set("\n".join(results))


# GUI Setup
root = tk.Tk()
root.title("Fake Website Detector")
root.geometry("500x300")

tk.Label(root, text="Enter Website URL:").pack(pady=5)
url_entry = tk.Entry(root, width=50)
url_entry.pack(pady=5)

tk.Button(root, text="Check Website", command=detect_fake_website).pack(pady=10)

result_text = tk.StringVar()
tk.Label(root, textvariable=result_text, wraplength=450, justify="left").pack(pady=10)

root.mainloop()
