import requests
from requests.cookies import RequestsCookieJar

# List of domains to test
domains = ["admin.microsoft.com"]

# Define user agent (you may need to change this to match your environment)
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36"
}

# Function to check CSRF vulnerability
def test_csrf_vulnerability(domain):
    # Start a session
    session = requests.Session()
    
    # Try to access a known session cookie from the domain (simulate user being logged in)
    response = session.get(f"https://{domain}/", headers=headers, allow_redirects=True)
    
    # Extract cookies (this is the session cookie we're interested in)
    session_cookie = session.cookies.get_dict()

    # If no session cookie, we can't test for CSRF
    if not session_cookie:
        print(f"[{domain}] No session cookie found.")
        return False

    print(f"[{domain}] Found session cookie: {session_cookie}")

    # Simulate a CSRF attack by attempting a sensitive action without the CSRF token
    # For example, making a POST request to a vulnerable endpoint without a CSRF token
    csrf_vulnerable = False
    csrf_endpoint = f"https://{domain}/"  # This would need to be a real endpoint on the domain, so it's default to the domain itself here
    
    # Perform a request without including any CSRF token or custom headers
    csrf_attack_response = session.post(csrf_endpoint, data={}, headers=headers, allow_redirects=True)

    # Check if the attack is successful (i.e., the session cookie was sent automatically and the action was processed)
    if csrf_attack_response.status_code == 200:
        print(f"[{domain}] CSRF attack successful. The session cookie was used without any additional protection.")
        csrf_vulnerable = True
    else:
        print(f"[{domain}] CSRF attack failed. No action was taken or response code indicates protection (e.g., 403).")

    return csrf_vulnerable

# Test each domain
for domain in domains:
    is_vulnerable = test_csrf_vulnerability(domain)
    if is_vulnerable:
        print(f"Domain {domain} is vulnerable to CSRF attacks.")
    else:
        print(f"Domain {domain} is not vulnerable to CSRF.")
