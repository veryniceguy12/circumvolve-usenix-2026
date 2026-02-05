# EVOLVE-BLOCK-START
"""
Host Obfuscation - Appends a trailing dot to the Host header.
Valid in DNS (FQDN), but breaks string-exact matching in DPI.
"""

def generate_http_request(host: str = "blocked.com", path: str = "/") -> bytes:
    request_line = f"GET {path} HTTP/1.1\r\n"
    
    # Append dot to host
    fqdn_host = f"{host}."
    
    headers = [
        f"Host: {fqdn_host}",
        "Connection: close"
    ]
    
    request = request_line + "\r\n".join(headers) + "\r\n\r\n"
    
    return request.encode('utf-8')

if __name__ == "__main__":
    payload = generate_http_request(host="blocked.com")
    print(payload.hex())
# EVOLVE-BLOCK-END
