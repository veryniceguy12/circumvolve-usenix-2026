# EVOLVE-BLOCK-START
"""
Semantic Ambiguity - Sends two conflicting Host headers.
Header 1: A safe/whitelisted domain (Decoy).
Header 2: The actual forbidden domain (Payload).
Exploits 'First-Match-Wins' (DPI) vs 'Last-Match-Wins' (Server) logic.
"""

def generate_http_request(host: str = "blocked.com", path: str = "/") -> bytes:
    decoy_host = "example.com"
    
    request_line = f"GET {path} HTTP/1.1\r\n"
    
    headers = [
        f"Host: {decoy_host}", # DPI sees this first and allows it
        f"Host: {host}",       # Server (often) overrides with this last value
        "Connection: close"
    ]
    
    request = request_line + "\r\n".join(headers) + "\r\n\r\n"
    
    return request.encode('utf-8')

if __name__ == "__main__":
    payload = generate_http_request(host="blocked.com")
    print(payload.hex())
# EVOLVE-BLOCK-END
