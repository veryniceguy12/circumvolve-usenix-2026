# EVOLVE-BLOCK-START
"""
Protocol Versioning - Uses a non-standard HTTP version (HTTP/1.2).
DPI looking for 'HTTP/1.1' or 'HTTP/1.0' signatures will miss this,
while robust servers often parse loosely (e.g., sscanf("HTTP/%d.%d")).
"""

def generate_http_request(host: str = "blocked.com", path: str = "/") -> bytes:
    # Use a fake version "1.2"
    request_line = f"GET {path} HTTP/1.2\r\n"
    
    headers = [
        f"Host: {host}",
        "Connection: close"
    ]
    
    request = request_line + "\r\n".join(headers) + "\r\n\r\n"
    
    return request.encode('utf-8')

if __name__ == "__main__":
    payload = generate_http_request(host="blocked.com")
    print(payload.hex())
# EVOLVE-BLOCK-END
