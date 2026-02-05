# EVOLVE-BLOCK-START
"""
Method Tunneling - Sends a POST request disguised as a GET via 
the 'X-HTTP-Method-Override' header. Bypasses DPI rules that 
specifically target GET verbs on sensitive paths.
"""

def generate_http_request(host: str = "blocked.com", path: str = "/") -> bytes:
    # Send POST instead of GET
    request_line = f"POST {path} HTTP/1.1\r\n"
    
    headers = [
        f"Host: {host}",
        "X-HTTP-Method-Override: GET", # Tells server to treat this as GET
        "Content-Length: 0",           # Valid POST requires Content-Length
        "Connection: close"
    ]
    
    request = request_line + "\r\n".join(headers) + "\r\n\r\n"
    
    return request.encode('utf-8')

if __name__ == "__main__":
    payload = generate_http_request(host="blocked.com")
    print(payload.hex())
# EVOLVE-BLOCK-END
