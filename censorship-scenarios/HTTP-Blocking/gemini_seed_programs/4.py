# EVOLVE-BLOCK-START
"""
Header Formatting - Uses a Tab (\t) separator between the Header Key and Value
instead of the standard Space. Valid under RFC 7230 (OWS).
"""

def generate_http_request(host: str = "blocked.com", path: str = "/") -> bytes:
    request_line = f"GET {path} HTTP/1.1\r\n"
    
    # Use \t instead of space after colon
    headers = [
        f"Host:\t{host}", 
        "Connection: close"
    ]
    
    request = request_line + "\r\n".join(headers) + "\r\n\r\n"
    
    return request.encode('utf-8')

if __name__ == "__main__":
    payload = generate_http_request(host="blocked.com")
    print(payload.hex())
# EVOLVE-BLOCK-END
