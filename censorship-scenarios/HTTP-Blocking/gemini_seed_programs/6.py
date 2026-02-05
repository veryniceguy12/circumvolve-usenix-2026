# EVOLVE-BLOCK-START
"""
Request Semantics - Sends the full Absolute URI in the Request Line.
Common in proxy traffic, but valid for direct server connections (RFC 7230).
"""

def generate_http_request(host: str = "blocked.com", path: str = "/") -> bytes:
    # Construct absolute URI: GET http://blocked.com/ HTTP/1.1
    # Note: path must handle the leading slash correctly
    clean_path = path.lstrip("/")
    absolute_uri = f"http://{host}/{clean_path}"
    
    request_line = f"GET {absolute_uri} HTTP/1.1\r\n"
    
    headers = [
        f"Host: {host}", # Host header is still required in HTTP/1.1
        "Connection: close"
    ]
    
    request = request_line + "\r\n".join(headers) + "\r\n\r\n"
    
    return request.encode('utf-8')

if __name__ == "__main__":
    payload = generate_http_request(host="blocked.com")
    print(payload.hex())
# EVOLVE-BLOCK-END
