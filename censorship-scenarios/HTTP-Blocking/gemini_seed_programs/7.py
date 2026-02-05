# EVOLVE-BLOCK-START
"""
Request Line Smuggling - Injects extra spaces between the verb and path.
Confuses rigid tokenizers that expect single-space delimiters.
"""

def generate_http_request(host: str = "blocked.com", path: str = "/") -> bytes:
    # Inject 3 spaces between GET and path
    request_line = f"GET   {path} HTTP/1.1\r\n"
    
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
