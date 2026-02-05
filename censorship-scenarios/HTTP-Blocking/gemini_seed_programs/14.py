# EVOLVE-BLOCK-START
"""
Tokenizer Desync - Injects a space before the colon in the Host header.
Format: 'Host : value'. Confuses simple string splitters in DPI,
relying on server normalization to strip the pre-colon whitespace.
"""

def generate_http_request(host: str = "blocked.com", path: str = "/") -> bytes:
    request_line = f"GET {path} HTTP/1.1\r\n"
    
    # Note the space between 'Host' and ':'
    headers = [
        f"Host : {host}", 
        "Connection: close"
    ]
    
    request = request_line + "\r\n".join(headers) + "\r\n\r\n"
    
    return request.encode('utf-8')

if __name__ == "__main__":
    payload = generate_http_request(host="blocked.com")
    print(payload.hex())
# EVOLVE-BLOCK-END	
