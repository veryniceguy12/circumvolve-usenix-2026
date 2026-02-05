# EVOLVE-BLOCK-START
"""
Inspection Buffer Overflow - Injects a massive 3KB 'junk' header before 
the Host header. This pushes the sensitive Host data beyond the static 
inspection window of many high-speed DPI appliances.
"""

def generate_http_request(host: str = "blocked.com", path: str = "/") -> bytes:
    request_line = f"GET {path} HTTP/1.1\r\n"
    
    # Generate 3000 bytes of junk data 'A'
    # Most DPI buffers are 1024 or 2048 bytes deep.
    padding_size = 3000 
    junk_data = "A" * padding_size
    
    headers = [
        f"X-Ignore-Me: {junk_data}", # The "Fat" header
        f"Host: {host}",              # The hidden sensitive header
        "Connection: close"
    ]
    
    request = request_line + "\r\n".join(headers) + "\r\n\r\n"
    
    return request.encode('utf-8')

if __name__ == "__main__":
    payload = generate_http_request(host="blocked.com")
    print(payload.hex())
# EVOLVE-BLOCK-END
