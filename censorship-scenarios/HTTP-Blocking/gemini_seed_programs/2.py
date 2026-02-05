# EVOLVE-BLOCK-START
"""
Traffic Pipelining - Sends two complete HTTP requests in a single payload.
Request 1: Targets a safe/allowed domain (The "Decoy").
Request 2: Targets the forbidden domain (The "Payload").
DPI often inspects only the head of the stream (Req 1) and lets the tail pass.
"""

def generate_http_request(host: str = "blocked.com", path: str = "/") -> bytes:
    # --- Request 1: The Decoy ---
    # Targets a safe domain (e.g., the server's own IP or a whitelisted site)
    decoy_host = "google.com" 
    req1 = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {decoy_host}\r\n"
        f"Connection: keep-alive\r\n" # Critical: Keep conn open for Req 2
        f"\r\n"
    )
    
    # --- Request 2: The Payload ---
    # The actual request we want executed
    req2 = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    )
    
    # Combine them into a single stream
    payload = req1 + req2
    
    return payload.encode('utf-8')

if __name__ == "__main__":
    payload = generate_http_request(host="blocked.com")
    print(payload.hex())
# EVOLVE-BLOCK-END
