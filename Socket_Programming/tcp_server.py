import socket
import time

# Simple XOR encryption
def xor_encrypt_decrypt(data, key=5):
    return ''.join(chr(ord(c) ^ key) for c in data)

# Logging function
def log_event(text):
    with open("Task2/server_log.txt", "a") as log:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        log.write(f"[{timestamp}] {text}\n")

def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("10.0.0.169", 9999))
    server_socket.listen(1)

    print("[SERVER] Started. Waiting for client...")
    log_event("Server started and listening.")

    client_socket, client_address = server_socket.accept()
    print(f"[SERVER] Client connected from {client_address}")
    log_event(f"Client connected from {client_address}")

    try:
        while True:
            encrypted_data = client_socket.recv(4096)
            if not encrypted_data:
                print("[SERVER] Client disconnected.")
                log_event("Client disconnected.")
                break

            data = xor_encrypt_decrypt(encrypted_data.decode())
            print(f"[CLIENT → SERVER] {data}")
            log_event(f"Received: {data}")

            # Handle exit
            if data.lower() == "exit":
                print("[SERVER] Client requested exit. Closing connection.")
                log_event("Client requested exit.")
                break

            # Input validation
            if len(data) > 500:
                reply = "Error: Message too long."
                encrypted_reply = xor_encrypt_decrypt(reply)
                client_socket.send(encrypted_reply.encode())
                continue

            # Help menu
            if data.lower() == "help":
                reply = (
                    "Available commands:\n"
                    "  msg:<text>  - send a normal message\n"
                    "  exit        - close the session\n"
                )
                encrypted_reply = xor_encrypt_decrypt(reply)
                client_socket.send(encrypted_reply.encode())
                continue

            # Normal message
            reply = input("[SERVER → CLIENT] Enter reply: ")
            encrypted_reply = xor_encrypt_decrypt(reply)
            client_socket.send(encrypted_reply.encode())
            log_event(f"Sent: {reply}")

            if reply.lower() == "exit":
                print("[SERVER] Server initiated exit.")
                break

    finally:
        client_socket.close()
        server_socket.close()
        log_event("Server shut down.")
        print("[SERVER] Closed.")

if __name__ == "__main__":
    main()
