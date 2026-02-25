import socket
import time

# Simple XOR encryption
def xor_encrypt_decrypt(data, key=5):
    return ''.join(chr(ord(c) ^ key) for c in data)

def main():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(("10.0.0.169", 9999))

    print("[CLIENT] Connected to server. Type 'help' for commands.")
    
    while True:
        message = input("[CLIENT → SERVER] ")

        # Input validation
        if not message.strip():
            print("[CLIENT] Empty message blocked.")
            continue

        encrypted_message = xor_encrypt_decrypt(message)
        client_socket.send(encrypted_message.encode())

        if message.lower() == "exit":
            break

        encrypted_reply = client_socket.recv(4096).decode()
        reply = xor_encrypt_decrypt(encrypted_reply)

        print(f"[SERVER → CLIENT] {reply}")

    client_socket.close()
    print("[CLIENT] Disconnected.")

if __name__ == "__main__":
    main()
