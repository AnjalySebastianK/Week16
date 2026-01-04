import socket

# Create TCP socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

HOST = '127.0.0.1'
PORT = 5000

# Connect to server
client_socket.connect((HOST, PORT))
print("[CLIENT] Connected to server")

# Send message to server
message = "Hello Server!"
client_socket.send(message.encode())
print(f"[CLIENT] Sent: {message}")

# Receive response from server
response = client_socket.recv(1024).decode()
print(f"[CLIENT] Received: {response}")

# Close connection
client_socket.close()
print("[CLIENT] Connection closed")
