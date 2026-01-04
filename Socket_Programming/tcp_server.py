import socket

# Create TCP socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind to IP and port
HOST = '127.0.0.1'   # localhost
PORT = 5000
server_socket.bind((HOST, PORT))

# Listen for incoming connections
server_socket.listen(1)
print(f"[SERVER] Listening on {HOST}:{PORT}")

# Accept client connection
conn, addr = server_socket.accept()
print(f"[SERVER] Connected by {addr}")

# Receive data from client
data = conn.recv(1024).decode()
print(f"[SERVER] Received: {data}")

# Send response to client
response = "Hello Client, message received!"
conn.send(response.encode())

# Close connection
conn.close()
server_socket.close()
print("[SERVER] Connection closed")
