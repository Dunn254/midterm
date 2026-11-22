import socket
import sys

HOST = "127.0.0.1" #looback address: only this machine can connect
PORT = 65432      #Non-privileged port (1024-65535)
BUFFER_SIZE = 1024   # Max bytes to read per recv() call
ENCODING = "utf-8"

def handle_client(conn: socket.socket, addr: tuple) -> None:
    """Receive messages from one client until it disconnects or sends 'quit'."""
    print(f"[SERVER] Connection established with {addr [0]}:{addr[1]}")
    with conn:   #'with' guarantees the client socket is closed
        while True:
            try:
                data = conn.recv(BUFFER_SIZE)
            except ConnectionResetError:
                print("[SERVER] Client connection was reset unexpectedly.")
                break

            # An empty bytes object means the client closed its side
            if not data:
                print("[SERVER] Client disconnected.")
                break

            message = data.decode(ENCODING).strip()
            print(f"[SERVER] Received from client: {message!r}")

            if message.lower() == "quit":
                conn.sendall("Goodbye! Closing connection.".encode(ENCODING))
                print("[SERVER] Client requested disconnect.")
                break

            # Process the message (here: build a simple response) and reply
            response = f"Server received: {message}"
            conn.sendall(response.encode(ENCODING))
            print(f"[SERVER] Sent response: {response!r}")

def main() -> None:
    #AF_INET = IPv4, SOCK_STREAM = TCP
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except OSError as err:
        print(f"[SERVER] Could not create socket: {err}")
        sys.exit(1)

    with server_socket:
        #Allow quick restarts without "Address already in use" errors
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            server_socket.bind((HOST, PORT))
            server_socket.listen()
        except OSError as err:
            print(f"[SERVER] Could not bind/listen on {HOST}:{PORT}: {err}")
            sys.exit(1)

        print(f"[SERVER] Listening on {HOST}:{PORT} ... (Ctrl+C to stop)")

        try:
            while True:
                conn, addr = server_socket.accept()  #Blocks until a client connects
                handle_client(conn, addr)
                print("[SERVER] Waiting for next connection...")
        except KeyboardInterrupt:
            print("\n[SERVER] Shutdown requested. Closing server socket.")
        except OSError as err:
            print(f"[SERVER] Socket error: {err}")

    print("[SERVER] Server stopped.")

    
if __name__ == "__main__":
    main()

            
