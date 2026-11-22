import socket
import sys
HOST = "127.0.0.1"  # Must match the server's address
PORT = 65432        # Must match the server's port
BUFFER_SIZE = 1024
ENCODING = "utf-8"
TIMEOUT = 5         # Seconds to wait before giving up on the connect/recv

def main() -> None:
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.settimeout(TIMEOUT)
    except OSError as err:
        print(f"[CLIENT] Coult not create socket: {err}")
        sys.exit(1)

    with client_socket:
        # --- Connect, with error handling for a server that isn't running ---
        try:
            print(f"[CLIENT] Connecting to {HOST}:{PORT} ...")
            client_socket.connect((HOST, PORT))
        except ConnectionRefusedError:
            print(f"[CLIENT] ERROR: Connection refused. Is the server running on {HOST}:{PORT}?")
            sys.exit(1)
        except socket.timeout:
            print("[CLIENT] ERROR: Connection time out.")
            sys.exit(1)
        except OSError as err:
            print(f"[CLIENT] Error:: Coult not connect: {err}")
            sys.exit(1)

        print("[CLIENT] Connected to server. Type a message and press Enter ('quit' to exit).")

        # --- Message loop ---
        try:
            while True:
                message = input("[CLIENT] Enter message: "). strip()
                if not message:
                   continue # Ignore empty input
                
                client_socket.sendall(message.encode(ENCODING))

                try:
                    data = client_socket.recv(BUFFER_SIZE)
                except socket.timeout:
                    print("[CLIENT] ERROR: time out waiting for server response.")
                    break

                if not data:
                    print("[CLIENT] Server closed the connection.")
                    break

                print(f"[CLIENT] Server replied: {data.decode(ENCODING)!r}")

                if message.lower() == "quit":
                    break
        except (BrokenPipeError, ConnectionResetError):
            print("[CLIENT] ERROR: Lost connection to server.")
        except (KeyboardInterrupt, EOFError):
            print("\n[CLIENT] Interrupted by user.")

    print("[CLIENT] Disconnected cleanly.")


if __name__ == "__main__":
    main()

            