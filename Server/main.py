from core.server import Server
import os
import sys

current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.append(current_dir)


if __name__ == "__main__":
    print("Starting server on port 8080...")
    try:
        server = Server(host="0.0.0.0", port=8080)
        server.start()
    except Exception as e:
        print(f"Server Error {e}")
