import os
import time
from fast_connect import FastConnectServer

if __name__ == "__main__":
    # Host 0.0.0.0 tells the cloud container to accept traffic externally
    # Render assigns an environment variable for the port automatically
    port = int(os.environ.get("PORT", 9999))

    # Remote control from server_control.py ("Connect to Online Server"). Set this as a secret
    # environment variable on the host (e.g. Render -> Environment), never in the code.
    admin_password = os.environ.get("FASTCONNECT_ADMIN_PASSWORD", "")
    if admin_password and len(admin_password) < 8:
        print("FASTCONNECT_ADMIN_PASSWORD is shorter than 8 characters - remote control stays off.")
        admin_password = ""

    print(f"Starting FastConnect Cloud Server on port {port}...")
    server = FastConnectServer(host='0.0.0.0', port=port, admin_password=admin_password or None)

    if server.start():
        print("Server is successfully running online.")
        print("Remote control:", "ON" if admin_password else "OFF (set FASTCONNECT_ADMIN_PASSWORD to turn it on)")
        # Keep the main thread alive indefinitely
        while True:
            time.sleep(3600)
