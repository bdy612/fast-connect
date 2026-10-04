import socket
import threading
import logging

from secure_channel import SecureChannel, ChannelError

MAX_CLIENTS = 200
MAX_LOG_ENTRIES = 1000


class Server:
    def __init__(self, host, port):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((host, port))
        self.server_socket.listen(5)
        self.running = True
        self.clients = []  # List of (socket, address) for connected clients
        self._channels = {}  # address -> SecureChannel, once its handshake is done
        self._lock = threading.Lock()
        self.message_handler = None
        self.client_kicked_handler = None  # Callback for when a client is kicked
        self.log = []

        # Start the listener in a separate thread
        self.listener_thread = threading.Thread(target=self.listen_for_clients)
        self.listener_thread.daemon = True
        self.listener_thread.start()

    def _log(self, entry):
        self.log.append(entry)
        if len(self.log) > MAX_LOG_ENTRIES:
            del self.log[:len(self.log) - MAX_LOG_ENTRIES]

    def get_binding(self, client_address):
        """The identifier of a client's encrypted connection (see secure_channel.py)"""
        channel = self._channels.get(client_address)
        return channel.binding if channel else None

    def listen_for_clients(self):
        """Listen for incoming client connections"""
        self.server_socket.settimeout(1.0)  # Add timeout to allow checking running flag

        while self.running:
            try:
                client_socket, client_address = self.server_socket.accept()

                if len(self.clients) >= MAX_CLIENTS:
                    self._log(f"Refused {client_address}: server is full")
                    client_socket.close()
                    continue

                self._log(f"Connection from {client_address}")
                with self._lock:
                    self.clients.append((client_socket, client_address))

                # Start a thread to handle this client
                client_thread = threading.Thread(target=self.handle_client,
                                               args=(client_socket, client_address))
                client_thread.daemon = True
                client_thread.start()

            except socket.timeout:
                # This allows the server to check if it should continue running
                continue
            except Exception as e:
                if self.running:  # Only log if still supposed to be running
                    self._log(f"Error accepting connection: {e}")

    def handle_client(self, client_socket, client_address):
        """Handle communication with a connected client"""
        client_socket.settimeout(1.0)
        channel = SecureChannel(client_socket, is_server=True, should_stop=lambda: not self.running)
        try:
            # Nothing is accepted from a client until the connection is encrypted
            channel.handshake()
            with self._lock:
                self._channels[client_address] = channel

            while self.running:
                data = channel.recv()

                # Message contents are private: log only that something arrived
                self._log(f"Received {len(data)} characters from {client_address}")

                if self.message_handler:
                    self.message_handler(client_address, data)

        except ChannelError as e:
            self._log(f"Client {client_address} disconnected ({e})")
        except Exception as e:
            if self.running:
                self._log(f"Error communicating with {client_address}: {e}")
        finally:
            # Notify about disconnect then clean up
            if self.client_kicked_handler:
                self.client_kicked_handler(client_address, "Disconnected")
            self.remove_client(client_socket, client_address)

    def kick_client(self, client_address):
        """Forcibly disconnect a client"""
        for client_socket, addr in list(self.clients):
            if addr == client_address:
                try:
                    # Send a kick message to the client
                    try:
                        self._channels[addr].send('{"type": "kicked"}')
                    except Exception:
                        pass  # Client might already be unresponsive

                    # Close the socket (handle_client finally block will clean up)
                    client_socket.close()

                    # Call the kicked handler if set
                    if self.client_kicked_handler:
                        self.client_kicked_handler(addr, "Kicked by server")

                    self._log(f"Client {addr} has been kicked")
                    return True
                except Exception as e:
                    self._log(f"Error kicking client {addr}: {e}")
                    return False

        self._log(f"Client {client_address} not found")
        return False

    def remove_client(self, client_socket, client_address):
        """Remove a client from the list and close their socket"""
        with self._lock:
            self._channels.pop(client_address, None)
            if (client_socket, client_address) in self.clients:
                self.clients.remove((client_socket, client_address))

        try:
            client_socket.close()
        except Exception:
            pass  # Socket might already be closed

    def broadcast(self, message):
        """Send a message to all connected clients"""
        for client_address, channel in list(self._channels.items()):
            try:
                channel.send(message)
            except ChannelError:
                pass  # Its handle_client thread notices the dead connection and cleans up

    def send_to_client(self, client_address, message):
        """Send a message to a specific client by address"""
        channel = self._channels.get(client_address)
        if channel is None:
            self._log(f"Client {client_address} not found")
            return False
        try:
            channel.send(message)
            return True
        except ChannelError as e:
            self._log(f"Error sending to {client_address}: {e}")
            return False

    def set_message_handler(self, handler_function):
        """Set a function to handle incoming messages"""
        self.message_handler = handler_function

    def set_client_kicked_handler(self, handler_function):
        """Set a function to handle client kick events"""
        self.client_kicked_handler = handler_function

    def close(self):
        """Close the server and all client connections"""
        self.running = False

        # Close all client connections
        for client_socket, _ in list(self.clients):
            try:
                client_socket.close()
            except Exception:
                pass
        with self._lock:
            self.clients = []
            self._channels = {}

        # Close server socket
        try:
            self.server_socket.close()
        except Exception:
            pass
