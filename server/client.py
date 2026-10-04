import socket
import threading
import json
import logging

from secure_channel import SecureChannel, ChannelError

# Create a logger
logger = logging.getLogger(__name__)

CONNECT_SECONDS = 10


class Client:
    def __init__(self, server_host, server_port):
        self.client_socket = socket.create_connection((server_host, server_port), timeout=CONNECT_SECONDS)
        self.running = True
        self.message_callback = None
        self.disconnect_callback = None

        # Encrypt the connection before anything else is sent
        self.client_socket.settimeout(1.0)
        self.channel = SecureChannel(self.client_socket, is_server=False, should_stop=lambda: not self.running)
        try:
            self.channel.handshake()
        except ChannelError:
            self.client_socket.close()
            raise
        self.binding = self.channel.binding
        logger.info(f"Connected to server at {server_host}:{server_port}")

        # Start listening thread
        self.listen_thread = threading.Thread(target=self.listen_for_messages)
        self.listen_thread.daemon = True
        self.listen_thread.start()

    def listen_for_messages(self):
        """Listen for incoming messages from the server"""
        while self.running:
            try:
                message = self.channel.recv()
            except ChannelError:
                if self.running:
                    logger.info("Disconnected from server")
                    if self.disconnect_callback:
                        self.disconnect_callback("Server disconnected")
                self.running = False
                break

            # Check if we've been kicked (JSON type)
            try:
                msg_data = json.loads(message)
                if msg_data.get('type') == 'kicked':
                    logger.info("You have been kicked from the server")
                    if self.disconnect_callback:
                        self.disconnect_callback("Kicked by server")
                    self.running = False
                    break
            except Exception:
                pass

            if self.message_callback:
                self.message_callback(message)

    def send(self, message):
        """Send a message to the server"""
        try:
            self.channel.send(message)
            return True
        except ChannelError as e:
            logger.error(f"Error sending message: {e}")
            return False

    def set_message_callback(self, callback_function):
        """Set a function to call when messages are received"""
        self.message_callback = callback_function

    def set_disconnect_callback(self, callback_function):
        """Set a function to call when disconnected"""
        self.disconnect_callback = callback_function

    def close(self):
        """Close the connection to the server"""
        self.running = False
        self.client_socket.close()
