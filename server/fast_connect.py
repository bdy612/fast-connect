import hashlib
import hmac
import json
import os
import re
import threading
import secrets
import string
import time
from collections import deque
from client import Client
from server import Server
from main import Encription
import accounts_api

MAX_MESSAGE_CHARS = 4000
MAX_PENDING_REQUESTS = 50
RATE_LIMIT_MESSAGES = 30       # per connection...
RATE_LIMIT_SECONDS = 10        # ...in this many seconds
_GUEST_NAME = re.compile(r'^Guest_\d{4}$')

ADMIN_MAX_FAILURES = 5          # wrong remote-admin passwords per IP...
ADMIN_LOCKOUT_SECONDS = 15 * 60  # ...before that IP is locked out for this long


class FastConnectServer:
    """Server-side FastConnect with multi-layer encryption"""

    def __init__(self, host='0.0.0.0', port=9999, admin_password=None):
        self.host = host
        self.port = port
        self.server = None
        # Remote control (server_control.py "Connect to online server"): off unless a password is given
        self._admin_hash = None
        if admin_password:
            salt = secrets.token_bytes(16)
            self._admin_hash = (salt, hashlib.pbkdf2_hmac('sha256', admin_password.encode('utf-8'), salt, 200000))
        self.admin_addrs = set()      # connections that proved the admin password
        self._admin_failures = {}     # ip -> [failure count, time of first failure]
        self._events = deque(maxlen=500)  # joins, leaves and broadcasts, for remote admins
        self._event_seq = 0
        self.users = {}  # username -> {'address': addr, 'real_name': name}
        self.addr_user = {}  # address -> username it proved (or its guest name)
        self.friend_requests = {}  # username -> [list of pending requests]
        self.friendships = {}  # username -> [list of accepted friends]
        self.muted_from_broadcast = set()  # usernames who cannot send broadcasts
        self.server_master_key = None    # the 16th key, set by the server admin
        self.encryption_key = self._generate_multi_layer_key()
        self.encryption_type = Encription.VIGENERE  # Vigenère: reversible with key only
        self.callbacks = {}
        self._recent = {}  # address -> times of its latest messages (flood protection)
        self._lock = threading.RLock()

    def _generate_multi_layer_key(self, iterations=15):
        """Generate multi-layer randomized encryption key (15 iterations)"""
        alphabet = string.ascii_letters + string.digits
        return '|'.join(''.join(secrets.choice(alphabet) for _ in range(32)) for _ in range(iterations))

    def start(self):
        """Start the server"""
        try:
            self.server = Server(self.host, self.port)
            self.server.set_message_handler(self._handle_message)
            self.server.set_client_kicked_handler(self._handle_client_kicked)
            self._trigger_callback('server_started', {'host': self.host, 'port': self.port})
            return True
        except Exception as e:
            print(f"Error starting server: {e}")
            self._trigger_callback('server_error', {'error': str(e)})
            return False

    def stop(self):
        """Stop the server"""
        if self.server:
            self.server.close()
            self.server = None
            self._trigger_callback('server_stopped', {})
            return True
        return False

    def _send(self, username, payload):
        """Send a JSON message to a connected user"""
        user = self.users.get(username)
        if user and self.server:
            self.server.send_to_client(user['address'], json.dumps(payload))

    def _allow(self, client_address):
        """Flood protection: at most RATE_LIMIT_MESSAGES per RATE_LIMIT_SECONDS per connection"""
        now = time.monotonic()
        recent = self._recent.setdefault(client_address, deque())
        while recent and now - recent[0] > RATE_LIMIT_SECONDS:
            recent.popleft()
        if len(recent) >= RATE_LIMIT_MESSAGES:
            return False
        recent.append(now)
        return True

    def _handle_message(self, client_address, message):
        """Handle incoming messages on the server"""
        try:
            data = json.loads(message)
            if not isinstance(data, dict):
                return
            msg_type = data.get('type')

            if msg_type == 'register':
                # Checking a login ticket takes a network call, so it runs outside the lock
                self._handle_register(client_address, data)
                return
            if msg_type == 'admin_login':
                self._handle_admin_login(client_address, data)
                return

            with self._lock:
                if client_address in self.admin_addrs:
                    if msg_type == 'admin' and self._allow(client_address):
                        self._handle_admin_command(client_address, data)
                    return

                # Who is sending is decided by the connection, never by what the message claims
                username = self.addr_user.get(client_address)
                if username is None or not self._allow(client_address):
                    return

                if msg_type == 'friend_request':
                    self._handle_friend_request(username, data)
                elif msg_type == 'friend_response':
                    self._handle_friend_response(username, data)
                elif msg_type == 'private_message':
                    self._handle_private_message(username, data)
                elif msg_type == 'broadcast':
                    self._handle_broadcast(username, data)
                elif msg_type == 'list_users':
                    self._handle_list_users(client_address)

        except Exception as e:
            print(f"Error handling message: {e}")

    # ------------------------------------------------------------------
    # Remote control: the owner's server_control.py, connected over the encrypted channel
    # ------------------------------------------------------------------
    def _handle_admin_login(self, client_address, data):
        ip = client_address[0]
        now = time.monotonic()
        with self._lock:
            if client_address in self.addr_user or client_address in self.admin_addrs:
                return
            count, since = self._admin_failures.get(ip, (0, now))
            if now - since > ADMIN_LOCKOUT_SECONDS:
                count, since = 0, now
            if count >= ADMIN_MAX_FAILURES:
                self._send_admin(client_address, {'type': 'admin_login_result', 'ok': False,
                                                  'error': 'Too many wrong passwords. Try again in 15 minutes.'})
                return

        password = data.get('password')
        good = False
        if self._admin_hash and isinstance(password, str) and len(password) <= 200:
            salt, expected = self._admin_hash
            good = hmac.compare_digest(hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 200000), expected)

        with self._lock:
            if not good:
                self._admin_failures[ip] = (count + 1, since)
                error = 'Wrong password.' if self._admin_hash else 'Remote control is turned off on this server.'
                self._send_admin(client_address, {'type': 'admin_login_result', 'ok': False, 'error': error})
                return
            self._admin_failures.pop(ip, None)
            self.admin_addrs.add(client_address)
            if self.server:
                self.server._log(f"Remote admin connected from {client_address[0]}")
            self._send_admin(client_address, {'type': 'admin_login_result', 'ok': True})

    def _handle_admin_command(self, client_address, data):
        cmd = data.get('cmd')
        arg = data.get('arg')
        if cmd == 'kick' and isinstance(arg, str):
            self.kick_user(arg)
        elif cmd == 'mute' and isinstance(arg, str):
            self.mute_user(arg)
        elif cmd == 'unmute' and isinstance(arg, str):
            self.unmute_user(arg)
        elif cmd == 'broadcast' and isinstance(arg, str) and 0 < len(arg) <= MAX_MESSAGE_CHARS:
            self.broadcast_as_server(arg)
        elif cmd == 'set_master_key' and isinstance(arg, str) and len(arg) <= 200:
            self.set_server_master_key(arg)
        elif cmd == 'regen_keys':
            self.regenerate_keys()
        elif cmd == 'clear_log' and self.server:
            self.server.log.clear()
        elif cmd != 'state':
            return
        since = data.get('since') if isinstance(data.get('since'), int) else 0
        self._send_admin(client_address, {
            'type': 'admin_state',
            'users': [[name, u['real_name'], u['address'][0], u['address'][1]] for name, u in self.users.items()],
            'muted': sorted(self.muted_from_broadcast),
            'friendships': self.friendships,
            'friend_requests': self.friend_requests,
            'layers': self.get_encryption_layers(),
            'log': list(self.server.log[-200:]) if self.server else [],
            'events': [e for e in self._events if e['seq'] > since],
        })

    def _send_admin(self, client_address, payload):
        if self.server:
            self.server.send_to_client(client_address, json.dumps(payload))

    def _reject_registration(self, client_address, reason):
        response = {'type': 'register_ack', 'status': 'error', 'message': reason}
        self.server.send_to_client(client_address, json.dumps(response))

    def _handle_register(self, client_address, data):
        """Handle user registration"""
        if client_address in self.addr_user or client_address in self.admin_addrs:
            return

        ticket = data.get('ticket')
        if isinstance(ticket, str) and ticket:
            # A signed-in user: the accounts backend says who the ticket belongs to
            result = accounts_api.verify_ticket(ticket)
            if not result.get('ok'):
                self._reject_registration(client_address, result.get('error') or 'Could not verify your login.')
                return
            # The ticket must have been issued for this exact encrypted connection
            if not result.get('bind') or result.get('bind') != self.server.get_binding(client_address):
                self._reject_registration(client_address, 'Your login could not be verified for this connection.')
                return
            username = result['username']
            real_name = result.get('real_name') or ''
            friends_details = result.get('friends') if isinstance(result.get('friends'), dict) else {}
        else:
            # A guest: no account, no saved friends, and only a Guest_#### name
            username = data.get('username')
            if not isinstance(username, str) or not _GUEST_NAME.match(username):
                self._reject_registration(client_address, 'Log in to your account to use this username.')
                return
            real_name = 'Guest User'
            friends_details = {}

        with self._lock:
            if username in self.users:
                self._reject_registration(client_address, f"'{username}' is already connected to this server.")
                return

            self.users[username] = {
                'address': client_address,
                'real_name': real_name
            }
            self.addr_user[client_address] = username
            self.friend_requests[username] = []
            self.friendships[username] = list(friends_details.keys())

            # Notify all users about new user
            self._broadcast_system_message(f"{username} joined the server")
            self._trigger_callback('user_registered', {'username': username, 'real_name': real_name})

            # Send acknowledgement: encryption key + existing friends list
            response = {
                'type': 'register_ack',
                'status': 'success',
                'username': username,
                'encryption_key': self.encryption_key,
                'encryption_type': self.encryption_type,
                'friends': friends_details   # {username: {real_name: ...}}
            }
            self.server.send_to_client(client_address, json.dumps(response))

    def _handle_friend_request(self, from_user, data):
        """Handle friend request"""
        to_user = data.get('to_user')
        if not isinstance(to_user, str) or to_user == from_user or to_user not in self.users:
            return
        if to_user in self.friendships.get(from_user, []):
            return

        pending = self.friend_requests[to_user]
        if from_user not in pending:
            if len(pending) >= MAX_PENDING_REQUESTS:
                return
            pending.append(from_user)

        self._send(to_user, {
            'type': 'friend_request_notification',
            'from_user': from_user,
            'real_name': self.users[from_user]['real_name']
        })
        self._trigger_callback('friend_request_sent', {'from': from_user, 'to': to_user})

    def _handle_friend_response(self, responder, data):
        """Handle friend request response (accept/decline)"""
        requester = data.get('from_user')
        accepted = data.get('accepted') is True

        # Only a request that was really sent to this user can be answered
        if requester not in self.friend_requests.get(responder, []):
            return
        self.friend_requests[responder].remove(requester)
        if requester not in self.users:
            return

        if accepted:
            if requester not in self.friendships[responder]:
                self.friendships[responder].append(requester)
            if responder not in self.friendships[requester]:
                self.friendships[requester].append(responder)

            # Each client saves its own side of the friendship to its account
            self._send(responder, {
                'type': 'friend_accepted',
                'friend_username': requester,
                'friend_real_name': self.users[requester]['real_name']
            })
            self._send(requester, {
                'type': 'friend_accepted',
                'friend_username': responder,
                'friend_real_name': self.users[responder]['real_name']
            })
            self._trigger_callback('friendship_established', {'user1': requester, 'user2': responder})
        else:
            self._send(requester, {
                'type': 'friend_declined',
                'friend_username': responder
            })

    def _handle_private_message(self, from_user, data):
        """Handle private message between friends"""
        to_user = data.get('to_user')
        message = data.get('message')
        if not isinstance(message, str) or not message or len(message) > MAX_MESSAGE_CHARS:
            return

        if to_user in self.friendships.get(from_user, []) and to_user in self.users:
            self._send(to_user, {
                'type': 'private_message',
                'from_user': from_user,
                'message': self._encrypt_with_layers(message),
                'encrypted': True
            })
            self._trigger_callback('private_message', {'from': from_user, 'to': to_user})

    def _handle_broadcast(self, from_user, data):
        """Handle broadcast message to all users"""
        message = data.get('message')
        if not isinstance(message, str) or not message or len(message) > MAX_MESSAGE_CHARS:
            return

        # Respect server mute list
        if from_user in self.muted_from_broadcast:
            self._send(from_user, {'type': 'system_message',
                                   'message': 'You are muted from broadcasting by the server.'})
            return

        broadcast_obj = {
            'type': 'broadcast_message',
            'from_user': from_user,
            'message': self._encrypt_with_layers(message),
            'encrypted': True
        }

        self.server.broadcast(json.dumps(broadcast_obj))
        self._trigger_callback('broadcast_sent', {'from_user': from_user})

    def _handle_list_users(self, client_address):
        """Send list of connected users"""
        users_list = list(self.users.keys())
        response = {
            'type': 'users_list',
            'users': users_list
        }
        self.server.send_to_client(client_address, json.dumps(response))
    
    def _handle_client_kicked(self, client_address, reason):
        """Handle client disconnect (normal or kicked)"""
        with self._lock:
            self._recent.pop(client_address, None)
            self.admin_addrs.discard(client_address)
            username = self.addr_user.pop(client_address, None)
            if username:
                del self.users[username]
                self.friend_requests.pop(username, None)
                self.friendships.pop(username, None)
                for pending in self.friend_requests.values():
                    if username in pending:
                        pending.remove(username)
                self._broadcast_system_message(f"{username} left the server")
                self._trigger_callback('user_disconnected', {'username': username})

    def _encrypt_with_layers(self, message, iterations=15):
        """Encrypt message through 15 Vigenère layers"""
        result = message
        keys = self.encryption_key.split('|') if '|' in self.encryption_key else [self.encryption_key]

        for i in range(min(iterations, len(keys))):
            try:
                result = Encription.encrypt(
                    result,
                    {'key': keys[i]},
                    Encription.VIGENERE
                )['text']
            except Exception:
                pass

        return result
    
    def _broadcast_system_message(self, message):
        """Broadcast a system message to all users"""
        if self.server:
            broadcast_obj = {
                'type': 'system_message',
                'message': message
            }
            self.server.broadcast(json.dumps(broadcast_obj))
    
    def register_callback(self, event_name, callback):
        """Register callback for events"""
        if event_name not in self.callbacks:
            self.callbacks[event_name] = []
        self.callbacks[event_name].append(callback)

    def _trigger_callback(self, event_name, data):
        """Trigger callbacks"""
        if event_name in ('user_registered', 'user_disconnected', 'broadcast_sent'):
            self._event_seq += 1
            self._events.append({'seq': self._event_seq, 'event': event_name, 'data': data})
        if event_name in self.callbacks:
            for callback in self.callbacks[event_name]:
                try:
                    callback(data)
                except Exception as e:
                    print(f"Error in callback {event_name}: {e}")

    # ------------------------------------------------------------------
    # Server admin controls
    # ------------------------------------------------------------------
    def kick_user(self, username):
        """Kick a connected user by username"""
        if username in self.users and self.server:
            address = self.users[username]['address']
            self.server.kick_client(address)
            return True
        return False

    def mute_user(self, username):
        """Prevent a user from sending broadcasts"""
        self.muted_from_broadcast.add(username)
        self._send(username, {'type': 'system_message',
                              'message': 'The server has muted you from broadcasting.'})

    def unmute_user(self, username):
        """Allow a user to send broadcasts again"""
        self.muted_from_broadcast.discard(username)
        self._send(username, {'type': 'system_message',
                              'message': 'The server has unmuted you — you can broadcast again.'})

    def set_server_master_key(self, key):
        """Set the server admin's master key as the 16th encryption layer"""
        self.server_master_key = key
        base_keys = self.encryption_key.split('|')
        # Keep only first 15 auto-generated keys, then append master key
        base_keys = base_keys[:15]
        if key:
            base_keys.append(key)
        self.encryption_key = '|'.join(base_keys)

    def regenerate_keys(self):
        """Re-generate all 15 random keys, keep the master key if set"""
        self.encryption_key = self._generate_multi_layer_key(15)
        if self.server_master_key:
            self.encryption_key = self.encryption_key + '|' + self.server_master_key

    def get_encryption_layers(self):
        """Return the list of encryption layer keys"""
        return self.encryption_key.split('|')

    def broadcast_as_server(self, message):
        """Send a broadcast from the server itself (not from any user)"""
        if not self.server:
            return
        encrypted = self._encrypt_with_layers(message)
        payload = {
            'type': 'broadcast_message',
            'from_user': '[SERVER]',
            'message': encrypted,
            'encrypted': True
        }
        self.server.broadcast(json.dumps(payload))
        self._trigger_callback('broadcast_sent', {'from_user': '[SERVER]'})


class FastConnect:
    """Client-side FastConnect"""
    
    def __init__(self, data_file='fc_data.json'):
        """Initialize FastConnect with data persistence"""
        self.data_file = data_file
        self.username = None
        self.real_name = None
        self.server_ip = None
        self.server_port = None
        self.client = None
        self.server = None
        self.friends = {}            # username -> {'real_name': name}
        self.encryption_key = None   # received from server on registration
        self.encryption_type = None
        self.callbacks = {}  # Callbacks for events
        self.last_error = None       # why the last connection attempt failed
        
        # Load existing data
        self.load_data()
    
    def load_data(self):
        """Load user data from JSON file"""
        try:
            if os.path.exists(self.data_file):
                with open(self.data_file, 'r') as f:
                    data = json.load(f)
                    self.username = data.get('username')
                    self.real_name = data.get('real_name', '')
                    self.server_ip = data.get('server_ip')
                    self.server_port = data.get('server_port')
            else:
                self._save_data()
        except Exception as e:
            print(f"Error loading data: {e}")
    
    def _save_data(self):
        """Save user data to JSON file"""
        try:
            data = {
                'username': self.username,
                'real_name': self.real_name,
                'server_ip': self.server_ip,
                'server_port': self.server_port
            }
            with open(self.data_file, 'w') as f:
                json.dump(data, f, indent=4)
        except Exception as e:
            print(f"Error saving data: {e}")
    
    def set_username(self, username):
        """Set the current user's username"""
        if not username or len(username) < 3:
            raise ValueError("Username must be at least 3 characters long")
        
        self.username = username
        self._save_data()
        self._trigger_callback('username_set', {'username': username})
        return True
    
    def set_real_name(self, real_name):
        """Set real name"""
        self.real_name = real_name
        self._save_data()
        self._trigger_callback('real_name_set', {'real_name': real_name})
    
    def get_username(self):
        """Get the current user's username"""
        return self.username
    
    def set_server_address(self, ip, port):
        """Set the server address"""
        self.server_ip = ip
        self.server_port = int(port)
        self._save_data()
        self._trigger_callback('server_set', {'ip': ip, 'port': port})
    
    def get_server_address(self):
        """Get the current server address"""
        return f"{self.server_ip}:{self.server_port}" if self.server_ip else None
    
    def start_local_server(self):
        """Start a local FastConnect server"""
        try:
            self.server = FastConnectServer(
                self.server_ip or '0.0.0.0', 
                self.server_port or 9999
            )
            if self.server.start():
                self._trigger_callback('server_started', {'port': self.server_port or 9999})
                return True
        except Exception as e:
            print(f"Error starting server: {e}")
        return False
    
    def stop_local_server(self):
        """Stop local server"""
        if self.server:
            self.server.stop()
            self._trigger_callback('server_stopped', {})
            return True
        return False
    
    def connect_to_server(self, host, port):
        """Connect to server as client"""
        try:
            self.client = Client(host, int(port))
            self.client.set_message_callback(self._handle_client_message)
            self.client.set_disconnect_callback(self._handle_disconnect)
            
            # Send registration
            if accounts_api.is_logged_in():
                # Prove who we are with a one-time ticket made for this encrypted connection.
                # The server never sees our session token or password.
                result = accounts_api.chat_ticket(self.client.binding)
                if not result.get('ok'):
                    raise ConnectionError(result.get('error') or 'Could not verify your login.')
                register_msg = {'type': 'register', 'ticket': result['ticket']}
                self.client.send(json.dumps(register_msg))
            elif self.username:
                register_msg = {
                    'type': 'register',
                    'username': self.username,
                    'real_name': self.real_name
                }
                self.client.send(json.dumps(register_msg))

            self._trigger_callback('connected_to_server', {'host': host, 'port': port})
            return True
        except Exception as e:
            print(f"Error connecting: {e}")
            if self.client:
                self.client.close()
                self.client = None
            self.last_error = str(e)
            self._trigger_callback('connection_error', {'error': str(e)})
            return False
    
    def disconnect_from_server(self):
        """Disconnect from server"""
        if self.client:
            self.client.close()
            self.client = None
            self._trigger_callback('disconnected_from_server', {})
            return True
        return False
    
    def _handle_client_message(self, message):
        """Handle incoming messages"""
        try:
            data = json.loads(message)
            msg_type = data.get('type')
            
            if msg_type == 'register_ack' and data.get('status') != 'success':
                self._trigger_callback('system_message', {
                    'message': f"The server refused the connection: {data.get('message', 'unknown reason')}"})
                self.disconnect_from_server()

            elif msg_type == 'register_ack':
                self.encryption_key = data.get('encryption_key')
                self.encryption_type = data.get('encryption_type')
                # Restore friends that the server already knows about
                server_friends = data.get('friends', {})
                self.friends = dict(server_friends)  # {username: {real_name: ...}}
                self._trigger_callback('registration_confirmed', {
                    'username': self.username,
                    'friends': self.friends
                })
            
            elif msg_type == 'friend_request_notification':
                from_user = data.get('from_user')
                self._trigger_callback('friend_request_received', {'from_user': from_user})
            
            elif msg_type == 'friend_accepted':
                friend_username = data.get('friend_username')
                friend_real_name = data.get('friend_real_name', '')
                self.friends[friend_username] = {'real_name': friend_real_name}
                if accounts_api.is_logged_in():
                    # Save our side of the friendship to our account (it counts once both sides have)
                    threading.Thread(target=accounts_api.add_friend, args=(friend_username,), daemon=True).start()
                self._trigger_callback('friend_accepted', {'friend': friend_username})
            
            elif msg_type == 'friend_declined':
                friend_username = data.get('friend_username')
                self._trigger_callback('friend_declined', {'friend': friend_username})
            
            elif msg_type == 'private_message':
                from_user = data.get('from_user')
                message_text = data.get('message')
                if data.get('encrypted') and self.encryption_key:
                    message_text = self._decrypt_with_layers(message_text)
                self._trigger_callback('private_message_received', {'from': from_user, 'message': message_text})

            elif msg_type == 'broadcast_message':
                from_user = data.get('from_user')
                broadcast_msg = data.get('message')
                if data.get('encrypted') and self.encryption_key:
                    broadcast_msg = self._decrypt_with_layers(broadcast_msg)
                self._trigger_callback('broadcast_received', {'from': from_user, 'message': broadcast_msg})
            
            elif msg_type == 'users_list':
                users = data.get('users', [])
                self._trigger_callback('users_list_received', {'users': users})
            
            elif msg_type == 'system_message':
                system_msg = data.get('message')
                self._trigger_callback('system_message', {'message': system_msg})
            
        except Exception as e:
            print(f"Error handling message: {e}")
    
    def _decrypt_with_layers(self, message):
        """Decrypt a message through the 15 Vigenère layers in reverse order"""
        if not self.encryption_key:
            return message
        keys = self.encryption_key.split('|')
        result = message
        for key in reversed(keys):
            try:
                result = Encription.decrypt({
                    'type': Encription.VIGENERE,
                    'text': result,
                    'params': {'key': key}
                })
            except Exception:
                pass
        return result

    def _handle_disconnect(self, reason):
        """Handle disconnect"""
        self._trigger_callback('disconnected', {'reason': reason})
    
    def send_friend_request(self, to_user):
        """Send friend request"""
        if self.client:
            msg = {
                'type': 'friend_request',
                'from_user': self.username,
                'to_user': to_user
            }
            self.client.send(json.dumps(msg))
            self._trigger_callback('friend_request_sent', {'to': to_user})
    
    def respond_to_friend_request(self, from_user, accepted):
        """Respond to friend request"""
        if self.client:
            msg = {
                'type': 'friend_response',
                'from_user': from_user,
                'to_user': self.username,
                'accepted': accepted
            }
            self.client.send(json.dumps(msg))
    
    def send_private_message(self, to_user, message):
        """Send private message to friend"""
        if self.client:
            msg = {
                'type': 'private_message',
                'from_user': self.username,
                'to_user': to_user,
                'message': message
            }
            self.client.send(json.dumps(msg))
            self._trigger_callback('private_message_sent', {'to': to_user, 'message': message})
    
    def send_broadcast(self, message):
        """Send broadcast message to all users"""
        if self.client:
            msg = {
                'type': 'broadcast',
                'from_user': self.username,
                'message': message
            }
            self.client.send(json.dumps(msg))
            self._trigger_callback('broadcast_sent', {'message': message})
    
    def request_users_list(self):
        """Request list of online users"""
        if self.client:
            msg = {'type': 'list_users'}
            self.client.send(json.dumps(msg))
    
    def register_callback(self, event_name, callback):
        """Register event callback"""
        if event_name not in self.callbacks:
            self.callbacks[event_name] = []
        self.callbacks[event_name].append(callback)
    
    def _trigger_callback(self, event_name, data):
        """Trigger callbacks"""
        if event_name in self.callbacks:
            for callback in self.callbacks[event_name]:
                try:
                    callback(data)
                except Exception as e:
                    print(f"Error in callback: {e}")
    
    def get_status(self):
        """Get current status"""
        return {
            'username': self.username,
            'real_name': self.real_name,
            'server_running': self.server is not None,
            'connected_to_server': self.client is not None and self.client.running if self.client else False,
            'encryption_enabled': True
        }


if __name__ == '__main__':
    fc = FastConnect()
    fc.set_username('TestUser')
    fc.set_real_name('Test User')
    print(f"Status: {fc.get_status()}")