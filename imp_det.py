import cv2
import numpy as np
from ultralytics import YOLO
import datetime
import time
import json
import hashlib
import hmac
import requests
import serial
import socket
import logging
from enum import Enum
from collections import defaultdict
import threading
from cryptography.fernet import Fernet
import sqlite3
from dataclasses import dataclass
from typing import Optional, Dict, List
import os

# Configure logging for safety and audit trail
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('traffic_control.log'),
        logging.StreamHandler()
    ]
)

class SignalState(Enum):
    NORTH_SOUTH_GREEN = 0
    EAST_WEST_GREEN = 1
    ALL_RED = 2
    EMERGENCY_OVERRIDE = 3
    MAINTENANCE_MODE = 4

class AuthorizationLevel(Enum):
    UNAUTHORIZED = 0
    OPERATOR = 1
    SUPERVISOR = 2
    EMERGENCY = 3
    MAINTENANCE = 4

@dataclass
class TrafficCommand:
    """Secure command structure for traffic signal control"""
    command_id: str
    timestamp: float
    signal_id: str
    new_state: SignalState
    duration: int
    authorization_level: AuthorizationLevel
    user_id: str
    signature: str
    emergency: bool = False

class SecurityManager:
    """Handles all security, authentication, and authorization"""
    
    def __init__(self, config_file='security_config.json'):
        self.config_file = config_file
        self.load_security_config()
        self.active_sessions = {}
        self.command_log = []
        
        # Initialize database for audit trail
        self.init_audit_database()
        
    def load_security_config(self):
        """Load security configuration"""
        try:
            with open(self.config_file, 'r') as f:
                config = json.load(f)
                self.secret_key = config['secret_key'].encode()
                self.authorized_users = config['authorized_users']
                self.api_keys = config['api_keys']
                self.encryption_key = config['encryption_key'].encode()
                self.cipher = Fernet(self.encryption_key)
        except FileNotFoundError:
            # Create default security config for demo
            self.create_default_security_config()
            
    def create_default_security_config(self):
        """Create default security configuration for demo"""
        config = {
            "secret_key": "your_secret_key_change_this_in_production",
            "encryption_key": Fernet.generate_key().decode(),
            "authorized_users": {
                "traffic_operator_001": {
                    "level": "SUPERVISOR",
                    "permissions": ["signal_control", "emergency_override"],
                    "password_hash": self.hash_password("secure_password_123")
                },
                "emergency_service_001": {
                    "level": "EMERGENCY", 
                    "permissions": ["emergency_override", "priority_control"],
                    "password_hash": self.hash_password("emergency_pass_456")
                }
            },
            "api_keys": {
                "traffic_management_system": "api_key_traffic_mgmt_001",
                "emergency_services": "api_key_emergency_001"
            }
        }
        
        with open(self.config_file, 'w') as f:
            json.dump(config, f, indent=2)
        
        print("🔒 Default security configuration created!")
        print("⚠️  CHANGE DEFAULT PASSWORDS IN PRODUCTION!")
        
        self.load_security_config()
    
    def hash_password(self, password: str) -> str:
        """Secure password hashing"""
        salt = os.urandom(32)
        pwdhash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
        return salt.hex() + pwdhash.hex()
    
    def verify_password(self, password: str, hash: str) -> bool:
        """Verify password against hash"""
        try:
            salt = bytes.fromhex(hash[:64])
            stored_hash = hash[64:]
            pwdhash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
            return stored_hash == pwdhash.hex()
        except:
            return False
    
    def authenticate_user(self, username: str, password: str) -> Optional[AuthorizationLevel]:
        """Authenticate user and return authorization level"""
        if username in self.authorized_users:
            user = self.authorized_users[username]
            if self.verify_password(password, user['password_hash']):
                level = AuthorizationLevel[user['level']]
                self.log_event(f"User {username} authenticated with level {level.name}")
                return level
        
        self.log_event(f"Failed authentication attempt for user {username}")
        return None
    
    def create_command_signature(self, command: TrafficCommand) -> str:
        """Create HMAC signature for command verification"""
        message = f"{command.command_id}:{command.timestamp}:{command.signal_id}:{command.new_state.name}:{command.user_id}"
        signature = hmac.new(self.secret_key, message.encode(), hashlib.sha256).hexdigest()
        return signature
    
    def verify_command_signature(self, command: TrafficCommand) -> bool:
        """Verify command signature for integrity"""
        expected_signature = self.create_command_signature(command)
        return hmac.compare_digest(command.signature, expected_signature)
    
    def authorize_command(self, command: TrafficCommand, user_auth_level: AuthorizationLevel) -> bool:
        """Check if user is authorized to execute command"""
        
        # Emergency commands require EMERGENCY level
        if command.emergency and user_auth_level != AuthorizationLevel.EMERGENCY:
            self.log_event(f"UNAUTHORIZED: Emergency command attempted by user with level {user_auth_level.name}")
            return False
        
        # Maintenance commands require MAINTENANCE level
        if command.new_state == SignalState.MAINTENANCE_MODE and user_auth_level != AuthorizationLevel.MAINTENANCE:
            self.log_event(f"UNAUTHORIZED: Maintenance command attempted by user with level {user_auth_level.name}")
            return False
        
        # Normal signal control requires at least OPERATOR level
        if user_auth_level.value < AuthorizationLevel.OPERATOR.value:
            self.log_event(f"UNAUTHORIZED: Signal control attempted by unauthorized user")
            return False
        
        self.log_event(f"AUTHORIZED: Command {command.command_id} authorized for user {command.user_id}")
        return True
    
    def init_audit_database(self):
        """Initialize audit trail database"""
        self.conn = sqlite3.connect('traffic_audit.db', check_same_thread=False)
        cursor = self.conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                event_type TEXT,
                user_id TEXT,
                command_id TEXT,
                signal_id TEXT,
                old_state TEXT,
                new_state TEXT,
                authorization_level TEXT,
                success BOOLEAN,
                details TEXT
            )
        ''')
        self.conn.commit()
    
    def log_event(self, message: str, **kwargs):
        """Log security event with audit trail"""
        timestamp = time.time()
        logging.info(message)
        
        # Store in database
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO audit_log (timestamp, event_type, user_id, command_id, 
                                 signal_id, old_state, new_state, authorization_level, 
                                 success, details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            timestamp,
            kwargs.get('event_type', 'GENERAL'),
            kwargs.get('user_id', ''),
            kwargs.get('command_id', ''),
            kwargs.get('signal_id', ''),
            kwargs.get('old_state', ''),
            kwargs.get('new_state', ''),
            kwargs.get('authorization_level', ''),
            kwargs.get('success', True),
            message
        ))
        self.conn.commit()

class TrafficSignalHardwareInterface:
    """Interface to actual traffic signal hardware"""
    
    def __init__(self, config_file='hardware_config.json'):
        self.config_file = config_file
        self.load_hardware_config()
        self.connections = {}
        self.signal_states = {}
        
    def load_hardware_config(self):
        """Load hardware interface configuration"""
        try:
            with open(self.config_file, 'r') as f:
                self.config = json.load(f)
        except FileNotFoundError:
            # Create default hardware config
            self.config = {
                "signals": {
                    "intersection_001": {
                        "type": "RS485_MODBUS",
                        "address": "192.168.1.100",
                        "port": 502,
                        "device_id": 1,
                        "backup_connection": {
                            "type": "SERIAL",
                            "port": "COM3",
                            "baudrate": 9600
                        }
                    },
                    "intersection_002": {
                        "type": "TCP_IP",
                        "address": "192.168.1.101", 
                        "port": 8080,
                        "protocol": "NTCIP"
                    }
                },
                "safety_parameters": {
                    "min_all_red_time": 5,
                    "max_green_extension": 60,
                    "pedestrian_clearance_time": 15,
                    "yellow_time": 4
                }
            }
            
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
            
            print("🔧 Default hardware configuration created!")
    
    def connect_to_signal(self, signal_id: str) -> bool:
        """Establish connection to traffic signal hardware"""
        if signal_id not in self.config['signals']:
            logging.error(f"Signal {signal_id} not found in configuration")
            return False
        
        signal_config = self.config['signals'][signal_id]
        
        try:
            if signal_config['type'] == 'RS485_MODBUS':
                # Connect via Modbus TCP
                import socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((signal_config['address'], signal_config['port']))
                self.connections[signal_id] = {
                    'type': 'modbus',
                    'socket': sock,
                    'device_id': signal_config['device_id']
                }
                
            elif signal_config['type'] == 'TCP_IP':
                # Connect via TCP/IP (NTCIP protocol)
                import socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((signal_config['address'], signal_config['port']))
                self.connections[signal_id] = {
                    'type': 'ntcip',
                    'socket': sock
                }
                
            elif signal_config['type'] == 'SERIAL':
                # Connect via Serial (RS232/RS485)
                import serial
                ser = serial.Serial(
                    signal_config['port'], 
                    signal_config['baudrate'],
                    timeout=1
                )
                self.connections[signal_id] = {
                    'type': 'serial',
                    'connection': ser
                }
            
            logging.info(f"Successfully connected to signal {signal_id}")
            return True
            
        except Exception as e:
            logging.error(f"Failed to connect to signal {signal_id}: {e}")
            
            # Try backup connection if available
            if 'backup_connection' in signal_config:
                try:
                    backup = signal_config['backup_connection']
                    if backup['type'] == 'SERIAL':
                        import serial
                        ser = serial.Serial(backup['port'], backup['baudrate'], timeout=1)
                        self.connections[signal_id] = {
                            'type': 'serial_backup',
                            'connection': ser
                        }
                        logging.info(f"Connected to signal {signal_id} via backup connection")
                        return True
                except Exception as backup_error:
                    logging.error(f"Backup connection also failed: {backup_error}")
            
            return False
    
    def send_signal_command(self, signal_id: str, new_state: SignalState, duration: int = 30) -> bool:
        """Send command to change traffic signal state"""
        if signal_id not in self.connections:
            if not self.connect_to_signal(signal_id):
                return False
        
        connection = self.connections[signal_id]
        
        try:
            if connection['type'] == 'modbus':
                # Send Modbus command
                command = self.create_modbus_command(new_state, duration, connection['device_id'])
                connection['socket'].send(command)
                response = connection['socket'].recv(1024)
                success = self.verify_modbus_response(response)
                
            elif connection['type'] == 'ntcip':
                # Send NTCIP command
                command = self.create_ntcip_command(new_state, duration)
                connection['socket'].send(command.encode())
                response = connection['socket'].recv(1024).decode()
                success = self.verify_ntcip_response(response)
                
            elif connection['type'] in ['serial', 'serial_backup']:
                # Send serial command
                command = self.create_serial_command(new_state, duration)
                connection['connection'].write(command)
                response = connection['connection'].readline()
                success = self.verify_serial_response(response)
            
            if success:
                self.signal_states[signal_id] = {
                    'state': new_state,
                    'timestamp': time.time(),
                    'duration': duration
                }
                logging.info(f"Signal {signal_id} successfully changed to {new_state.name}")
            else:
                logging.error(f"Failed to change signal {signal_id} to {new_state.name}")
            
            return success
            
        except Exception as e:
            logging.error(f"Error sending command to signal {signal_id}: {e}")
            return False
    
    def create_modbus_command(self, state: SignalState, duration: int, device_id: int) -> bytes:
        """Create Modbus RTU command for traffic signal"""
        # Modbus function code 16 (Write Multiple Registers)
        function_code = 0x10
        starting_address = 0x0001  # Signal state register
        num_registers = 0x0002     # State and duration
        byte_count = 0x04
        
        # Convert state to register value
        state_mapping = {
            SignalState.NORTH_SOUTH_GREEN: 0x0001,
            SignalState.EAST_WEST_GREEN: 0x0002,
            SignalState.ALL_RED: 0x0003,
            SignalState.EMERGENCY_OVERRIDE: 0x0004,
            SignalState.MAINTENANCE_MODE: 0x0005
        }
        
        state_value = state_mapping.get(state, 0x0003)  # Default to ALL_RED for safety
        duration_value = min(duration, 300)  # Max 5 minutes for safety
        
        # Build command
        command = bytearray([
            device_id,
            function_code,
            (starting_address >> 8) & 0xFF,
            starting_address & 0xFF,
            (num_registers >> 8) & 0xFF,
            num_registers & 0xFF,
            byte_count,
            (state_value >> 8) & 0xFF,
            state_value & 0xFF,
            (duration_value >> 8) & 0xFF,
            duration_value & 0xFF
        ])
        
        # Calculate CRC
        crc = self.calculate_modbus_crc(command)
        command.extend(crc.to_bytes(2, byteorder='little'))
        
        return bytes(command)
    
    def calculate_modbus_crc(self, data: bytearray) -> int:
        """Calculate Modbus RTU CRC-16"""
        crc = 0xFFFF
        for byte in data:
            crc ^= byte
            for _ in range(8):
                if crc & 0x0001:
                    crc >>= 1
                    crc ^= 0xA001
                else:
                    crc >>= 1
        return crc
    
    def create_ntcip_command(self, state: SignalState, duration: int) -> str:
        """Create NTCIP command for traffic signal"""
        # NTCIP 1202 standard command structure
        state_mapping = {
            SignalState.NORTH_SOUTH_GREEN: "1",
            SignalState.EAST_WEST_GREEN: "2", 
            SignalState.ALL_RED: "3",
            SignalState.EMERGENCY_OVERRIDE: "4",
            SignalState.MAINTENANCE_MODE: "5"
        }
        
        phase = state_mapping.get(state, "3")
        command = f"SET signalPhase {phase} duration {duration}\r\n"
        return command
    
    def create_serial_command(self, state: SignalState, duration: int) -> bytes:
        """Create serial command for traffic signal"""
        # Custom protocol for serial communication
        state_codes = {
            SignalState.NORTH_SOUTH_GREEN: b'\x01',
            SignalState.EAST_WEST_GREEN: b'\x02',
            SignalState.ALL_RED: b'\x03',
            SignalState.EMERGENCY_OVERRIDE: b'\x04',
            SignalState.MAINTENANCE_MODE: b'\x05'
        }
        
        state_code = state_codes.get(state, b'\x03')
        duration_bytes = duration.to_bytes(2, byteorder='big')
        
        # Command format: START + STATE + DURATION + CHECKSUM + END
        command = b'\x02' + state_code + duration_bytes  # STX + State + Duration
        checksum = sum(command[1:]) & 0xFF
        command += checksum.to_bytes(1, byteorder='big') + b'\x03'  # Checksum + ETX
        
        return command
    
    def verify_modbus_response(self, response: bytes) -> bool:
        """Verify Modbus response"""
        if len(response) < 6:
            return False
        
        # Check for exception response
        if response[1] & 0x80:
            exception_code = response[2]
            logging.error(f"Modbus exception: {exception_code}")
            return False
        
        # Verify CRC
        data = response[:-2]
        received_crc = int.from_bytes(response[-2:], byteorder='little')
        calculated_crc = self.calculate_modbus_crc(bytearray(data))
        
        return received_crc == calculated_crc
    
    def verify_ntcip_response(self, response: str) -> bool:
        """Verify NTCIP response"""
        return "ACK" in response or "OK" in response
    
    def verify_serial_response(self, response: bytes) -> bool:
        """Verify serial response"""
        return b'ACK' in response or b'OK' in response
    
    def get_signal_status(self, signal_id: str) -> Optional[Dict]:
        """Get current status of traffic signal"""
        if signal_id in self.signal_states:
            return self.signal_states[signal_id]
        return None
    
    def emergency_all_red(self, signal_id: str) -> bool:
        """Emergency command to set all signals to red"""
        logging.warning(f"EMERGENCY: Setting signal {signal_id} to ALL RED")
        return self.send_signal_command(signal_id, SignalState.ALL_RED, 60)

class RealTrafficController:
    """Main controller that integrates detection with real traffic signal control"""
    
    def __init__(self, video_source=0, signal_ids=['intersection_001']):
        # Initialize components
        self.security_manager = SecurityManager()
        self.hardware_interface = TrafficSignalHardwareInterface()
        self.signal_ids = signal_ids
        
        # Vehicle detection setup (from your original code)
        self.model = YOLO("yolov8s.pt")
        self.conf_threshold = 0.25
        self.iou_threshold = 0.45
        self.track_history = defaultdict(lambda: [])
        
        # Video setup
        self.video_source = video_source
        self.cap = None
        
        # Traffic management
        self.vehicle_threshold = 30
        self.current_states = {}
        self.traffic_data = {}
        
        # Initialize traffic data for each signal
        for signal_id in signal_ids:
            self.traffic_data[signal_id] = {
                'north': {'cars': 0, 'people': 0},
                'south': {'cars': 0, 'people': 0},
                'east': {'cars': 0, 'people': 0},
                'west': {'cars': 0, 'people': 0}
            }
            self.current_states[signal_id] = SignalState.ALL_RED
        
        # User authentication
        self.current_user = None
        self.auth_level = AuthorizationLevel.UNAUTHORIZED
        
        print("🚦 Real Traffic Controller initialized")
        print("🔒 Security systems active")
        print("⚠️  SAFETY WARNING: This system can control real traffic signals!")
    
    def authenticate(self, username: str, password: str) -> bool:
        """Authenticate user for system access"""
        auth_level = self.security_manager.authenticate_user(username, password)
        if auth_level:
            self.current_user = username
            self.auth_level = auth_level
            print(f"✅ User {username} authenticated with level {auth_level.name}")
            return True
        else:
            print("❌ Authentication failed")
            return False
    
    def execute_signal_change(self, signal_id: str, new_state: SignalState, duration: int = 30, emergency: bool = False) -> bool:
        """Execute traffic signal change with full authorization and safety checks"""
        
        if self.auth_level == AuthorizationLevel.UNAUTHORIZED:
            print("❌ UNAUTHORIZED: Please authenticate first")
            return False
        
        # Create secure command
        command = TrafficCommand(
            command_id=f"cmd_{int(time.time())}_{hash(signal_id)}",
            timestamp=time.time(),
            signal_id=signal_id,
            new_state=new_state,
            duration=duration,
            authorization_level=self.auth_level,
            user_id=self.current_user,
            signature="",  # Will be filled by create_command_signature
            emergency=emergency
        )
        
        # Create signature
        command.signature = self.security_manager.create_command_signature(command)
        
        # Verify signature
        if not self.security_manager.verify_command_signature(command):
            print("❌ SECURITY ERROR: Command signature verification failed")
            return False
        
        # Check authorization
        if not self.security_manager.authorize_command(command, self.auth_level):
            print("❌ AUTHORIZATION DENIED: Insufficient privileges")
            return False
        
        # Log command attempt
        self.security_manager.log_event(
            f"Signal change command initiated for {signal_id}",
            event_type="SIGNAL_COMMAND",
            user_id=self.current_user,
            command_id=command.command_id,
            signal_id=signal_id,
            old_state=self.current_states.get(signal_id, SignalState.ALL_RED).name,
            new_state=new_state.name,
            authorization_level=self.auth_level.name,
            success=False  # Will update after execution
        )
        
        # Safety checks
        if not self.perform_safety_checks(signal_id, new_state):
            print("❌ SAFETY CHECK FAILED: Command rejected")
            return False
        
        # Execute hardware command
        success = self.hardware_interface.send_signal_command(signal_id, new_state, duration)
        
        if success:
            self.current_states[signal_id] = new_state
            print(f"✅ Signal {signal_id} changed to {new_state.name} for {duration} seconds")
            
            # Update audit log
            self.security_manager.log_event(
                f"Signal change successful for {signal_id}",
                event_type="SIGNAL_COMMAND",
                user_id=self.current_user,
                command_id=command.command_id,
                signal_id=signal_id,
                old_state=self.current_states.get(signal_id, SignalState.ALL_RED).name,
                new_state=new_state.name,
                authorization_level=self.auth_level.name,
                success=True
            )
        else:
            print(f"❌ Failed to change signal {signal_id}")
        
        return success
    
    def perform_safety_checks(self, signal_id: str, new_state: SignalState) -> bool:
        """Perform safety checks before signal change"""
        
        # Check minimum all-red time
        if signal_id in self.current_states:
            current_state = self.current_states[signal_id]
            # Add logic to ensure minimum all-red time between conflicting phases
        
        # Check for conflicting signals (in multi-intersection systems)
        # Add logic to prevent conflicting green phases
        
        # Check emergency override conditions
        if new_state == SignalState.EMERGENCY_OVERRIDE:
            # Ensure emergency vehicle detection or manual emergency activation
            pass
        
        # All safety checks passed
        return True
    
    def process_traffic_detection(self):
        """Process traffic detection and trigger signal changes"""
        
        if not self.cap:
            self.cap = cv2.VideoCapture(self.video_source)
        
        while True:
            ret, frame = self.cap.read()
            if not ret:
                break
            
            # Perform detection (simplified from your original code)
            results = self.model.track(frame, conf=self.conf_threshold, persist=True)
            
            vehicle_count = 0
            people_count = 0
            
            if results[0].boxes is not None:
                for box in results[0].boxes:
                    class_id = int(box.cls[0])
                    if class_id == 0:  # Person
                        people_count += 1
                    elif class_id in [1, 2, 3, 5, 7]:  # Vehicles
                        vehicle_count += 1
            
            # Update traffic data (simplified - in real system, would track by direction)
            for signal_id in self.signal_ids:
                self.traffic_data[signal_id]['north']['cars'] = vehicle_count
                self.traffic_data[signal_id]['north']['people'] = people_count
                
                # Check threshold
                if vehicle_count >= self.vehicle_threshold:
                    print(f"🚨 THRESHOLD REACHED: {vehicle_count} vehicles detected at {signal_id}")
                    
                    # Auto-change signal if authorized
                    if self.auth_level.value >= AuthorizationLevel.OPERATOR.value:
                        current_state = self.current_states.get(signal_id, SignalState.ALL_RED)
                        
                        # Simple logic: alternate between N-S and E-W
                        if current_state != SignalState.NORTH_SOUTH_GREEN:
                            new_state = SignalState.NORTH_SOUTH_GREEN
                        else:
                            new_state = SignalState.EAST_WEST_GREEN
                        
                        self.execute_signal_change(signal_id, new_state, 45)
            
            # Display (optional)
            cv2.imshow('Traffic Detection', frame)
            if cv2.waitKey(1) & 0xFF == ord('q'):
                break
        
        self.cap.release()
        cv2.destroyAllWindows()
    
    def emergency_override(self, signal_id: str, direction: str = "north_south"):
        """Emergency override for priority vehicles"""
        if self.auth_level != AuthorizationLevel.EMERGENCY:
            print("❌ EMERGENCY OVERRIDE DENIED: Emergency authorization required")
            return False
        
        print(f"🚨 EMERGENCY OVERRIDE ACTIVATED for {signal_id}")
        
        if direction == "north_south":
            return self.execute_signal_change(signal_id, SignalState.NORTH_SOUTH_GREEN, 60, emergency=True)
        else:
            return self.execute_signal_change(signal_id, SignalState.EAST_WEST_GREEN, 60, emergency=True)
    
    def manual_signal_control(self):
        """Manual control interface for authorized operators"""
        
        if self.auth_level == AuthorizationLevel.UNAUTHORIZED:
            print("❌ Please authenticate first")
            return
        
        print("\n🚦 Manual Signal Control Interface")
        print("Available commands:")
        print("1. Change signal state")
        print("2. Emergency override") 
        print("3. View signal status")
        print("4. Emergency all-red")
        print("5. Exit")
        
        while True:
            choice = input("\nEnter command (1-5): ").strip()
            
            if choice == "1":
                signal_id = input("Enter signal ID: ").strip()
                if signal_id not in self.signal_ids:
                    print("❌ Invalid signal ID")
                    continue
                
                print("Available states:")
                print("1. North-South Green")
                print("2. East-West Green") 
                print("3. All Red")
                
                state_choice = input("Select state (1-3): ").strip()
                state_map = {
                    "1": SignalState.NORTH_SOUTH_GREEN,
                    "2": SignalState.EAST_WEST_GREEN,
                    "3": SignalState.ALL_RED
                }
                
                if state_choice in state_map:
                    duration = int(input("Duration (seconds, max 300): ") or "30")
                    duration = min(duration, 300)  # Safety limit
                    
                    self.execute_signal_change(signal_id, state_map[state_choice], duration)
                else:
                    print("❌ Invalid state selection")
            
            elif choice == "2":
                if self.auth_level != AuthorizationLevel.EMERGENCY:
                    print("❌ Emergency authorization required")
                    continue