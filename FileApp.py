#!/usr/bin/env python3

import sys
import os
import socket
import ipaddress
import threading
import pickle
import time
import math

PACKET_LEN = 1024


def terminate(signal, frame):
    sys.exit(0)


def log(message, type="std"):
    if type == "std":
        print(">>>", message)
    elif type == "ft":
        print("<", message, ">")


def is_ip(ip_address):
    try:
        if type(ipaddress.ip_address(ip_address)) is not ipaddress.IPv4Address:
            raise
    except:
        return False
    return True


def is_port(port):
    if port < 1024 or port > 65535:
        return False
    return True


def UDP_flags_to_header(start, end, flag):
    num = int(start) * 16 + int(end) * 8 + flag
    o = num.to_bytes(1, "big")
    return o


def UDP_header_to_flags(input):
    byte = format(input, '08b')
    return int(byte[-5:-4], 2), int(byte[-4:-3], 2), int(byte[-3:], 2)


def best_effort(function, parameters=()):
    if function(parameters, action="setup") == 0:  # setup
        return 0

    start_time = time.time()
    if function(parameters, action="attempt") == 0:  # attempt first time
        return 0

    while (time.time() - start_time < 0.5):  # wait 500ms for verification
        if function(parameters, action="verify") == 1:
            return 1
        time.sleep(0)

    for _ in range(2):  # attempt two more times, sleeping in between
        function(parameters, action="attempt")
        time.sleep(0.5)
        verification = function(parameters, action="verify")
        if verification == 1:
            return 1
        elif verification == 0:
            return 0

    return 2  # timeout


class client:
    def __init__(self, name, server_ip, server_port, client_udp_port, client_tcp_port):
        if len(name) > 32:
            log(f"[setup failed: '{name}' is longer than 32 characters]")
            sys.exit()

        if not is_ip(server_ip):
            log(f"[setup failed: '{server_ip}' is not a valid IPv4 address for argument <server-ip>]")
            sys.exit()

        if not is_port(server_port):
            log(f"[setup failed: <server-port> '{server_port}' is not between 1024 and 65535]")
            sys.exit()

        if not is_port(client_udp_port):
            log(f"[setup failed: <client-udp-port> '{client_udp_port}' is not between 1024 and 65535]")
            sys.exit()

        if not is_port(client_tcp_port):
            log(f"[setup failed: <client-tcp-port> '{client_tcp_port}' is not between 1024 and 65535]")
            sys.exit()

        self.server_ip = server_ip
        self.server_port = server_port

        self.name = name
        self.client_udp_port = client_udp_port
        self.client_tcp_port = client_tcp_port

        self.directory = ""

        self.files = 0
        self.files_lock = threading.RLock()

        self.messages = []
        self.messages_lock = threading.RLock()

        self.begin_loop = False

    def UDP_listen(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.bind(("", self.client_udp_port))
        except:
            log(f"[UDP port {self.client_udp_port} unavailable.]")
            sys.exit(0)

        data_combined = bytearray(b'')
        while (True):
            try:
                data = s.recv(PACKET_LEN)
                start, end, flag = UDP_header_to_flags(data[0])
                match flag:
                    case 0:  # ack from server
                        with self.messages_lock:
                            self.messages.append("ack")
                    case 1:  # accept from server
                        with self.messages_lock:
                            self.messages.append("accept")
                    case 2:  # reject from server
                        with self.messages_lock:
                            self.messages.append("reject")
                    case 5:  # table from server
                        if start:
                            data_combined = bytearray(b'')

                        data_combined.extend(bytes(data[1:]))

                        if end:
                            try:
                                result = pickle.loads(data_combined)
                                self.send_to_server(0, self.name)
                                with self.files_lock:
                                    self.files = result
                                    for file, address in self.files.items(): # update ambiguous TCP IPs
                                        if address[0] == "127.0.0.1":
                                            self.files[file] = (self.server_ip, address[1])
                                if self.begin_loop:
                                    print("[Client table updated.]")
                                    print(">>> ", end="", flush=True)
                            except:
                                pass
            except:
                pass

    def check_messages(self, message):
        with self.messages_lock:
            if message in self.messages:
                index = self.messages.index(message)
                self.messages.pop(index)
                return 1
        return 0

    def send_to_server(self, flag, data):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            message = UDP_flags_to_header(start=True, end=True, flag=flag) + pickle.dumps(data)
            s.sendto(message, (self.server_ip, self.server_port))
            return 1
        except:
            return 0

    def register(self, parameters, action):
        match action:
            case "attempt":
                self.send_to_server(3, (self.name, self.client_udp_port, self.client_tcp_port))
            case "verify":
                if self.check_messages("accept"):
                    log("[Welcome, You are registered.]")
                    return 1
                elif self.check_messages("reject"):
                    log("[Could not register with server.]")
                    sys.exit(0)

    def update_table(self, parameters, action):
        match action:
            case "verify":
                with self.files_lock:
                    if self.files != 0:
                        log("[Client table updated.]")
                        return 1

    def TCP_listen(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("", self.client_tcp_port))
            except:
                log(f"[TCP port {self.client_tcp_port} unavailable.]")
                sys.exit(0)
            s.listen()
            while True:
                connection, address = s.accept()
                with connection:
                    print()
                    log(f"Accepting connection request from {address}", type="ft")
                    try:
                        filename = pickle.loads(connection.recv(PACKET_LEN))
                        log(f"Transferring {filename}", type="ft")

                    except:
                        log(f"No file requested from {address}", type="ft")
                        break
                    try:
                        with open(self.directory + "/" + filename, "rb") as file:
                            while True:
                                file_bytes = file.read(PACKET_LEN)
                                if not file_bytes:
                                    break
                                connection.send(file_bytes)
                        log(f"{filename} transferred successfully!", type="ft")
                    except:
                        log(f"File transfer failed", type="ft")
                log(f"Connection with client closed", type="ft")
                print(">>> ", end="", flush=True)

    def valid_args(self, options):
        args = options.split(" ")
        if args[0] in ("setdir", "offer", "list", "request", "dereg"):
            return args
        else:
            log(f"[Unknown command {args[0]}]")
            return 0

    def set_dir(self, path):
        if not os.path.isdir(path):
            log(f"[setdir failed: '{path}' does not exist. <dir> must be a path relative to FileApp.py.py]")
            return 0
        if "/" in path:
            log(f"[setdir failed: <dir> may not contain a '/'.]")
            return 0
        if self.directory:
            log("[setdir failed: directory already set.]")
            return 0
        self.directory = path
        log(f"[Successfully set '{path}' as the directory for searching offered files.]")
        return 1

    def offer_files(self, parameters, action):
        match action:
            case "setup":
                if not self.directory:
                    log("[offer failed: no directory set]")
                    return 0
                if len(parameters) > 10:
                    log("[offer failed: no more than 10 files may be offered at once]")
                    return 0
                for file in parameters:
                    if "/" in file:
                        log(f"[offer failed: '{file}' may not be in subdirectory")
                    if not os.path.isfile(self.directory + "/" + file):
                        log(f"[offer failed: '{file}' is not in {self.directory}]")
                        return 0
                    if len(file) > 32:
                        log(f"[offer failed: '{file}' is longer than 32 characters]")
                        return 0
            case "attempt":
                self.send_to_server(6, (self.name, parameters))
            case "verify":
                if self.check_messages("ack"):
                    log("[Offer message received by server.]")
                    return 1

    def list_files(self):
        with self.files_lock:
            if not self.files:
                log("[No files available for download at the moment.]")
                return 0
            table = [["FILENAME", "OWNER", "IP ADDRESS", "TCP PORT"]]
            table.extend([[key[0], key[1], value[0], str(value[1])] for key, value in self.files.items()])
            columns = [[table[row][col] for row in range(len(table))] for col in range(len(table[0]))]
            col_width = [max([len(element) for element in column]) + 3 for column in columns]

            for row in table:
                for col, element in enumerate(row):
                    print(element + (col_width[col] - len(element)) * " ", end="")
                print()
        return 1

    def request_file(self, file_name, client_name):
        address = ()
        with self.files_lock:
            if (file_name, client_name) not in self.files or self.name == client_name:
                log("Invalid Request", type="ft")
                return 0
            address = self.files[(file_name, client_name)]
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.connect(address)
                log(f"Connection with client {client_name} established.", type="ft")

                request = pickle.dumps(file_name)
                s.send(request)

                with open(file_name, "wb") as file:
                    log(f"Downloading {file_name}", type="ft")
                    while data := s.recv(PACKET_LEN):
                        file.write(data)
                log(f"{file_name} downloaded successfully!", type="ft")
            except:
                log(f"Connection with {client_name} couldn't be established", type="ft")
                return 0
        log(f"Connection with client {client_name} closed", type="ft")
        return 1

    def deregister(self, parameters, action):
        match action:
            case "attempt":
                self.send_to_server(4, self.name)
            case "verify":
                if self.check_messages("ack"):
                    log("[You are Offline. Bye.]")
                    return 1

    def start(self):
        UDP_thread = threading.Thread(target=self.UDP_listen, daemon=True)
        UDP_thread.start()

        if best_effort(self.register) == 2:
            log("[Could not register with server.]")
            sys.exit(0)

        if best_effort(self.update_table) == 2:
            log("[Could not update file table.]")
            sys.exit(0)

        TCP_thread = threading.Thread(target=self.TCP_listen, daemon=True)
        TCP_thread.start()

        log("-------------------------------")
        log("Welcome to FileApp.py.")
        log("Commands are stated below.")
        log("Options may not contain spaces.")
        log("    setdir <dir>")
        log("    offer <filename1> ...")
        log("    list")
        log("    request <filename> <client>")
        log("    dereg")
        log("-------------------------------")

        self.begin_loop = True
        while True:
            try:
                if args := self.valid_args(input(">>> ")):
                    match args[0]:
                        case "setdir":
                            if len(args) == 2:
                                self.set_dir(args[1])
                            else:
                                log("[setdir failed: use '>>> setdir <dir>']")
                        case "offer":
                            if len(args) >= 2:
                                if best_effort(self.offer_files, args[1:]) == 2:
                                    log("[No ACK from Server, please try again later.]")
                            else:
                                log("[offer failed: use '>>> offer <filename1> ...']")
                        case "list":
                            if len(args) == 1:
                                self.list_files()
                            else:
                                log("[list failed: use '>>> list']")
                        case "request":
                            if len(args) == 3:
                                self.request_file(args[1], args[2])
                            else:
                                log("[request failed: use '>>> request <filename> <client>']")
                        case "dereg":
                            if len(args) == 1:
                                if best_effort(self.deregister) == 2:
                                    log("[Server not responding]")
                                    log("[Exiting]")
                                    sys.exit(0)
                            else:
                                log("[dereg failed: use '>>> dereg']")
            except KeyboardInterrupt:
                print("")
                sys.exit(0)
            except:
                log("Error: try again")


class server:
    def __init__(self, server_port):
        if not is_port(server_port):
            log(f"[setup failed: %s is not a valid port for argument <{server_port}>]")
            sys.exit()

        self.server_port = server_port

        self.server_table = {}
        self.client_table = {}

        self.messages = []
        self.messages_lock = threading.RLock()

    def UDP_listen(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.bind(("", self.server_port))
        except:
            log(f"[UDP port {self.server_port} unavailable, press Ctrl+C to exit.]")
            sys.exit(0)

        while (True):
            try:
                data, addr = s.recvfrom(PACKET_LEN)
                start, end, flag = UDP_header_to_flags(data[0])
                contents = pickle.loads(data[1:])
                with self.messages_lock:
                    match flag:
                        case 0:
                            self.messages.append(("ack", contents))
                        case 3:
                            self.messages.append(("register", (addr[0], contents)))
                        case 4:
                            self.messages.append(("deregister", contents))
                        case 6:
                            self.messages.append(("file offer", contents))
            except:
                log("[Error while receiving data]")
                continue

    def check_ack(self, client_name):
        with self.messages_lock:
            if ("ack", client_name) in self.messages:
                index = self.messages.index(("ack", client_name))
                self.messages.pop(index)
                return 1
            else:
                return 0

    def send_to_client(self, flag, data=b'', client_name=0, client_address=0):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            contents = pickle.dumps(data)
            packets_required = math.ceil(len(contents) / PACKET_LEN)
            for i in range(packets_required):
                message = UDP_flags_to_header(start=int(i == 0), end=int(i == packets_required - 1),
                                              flag=flag) + contents[i * (PACKET_LEN - 1):(i + 1) * (PACKET_LEN - 1)]
                if client_address:
                    s.sendto(message, client_address)
                elif client_name:
                    s.sendto(message, (self.server_table[client_name]["ip"], self.server_table[client_name]["udp_port"]))
                else:
                    return 0
            return 1
        except:
            return 0

    def transform_table(self):
        self.client_table = {}
        for client_name, client_data in self.server_table.items():
            if client_data["online"]:
                for file_name in client_data["file_names"]:
                    self.client_table[(file_name, client_name)] = (client_data["ip"], client_data["tcp_port"])

    def send_table(self, parameters, action):
        match action:
            case "setup":
                self.transform_table()
            case "attempt":
                self.send_to_client(5, data=self.client_table, client_name=parameters[0])
            case "verify":
                if self.check_ack(parameters[0]):
                    return 1

    def register(self, client_IP, client_name, client_UDP_port, client_TCP_port):
        if client_name in self.server_table:
            log(f"[client {client_name} already registered]")
            self.send_to_client(flag=2, client_address=(client_IP, client_UDP_port))
            return 0

        self.server_table[client_name] = {"ip": client_IP, "udp_port": client_UDP_port, "tcp_port": client_TCP_port,
                                          "online": True, "file_names": set()}
        self.send_to_client(flag=1, client_name=client_name)
        log(f"[registered {client_name} at {client_IP}:{client_UDP_port} with TCP port {client_TCP_port}]")

        if best_effort(self.send_table, (client_name,)) == 2:
            log(f"[could not send table to {client_name}]")
            self.server_table.pop(client_name)
            log(f"[unregistered {client_name}]")
        return 1

    def broadcast_table(self):
        log("[broadcasting new table]")
        for client_name in self.server_table:
            if self.server_table[client_name]["online"]:
                if best_effort(self.send_table, (client_name,)) == 2:
                    log(f"[could not send table to {client_name}]")

    def add_file(self, client_name, file_names):
        self.send_to_client(0, client_name=client_name)
        log(f"[adding file(s) {file_names} from {client_name}]")
        for file_name in file_names:
            self.server_table[client_name]["file_names"].add(file_name)

    def deregister(self, client_name):
        self.send_to_client(0, client_name=client_name)
        self.server_table[client_name]["online"] = False
        log(f"[client {client_name} offline]")

    def start(self):
        UDP_thread = threading.Thread(target=self.UDP_listen, daemon=True)
        UDP_thread.start()

        log("listening...")

        message = ()
        while True:
            try:
                with self.messages_lock:
                    if len(self.messages) > 0:
                        message = self.messages.pop(0)
                if message:
                    match message[0]:
                        case "register":
                            self.register(message[1][0], *message[1][1])
                        case "deregister":
                            self.deregister(message[1])
                            self.broadcast_table()
                        case "file offer":
                            self.add_file(*message[1])
                            self.broadcast_table()
                message = ()
            except KeyboardInterrupt:
                print("")
                sys.exit(0)
            except:
                log("[Error in message processing]")
                message = ()


if __name__ == "__main__":
    if len(sys.argv)  <= 1:
        log("use either:")
        log("    ./FileApp.py.py -s <port>")
        log("    ./FileApp.py.py -c <name> <server-ip> <server-port> <client-udp-port> <client-tcp-port>")
        sys.exit()

    mode, options = sys.argv[1], sys.argv[2:]

    match mode:
        case "-c":
            if len(options) != 5:
                log("[setup failed: incorrect number of options]")
                sys.exit(0)
            try:
                c = client(options[0], options[1], int(options[2]), int(options[3]), int(options[4]))
                c.start()
            except:
                sys.exit(0)
        case "-s":
            if len(options) != 1:
                log("[setup failed: incorrect number of options]")
                sys.exit(0)
            try:
                s = server(int(options[0]))
                s.start()
            except:
                sys.exit(0)
        case "" | "help" | "-h":
            log("use either:")
            log("    ./FileApp.py.py -s <port>")
            log("    ./FileApp.py.py -c <name> <server-ip> <server-port> <client-udp-port> <client-tcp-port>")
        case _:
            log("invalid mode: please use either -c or -s")