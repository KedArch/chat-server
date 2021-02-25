#!/usr/bin/env python3
import os
import sys
import ssl
import json
import shlex
import select
import signal
import socket
import sqlite3
import hashlib
import argparse
import datetime
import threading


class Server():
    """
    Main server class
    """
    def __init__(self):
        self.basedir = os.path.dirname(os.path.realpath(sys.argv[0]))
        self.buffer = 1024  # Better if >= 512 and <= 2048
        self.host = "0.0.0.0"
        self.port = 1111
        self.timeout = 60.0  # Better if >= 30.0
        self.logfile = None
        self.sname = "Server"
        self.reserved = set()
        self.welcome = "Welcome on this server!\nGive "\
                       "yourself a nickname or log in so others "\
                       "can recognize you!"
        self.help = {
            "{csep}a": "list all clients",
            "{csep}cn": "change nickname (saved if logged in)",
            "{csep}l $user $pass": "log in",
            "{csep}ca $user $pass": "create account",
            "{csep}cap $pass $newpass": "change password (when logged in)",
            "{csep}ra $pass $user": "remove account (when logged in)",
            "{csep}pm $nick $message": "send private message to someone "
            "online (also to guests)"
        }
        self.logtype = ("END", "LOG", "CHAT", "ERR")
        self.logsep = 0
        for i in self.logtype:
            if len(i) > self.logsep:
                self.logsep = len(i)
        self.context = None
        signal.signal(signal.SIGTERM, self.exit)
        signal.signal(signal.SIGINT, self.exit)

    def exit(self, signum, frame=None):
        """
        Handles exit signal
        """
        try:
            if self.foreground:
                print()
            self.db_check(True)
            self.logging("<<Logging ended at {}>>".format(
                str(datetime.datetime.now())),
                self.logtype[0])
            self.logfile.close()
            self.server.close()
        finally:
            sys.exit(signum)

    def logging(self, text, logtype):
        """
        Formats logging messages
        """
        longtext = str(datetime.datetime.now()) + "|"\
            + logtype.ljust(self.logsep) + "|"
        if self.log:
            if logtype == self.logtype[0]:
                self.logfile.write(text + "\n")
            else:
                self.logfile.write(longtext + text + "\n")
            self.logfile.flush()
        if self.foreground:
            if logtype == self.logtype[0]:
                print(text)
            else:
                print(longtext + text)

    def db_check(self, close=False):
        """
        Check database at server start and stop
        """
        if not close:
            try:
                con = sqlite3.connect(
                    self.basedir+os.path.sep+"users.db",
                    check_same_thread=False)
                cur = con.cursor()
                try:
                    for i in cur.execute("SELECT nick FROM users"):
                        self.reserved.add(i[0])
                except sqlite3.OperationalError:
                    self.logging(
                        "Database empty or corrupted, trying "
                        "to create a new one.", self.logtype[1])
                    cur.execute(
                        "CREATE TABLE users (user text primary key "
                        "unique, password text, sgroup text, nick text)")
                    self.logging(
                        "Initialized empty user database.", self.logtype[1])
                except TypeError:
                    pass
                self.logging(
                    "Loaded user database.", self.logtype[1])
                con.commit()
                self.db = (con, cur)
            except (sqlite3.OperationalError):
                self.logging(
                    "Unable to access user database. Exiting...",
                    self.logtype[3])
                self.exit(69)
            except IndexError:
                self.logging(
                    "Database corrupted. Exiting...",
                    self.logtype[3])
                self.exit(69)
        else:
            if os.path.isfile(self.basedir+os.path.sep+"users.db"):
                self.db[0].commit()
                self.db[0].close()
                self.logging(
                    "User database synchronized.",
                    self.logtype[1])
            else:
                try:
                    self.logging(
                        "User database not available. Trying to recreate.",
                        self.logtype[1])
                    tempcon = sqlite3.connect(
                        self.basedir+os.path.sep+"users.db")
                    tempcur = tempcon.cursor()
                    cur = self.db[1]
                    tempcur.execute(
                        "CREATE TABLE users (user text primary key "
                        "unique, password text, sgroup text, nick text)")
                    for i in cur.execute("SELECT * FROM users"):
                        tempcur.execute(
                            "INSERT INTO users VALUES (?, ?, ?, ?)", i)
                    tempcon.commit()
                    tempcon.close()
                    self.db[0].close()
                    self.logging(
                        "Succesfully recreated and synchronized"
                        " user database.",
                        self.logtype[1])
                except sqlite3.OperationalError:
                    self.logging(
                        "Couldn't recreate user database. Possibly data loss.",
                        self.logtype[3])
                    self.db[0].close()

    def start(self, foreground=False, log=None, overwrite=False, append=False,
              key=None, cert=None, passwd=None):
        """
        Checks conditions and initializes server
        """
        if not foreground and os.name == "nt":
            print("Sorry, Windows needs foreground argument")
        if overwrite and append:
            print("You must select 'overwrite' OR 'append'")
            sys.exit(68)
        if (overwrite or append) and not log:
            print("'overwrite' and 'append' require 'log'")
            sys.exit(65)
        if not (foreground or log):
            print("There must be 'foreground' or 'log' or both of them "
                  "specified")
            sys.exit(65)
        if (key or cert) and not (key and cert):
            print("There must be both 'key' and 'cert'")
            sys.exit(67)
        if passwd and not key:
            print("'passwd' requires 'key'")
            sys.exit(67)
        if key:
            self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            try:
                self.context.load_cert_chain(certfile=cert,
                                             keyfile=key,
                                             password=passwd)
            except ssl.SSLError:
                print("Invalid cert/key/password")
                sys.exit(67)
        if log:
            dirname = os.path.dirname(log)
            if os.path.exists(dirname) or not dirname:
                if os.path.exists(log):
                    if append:
                        answer = "1"
                    elif overwrite:
                        answer = "2"
                    else:
                        print(
                            "Given log file exists. What to do?\n"
                            "1 - append\n2 - overwrite\n"
                            "anything else - exit")
                        answer = input("> ")
                    if answer == "1":
                        self.logfile = open(log, "a")
                    elif answer == "2":
                        self.logfile = open(log, "w")
                    else:
                        sys.exit(65)
                else:
                    self.logfile = open(log, "w")
            else:
                print("Given log directory does not exists. Exiting...")
                sys.exit(65)
        self.foreground = foreground
        self.log = log
        self.clients = {}
        addr = (self.host, self.port)
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.server.bind(addr)
        except OSError:
            print(f"{addr[0]}:{addr[1]} is being used!")
            if self.logfile:
                self.logfile.close()
            sys.exit(66)
        if not foreground:
            pid = os.fork()
            if pid > 0:
                sys.exit(0)
            os.chdir("/")
            os.setsid()
            os.umask(0)
            pid = os.fork()
            if pid > 0:
                sys.exit(0)
        self.logging("<<Logging started at {}>>".format(
            str(datetime.datetime.now())),
            self.logtype[0])
        self.db_check()
        self.server.listen()
        self.logging("Waiting for connections...", self.logtype[1])
        accepting_thread = threading.Thread(
            name="Accepting connections",
            target=self.accept_connections)
        accepting_thread.daemon = 1
        accepting_thread.start()
        try:
            accepting_thread.join()
        except EOFError:
            self.exit(0)

    def send(self, content, client, mtype="message",
             attrib=[]):
        """
        Handles message sending with correct protocol
        """
        tmp = {
            "type": mtype,
            "attrib": attrib,
            "content": content.strip()
        }
        data = json.dumps(tmp)
        if not len(data) > int(self.buffer*0.8):
            data = data.ljust(self.buffer)
            client.sendall(bytes(data, "utf8"))

    def broadcast(self, data, prefix=None, omit=False):
        """
        Broadcasts message to all clients
        """
        if not prefix:
            prefix = self.sname + ": "
        self.logging(prefix + data, self.logtype[2])
        errcl = []
        for sock in self.clients:
            try:
                if not omit:
                    self.send(prefix + data, sock)
            except BrokenPipeError:
                errcl.append(sock)
        for sock in errcl:
            self.client_error(
                sock,
                f"Connection lost with {self.clients[sock]['address'][0]}"
                f": {self.clients[sock]['address'][1]}.",
                f"Connection lost with {self.clients[sock]['name']}.")

    def accept_connections(self):
        """
        Handles first time connection
        """
        while True:
            client, address = self.server.accept()
            if self.context:
                try:
                    client = self.context.wrap_socket(client, server_side=True)
                except (ssl.SSLError, OSError):
                    self.logging(
                        f"{address[0]}:{address[1]} SSL handshake "
                        "failed or disconnected", self.logtype[1])
                    continue
            self.logging(f"{address[0]}:{address[1]} connected.",
                         self.logtype[1])
            client.sendall(bytes(str(self.buffer), "utf8"))
            try:
                rdy, _, _ = select.select([client], [], [], self.timeout/2)
                if rdy:
                    response = json.loads(client.recv(self.buffer))
                    if not (response["type"] == "control" and
                            "buffer" in response["attrib"] and
                            response["content"] == f"ACK{self.buffer}"):
                        raise json.JSONDecodeError
                    self.send(
                        str(self.timeout), client,
                        "control", ["timeout"])
                else:
                    raise ConnectionRefusedError
            except Exception:
                self.client_error(
                    client, "Failed to communicate with "
                    f"{address[0]}:{address[1]}, disconnecting.")
                continue
            self.send(self.welcome, client)
            self.clients[client] = {
                "address": address,
                "user": None,
                "name": None,
            }
            handle_thread = threading.Thread(
                name="Client: " + address[0] + str(address[1]),
                target=self.handle_connected, args=(client, ))
            handle_thread.daemon = 1
            handle_thread.start()

    def client_error(self, client, text, btext=""):
        """
        Clears variables after client error
        """
        self.logging(text, self.logtype[1])
        if client in self.clients:
            if self.clients[client]["name"]:
                self.broadcast(btext, omit=True)
            if not self.clients[client]["user"]:
                try:
                    self.reserved.remove(self.clients[client]["name"])
                except KeyError:
                    pass
            del self.clients[client]
        client.close()

    def command_change_nickname(self, client, command):
        """
        Command functionality
        """
        try:
            name = shlex.split(command)[1]
        except IndexError:
            return
        if name in self.reserved:
            self.send(
                "This nickname is already"
                f" taken: '{name}'",
                client)
            return
        elif not name:
            self.send(
                "Invalid nickname",
                client)
            return
        elif name == self.sname:
            self.send("You won't disguise as me!", client)
            return
        self.clients[client]["name"], name = name,\
            self.clients[client]["name"]
        if not name:
            self.logging(
                f"{self.clients[client]['address'][0]}"
                f":{self.clients[client]['address'][1]}"
                " took nickname "
                f"'{self.clients[client]['name']}'",
                self.logtype[1])
            msg = f"'{self.clients[client]['name']}' "\
                  "connected to chat!"
        else:
            self.logging(
                f"{self.clients[client]['address'][0]}"
                f":{self.clients[client]['address'][1]}"
                f" changed nickname from '{name}' to "
                f"'{self.clients[client]['name']}'",
                self.logtype[1])
            msg = f"'{name}' changed nickname to " + \
                f"'{self.clients[client]['name']}'"
        if self.clients[client]['user']:
            try:
                self.db[1].execute(
                    "UPDATE users SET nick = "
                    f"'{self.clients[client]['name']}' WHERE user = "
                    f"'{self.clients[client]['user']}'")
            except sqlite3.OperationalError:
                self.send(
                    "Couldn't manipulate user database!"
                    " (Internal server error)",
                    client)
        if name in self.reserved:
            self.reserved.remove(name)
        self.reserved.add(self.clients[client]["name"])
        self.broadcast(msg)

    def command_help(self, client, command):
        """
        Command functionality
        """
        self.send("Server commands:\n", client)
        for i in self.help.keys():
            self.send(f"{i} - {self.help[i]}\n", client,
                      "message", ["csep"])
        self.send(
            "Arguments with '$' may be handled by client "
            "differently:\n", client)

    def command_list_all(self, client, command):
        """
        Command functionality
        """
        if self.clients:
            self.send("Client list:\n", client)
            self.send(f"Server    |{self.sname}\n", client)
            names = list(self.reserved)
            names.sort()
            for nick in names:
                if nick == self.clients[client]['name']:
                    if not self.clients[client]['user']:
                        self.send(
                            f"You(Guest)|{nick}\n",
                            client)
                    else:
                        self.send(
                            f"You       |{nick}\n",
                            client)
                else:
                    for i in self.clients.values():
                        if i['name'] == nick:
                            for j in self.db[1].execute(
                                    "SELECT nick FROM users"):
                                if nick == j[0]:
                                    self.send(f"Online    |{nick}\n", client)
                                    break
                            else:
                                self.send(f"Guest     |{nick}\n", client)
                            break
                    else:
                        self.send(
                            f"Offline   |{nick}\n",
                            client)
        else:
            self.send("Nobody is on server.", client)

    def command_login(self, client, command):
        """
        Command functionality
        """
        try:
            user = shlex.split(command)[1]
            password = hashlib.sha512(
                bytes(shlex.split(command)[2],
                      "utf8")).hexdigest()
        except IndexError:
            self.send("Not enough arguments", client)
            return
        for i in self.db[1].execute("SELECT user, password, nick FROM users"):
            if user == i[0] and password == i[1]:
                self.send(
                    "Succesfully logged in as user "
                    f"'{user}' aka '{i[2]}'",
                    client)
                self.logging(
                    f"{self.clients[client]['address'][0]}:"
                    f"{self.clients[client]['address'][1]} "
                    f"logged in as '{user}'"
                    f" aka '{i[2]}",
                    self.logtype[1])
                if not self.clients[client]['user'] and\
                        self.clients[client]['name']:
                    self.broadcast(
                        f"'{self.clients[client]['name']}' "
                        f"logged in as '{i[2]}'.")
                    self.reserved.remove(self.clients[client]['name'])
                else:
                    self.broadcast(f"'{i[2]}' logged in.")
                self.clients[client]['user'] = user
                self.clients[client]['name'] = i[2]
                break
        else:
            self.send("Invalid username or password", client)

    def command_create_account(self, client, command):
        """
        Command functionality
        """
        try:
            user = shlex.split(command)[1]
            password = hashlib.sha512(
                bytes(shlex.split(command)[2], "utf8")).hexdigest()
        except IndexError:
            self.send("Not enough arguments", client)
            return
        for i in self.db[1].execute("SELECT user FROM users"):
            if user == i[0]:
                self.send(
                    f"User already exist: '{user}'",
                    client)
                break
        else:
            try:
                self.db[1].execute(
                    f"INSERT INTO users VALUES ('{user}',"
                    f"'{password}','user','{user}')")
            except sqlite3.OperationalError:
                self.send(
                    f"Could not create user '{user}'.",
                    client)
                return
            self.db[0].commit()
            self.send(
                f"User '{user}' succesfully created! "
                "Logging in.",
                client)
            self.logging(
                f"{self.clients[client]['address'][0]}:"
                f"{self.clients[client]['address'][1]} "
                f"created user '{user}'", self.logtype[1])
            if not self.clients[client]['user'] and\
                    self.clients[client]['name']:
                self.broadcast(
                    f"'{self.clients[client]['name']}' "
                    f"logged in as '{user}'.")
                self.reserved.remove(self.clients[client]['name'])
            else:
                self.broadcast(f"'{user}' logged in.")
            self.clients[client]['user'] = user
            self.clients[client]['name'] = user
            self.reserved.add(user)

    def command_change_password(self, client, command):
        """
        Command functionality
        """
        if not self.clients[client]['user']:
            self.send("You are not logged in!", client)
            return
        else:
            try:
                oldpass = hashlib.sha512(
                    bytes(shlex.split(command)[1], "utf8")).hexdigest()
                newpass = hashlib.sha512(
                    bytes(shlex.split(command)[2], "utf8")).hexdigest()
            except IndexError:
                self.send("Not enough arguments", client)
                return
            if oldpass == self.db[1].execute(
                    "SELECT password FROM users WHERE user = "
                    f"'{self.clients[client]['user']}'").fetchone()[0]:
                try:
                    self.db[1].execute(
                        "UPDATE users SET password = "
                        f"'{newpass}' WHERE user = "
                        f"'{self.clients[client]['user']}'")
                except sqlite3.OperationalError:
                    self.send(
                        "Couldn't manipulate user database!"
                        " (Internal server error)",
                        client)
                    return
                self.db[0].commit()
                self.send("Successfully changed password", client)
                self.logging(
                    f"{self.clients[client]['address'][0]}:"
                    f"{self.clients[client]['address'][1]} "
                    f"changed user '{self.clients[client]['user']}' "
                    "password.",
                    self.logtype[1])
            else:
                self.send("Invalid password", client)

    def command_remove_account(self, client, command):
        """
        Command functionality
        """
        if not self.clients[client]['user']:
            self.send("You are not logged in!", client)
            return
        else:
            try:
                password = hashlib.sha512(
                    bytes(shlex.split(command)[1], "utf8")).hexdigest()
                username = shlex.split(command)[2]
            except IndexError:
                self.send("Not enough arguments", client)
                return
            if password == self.db[1].execute(
                    "SELECT password FROM users WHERE user = "
                    f"'{self.clients[client]['user']}'").fetchone()[0] and\
                    username == self.db[1].execute(
                    "SELECT user FROM users WHERE user = "
                    f"'{self.clients[client]['user']}'").fetchone()[0]:
                try:
                    self.db[1].execute(
                        "DELETE FROM users "
                        f"WHERE user = '{self.clients[client]['user']}'")
                except sqlite3.OperationalError:
                    self.send(
                        "Couldn't manipulate user database!"
                        " (Internal server error)",
                        client)
                    return
                self.db[0].commit()
                self.send("Successfully removed account", client)
                self.logging(
                    f"{self.clients[client]['address'][0]}:"
                    f"{self.clients[client]['address'][1]} "
                    f"removed user '{self.clients[client]['user']}' "
                    "account.",
                    self.logtype[1])
                self.clients[client]['user'] = None
            else:
                self.send("Invalid password or username", client)

    def command_private_message(self, client, command):
        """
        Command functionality
        """
        nick = command.split()[1]
        if nick == self.clients[client]['name']:
            self.send(
                "It would be funny to send messages to lonely self but no",
                client)
            return
        for i in self.clients.items():
            if i[1]['name'] == nick:
                priv = i[0]
                break
        else:
            self.send(f"{nick} is unavailable!", client)
            return
        message = command[len(command.split()[0])+len(command.split()[1])+2:]
        self.send(f"(priv)|{self.clients[client]['name']}: {message}", priv)
        self.send(f"(priv)|{self.clients[client]['name']}: {message}", client)

    def handle_connected(self, client):
        """
        Serves client output
        """
        err = 0
        timeout = False
        while True:
            try:
                rdy, _, _ = select.select([client], [], [], self.timeout/2)
                if rdy:
                    data = client.recv(self.buffer).decode("utf8")
                    if not data:
                        raise ConnectionResetError
                    data = json.loads(data)
                    if data["type"] == "message":
                        if not self.clients[client]["name"]:
                            err += 1
                            if err == 1:
                                self.send(
                                    "Type {csep}h for help.",
                                    client, attrib=["csep"])
                            elif err == 2:
                                self.send(
                                    "Last chance. Type {csep}h.",
                                    client, attrib=["csep"])
                            elif err == 3:
                                raise ConnectionRefusedError
                            continue
                        self.broadcast(
                            data["content"],
                            self.clients[client]["name"] + ": ")
                    if data["type"] == "command":
                        command = data["content"]
                        if shlex.split(command)[0] == "cn":
                            self.command_change_nickname(client, command)
                        elif command == "h":
                            self.command_help(client, command)
                        elif command == "a":
                            self.command_list_all(client, command)
                        elif shlex.split(command)[0] == "l":
                            self.command_login(client, command)
                        elif shlex.split(command)[0] == "ca":
                            self.command_create_account(client, command)
                        elif not self.clients[client]["name"]:
                            err += 1
                            if err == 1:
                                self.send(
                                    "Type {csep}h for help.",
                                    client, attrib=["csep"])
                            elif err == 2:
                                self.send(
                                    "Last chance. Type {csep}h.",
                                    client, attrib=["csep"])
                            elif err == 3:
                                raise ConnectionRefusedError
                            continue
                        elif shlex.split(command)[0] == "cap":
                            self.command_change_password(client, command)
                        elif shlex.split(command)[0] == "ra":
                            self.command_remove_account(client, command)
                        elif shlex.split(command)[0] == "pm":
                            self.command_private_message(client, command)
                        else:
                            self.send(f"Unknown command: ':{command}'", client)
                    if data["type"] == "control":
                        if "alive" in data["attrib"]:
                            pass
                    timeout = False
                else:
                    if timeout:
                        raise ConnectionError
                    else:
                        self.send("", client, "control", ["alive"])
                        timeout = True
            except (ConnectionAbortedError, ConnectionResetError):
                self.client_error(
                    client,
                    f"{self.clients[client]['address'][0]}:"
                    f"{self.clients[client]['address'][1]} disconnected.",
                    f"'{self.clients[client]['name']}' left chat.")
                break
            except BrokenPipeError:
                self.client_error(
                    client,
                    "Connection lost with "
                    f"{self.clients[client]['address'][0]}:"
                    f"{self.clients[client]['address'][1]} .",
                    f"Connection lost with '{self.clients[client]['name']}'.")
                break
            except ConnectionRefusedError:
                self.client_error(
                    client,
                    f"{self.clients[client]['address'][0]}:"
                    f"{self.clients[client]['address'][1]}"
                    " gave 3 times wrong command for nickname. "
                    "Either they didn't understand or it was an attack.")
                break
            except (UnicodeDecodeError, json.JSONDecodeError):
                self.client_error(
                    client,
                    f"{self.clients[client]['address'][0]}:"
                    f"{self.clients[client]['address'][1]}"
                    " sent invalid characters and was disconnected.")
                break
            except ConnectionError:
                self.client_error(
                    client,
                    f"{self.clients[client]['address'][0]}:"
                    f"{self.clients[client]['address'][1]} hit timeout "
                    "limit and was disconnected.",
                    f"'{self.clients[client]['name']}' timed out.")
                break


def parse_args():
    """
    Parses command line arguments
    """
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Simple chat server intended for personal use",
        epilog="Error codes and their "
               "element:\n65 - log\n66 - socket\n67 - certfile or "
               "keyfile (or its password)\n68 - mutually exclusive arguments\n"
               "69 - user database error")
    parser.add_argument(
        "-f", "--foreground", action="store_true",
        required=not {"-l", "--log"} &
        set(sys.argv),
        help="run in foreground instead (required on Windows)")
    logparser = parser.add_argument_group(
        title="Logging",
        description="Simple logging system")
    logparser.add_argument(
        "-l", "--log",
        required=not {"-f", "--foreground"} &
        set(sys.argv) or {"-o", "--overwrite", "-a", "--append"} &
        set(sys.argv),
        help="log to file; required without -f")
    loggroup = logparser.add_mutually_exclusive_group()
    loggroup.add_argument(
        "-o", "--overwrite", action="store_true",
        help="overwrite log file")
    loggroup.add_argument(
        "-a", "--append", action="store_true",
        help="append to log file")
    tlsgroup = parser.add_argument_group(
        title="SSL/TLS", description="Existence of this parameters "
        "enables TLS/SSL of best version available to both client "
        "and server.\nHere's example of simple key and cert generation"
        " on openssl:\nopenssl req -new -newkey rsa:2048 -sha512 -days"
        "365 -nodes -x509 -keyout server.key -out server.crt\n"
        "Refer to openssl's or other documentation for more info.")
    tlsgroup.add_argument(
        "-k", "--key",
        required={"-c", "--cert", "-p", "--passwd"} & set(sys.argv),
        help="private key location")
    tlsgroup.add_argument(
        "-c", "--cert",
        required={"-k", "--key"} & set(sys.argv),
        help="certificate location")
    tlsgroup.add_argument(
        "-p", "--passwd",
        help="password to private key. WARNING! This option is "
        "insecure. If not given will be asked for it at server start "
        "if needed.")
    args = parser.parse_args()
    Server().start(
        args.foreground, args.log, args.overwrite, args.append,
        args.key, args.cert, args.passwd)


if __name__ == "__main__":
    parse_args()
