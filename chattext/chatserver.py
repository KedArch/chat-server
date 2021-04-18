#!/usr/bin/env python3
import os
import sys
import json
import shlex
import signal
import argparse
import sqlite3
import hashlib
import datetime
import traceback
import importlib
import asyncio
from asyncio.selector_events import ssl
from asyncio.selector_events import socket

class Server():
    """
    Main server class
    """
    def __init__(self):
        self.basedir = os.path.dirname(os.path.realpath(sys.argv[0]))
        self.buffer = 512  # Better if >= 512 and <= 2048
        self.host = "0.0.0.0"
        self.port = 1111
        self.timeout = 60.0  # Better if >= 30.0
        self.plugins_path = self.basedir + os.path.sep + "plugins"
        self.plugins_command = {}
        self.logfile = None
        self.sname = "Server"
        self.maxchars = 30
        self.ssl_context = None
        self.clients = {}
        self.reserved = set()
        self.welcome = "Welcome on this server!\nGive "\
                       "yourself a nickname or log in so others "\
                       "can recognize you!"
        self.help = {
            "{csep}a": "list all clients ('!' indicates you instead of '|')",
            "{csep}cn $nick": "change nickname (saved if logged in)",
            "{csep}l $user $pass": "log in",
            "{csep}ca $user $pass": "create account",
            "{csep}cap $pass $newpass": "change password (when logged in)",
            "{csep}ra $pass $user": "remove account (when logged in)",
            "{csep}pm $nick $message": "send private message to someone "
            "online (also to guests)",
        }
        self.groups = {"guest", "user", "admin"}
        self.logtype = ("END", "LOG", "CHAT", "ERR")
        self.logsep = 0
        for i in self.logtype:
            if len(i) > self.logsep:
                self.logsep = len(i)
        signal.signal(signal.SIGTERM, self.exit)
        signal.signal(signal.SIGINT, self.exit)

    def exit(self, signum, frame=None):
        """
        Handles exit signal
        """
        try:
            if self.foreground and signum != 70:
                print()
            self.logging("Requesting shutdown.", self.logtype[1])
            self.db_check(True)
            self.logging("<<Logging ended at {}>>".format(
                str(datetime.datetime.now())),
                self.logtype[0])
            if self.logfile:
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
                    self.offline = set()
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

    async def load_plugins(self):
        sys.path.insert(0, self.plugins_path)
        for pfile in sorted(os.listdir(self.plugins_path)):
            fileext = os.path.splitext(pfile)[1].replace(".", "").lower()
            filename = os.path.splitext(pfile)[0]
            if fileext == "py":
                plugin = importlib.import_module(
                    f"{filename}", "plugins").Plugin()
                if plugin.type == "startup":
                    try:
                        await plugin.execute(self)
                        self.logging(
                            f"Loaded startup plugin '{plugin.__module__}'",
                            self.logtype[1])
                    except Exception:
                        self.logging(
                            f"Uncaught exception in plugin "
                            f"'{plugin.__module__}':\n"
                            f"{traceback.format_exc()}",
                            self.logtype[3])
                elif plugin.type == "command":
                    command = plugin.command.split()[0]
                    if command in self.plugins_command:
                        self.logging(
                              f"Plugin '{plugin.__module__}' "
                              "tried to use command "
                              f"'{command}' reserved for plugin "
                              f"'{self.plugins_command[command].__module__}'"
                              ". Resolve the conflict and start again.",
                              self.logtype[3])
                        self.exit(70)
                    self.help["{csep}"+plugin.command] = plugin.help\
                            + f"\n  (part of plugin '{plugin.__module__}')"
                    self.plugins_command[
                        plugin.command.split(" ")[0]] = plugin
                    for i in plugin.groups:
                        self.groups.add(i)
                    self.logging(
                            f"Loaded command plugin '{plugin.__module__}'"
                            f" registered for '{command}'",
                            self.logtype[1])
        sys.path.pop(0)

    def start(self, foreground=False, log=None, overwrite=False,
              append=False, key=None, cert=None, passwd=None,
              no_plugins=False):
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
            self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            try:
                self.ssl_context.load_cert_chain(
                        certfile=cert, keyfile=key, password=passwd)
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
        self.loop = asyncio.get_event_loop()
        if not no_plugins:
            try:
                self.loop.run_until_complete(self.load_plugins())
            except SystemExit:
                return
        addr = (self.host, self.port)
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.setblocking(False)
        try:
            self.server.bind(addr)
        except OSError:
            print(f"{addr[0]}:{addr[1]} is being used!")
            if self.logfile:
                self.logfile.close()
            sys.exit(66)
        self.logging("Waiting for connections...", self.logtype[1])
        self.loop.run_until_complete(self.accept_connections())

    async def send(self, client, content, mtype="message", attrib=""):
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
            await self.loop.sock_sendall(client, bytes(data, "utf8"))

    async def broadcast(self, content, mtype="message",
                        attrib="", prefix="", to_all=False):
        """
        Broadcasts message to all clients
        """
        if not prefix and mtype == "message":
            prefix = self.sname + ": "
        self.logging(prefix + content, self.logtype[2])
        errcl = []
        for sock in self.clients:
            try:
                if self.clients[sock]['name'] or to_all:
                    await self.send(sock, prefix + content, mtype, attrib)
            except BrokenPipeError:
                errcl.append(sock)
            await asyncio.sleep(0)
        for sock in errcl:
            await self.client_error(
                sock,
                f"Connection lost with {self.clients[sock]['address'][0]}"
                f": {self.clients[sock]['address'][1]}.",
                f"Connection lost with '{self.clients[sock]['name']}'.")
            await asyncio.sleep(0)

    async def accept_connections(self):
        """
        Handles first time connection
        """
        self.server.listen()
        while True:
            client, address = await self.loop.sock_accept(self.server)
            if self.ssl_context:
                try:
                    client = await self.ssl_context.wrap_socket(
                            client, server_side=True)
                except (ssl.SSLError, OSError):
                    self.logging(
                        f"{address[0]}:{address[1]} SSL handshake "
                        "failed or disconnected", self.logtype[1])
                    continue
            self.logging(f"{address[0]}:{address[1]} connected.",
                         self.logtype[1])
            client.setblocking(False)
            client.sendall(bytes(str(self.buffer), "utf8"))
            try:
                response = await asyncio.wait_for(
                    self.loop.sock_recv(client, self.buffer),
                    self.timeout/2)
                response = json.loads(response.decode("utf8"))
                if not (response['type'] == "control" and
                        response['attrib'] == "buffer" and
                        response['content'] == f"ACK{self.buffer}"):
                    raise json.JSONDecodeError
                await self.send(
                    client,
                    str(self.timeout), "control", 'timeout')
                await self.send(client, self.sname, "control", "sname")
                await self.command_help(client, True)
                await self.send(client, self.welcome, "message", "welcome")
            except Exception:
                await self.client_error(
                    client, "Failed to communicate with "
                    f"{address[0]}:{address[1]}, disconnecting.")
                continue
            self.clients[client] = {
                "address": address,
                "group": ["guest"],
                "user": None,
                "name": None
            }
            self.loop.create_task(self.handle_connected(client))

    async def client_error(self, client, text, btext=""):
        """
        Clears variables after client error
        """
        self.logging(text, self.logtype[1])
        if client in self.clients:
            name = self.clients[client]['name']
            if not self.clients[client]['user']:
                try:
                    self.reserved.remove(name)
                except KeyError:
                    pass
            del self.clients[client]
            if name:
                await self.broadcast(btext)
        client.close()

    async def command_change_nickname(self, client, command):
        """
        Command functionality
        """
        if not command:
            await self.send(client, "Not enough arguments")
            return
        else:
            name = command
        if name in self.reserved:
            await self.send(
                client,
                "This nickname is already"
                f" taken: '{name}'")
            return
        elif not name:
            await self.send(
                client,
                "Invalid nickname")
            return
        elif name == self.sname:
            await self.send(client, "You won't disguise as server!")
            return
        if len(name) > self.maxchars:
            await self.send(
                client,
                f"Sorry, max {self.maxchars} characters for username"
                " and nick")
            return
        self.clients[client]['name'], name = name,\
            self.clients[client]['name']
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
                await self.send(
                    client,
                    "Couldn't manipulate user database!"
                    " (Internal server error)")
        if name in self.reserved:
            self.reserved.remove(name)
        user = "|"+self.clients[client]['user'] if \
                self.clients[client]['user'] else ""
        await self.send(
            client,
            f"{self.clients[client]['name']}{user}",
            "control", "client")
        self.reserved.add(self.clients[client]['name'])
        await self.broadcast(msg)

    async def command_help(self, client, completion=False):
        """
        Command functionality
        """
        if completion:
            for i in self.help.keys():
                await self.send(client, i, "control", 'csep')
        else:
            await self.send(client, "Server commands:")
            for i in self.help.keys():
                await self.send(
                    client,
                    f"{i} - {self.help[i]}", "message", 'csep')
            await self.send(
                client,
                "Arguments with '$' may be handled by client "
                "differently")

    async def command_list_all(self, client):
        """
        Command functionality
        """
        if self.clients:
            names = list(self.reserved)
            names.sort()
            await self.send(client, "Server" + f" | {self.sname}")
            await self.send(client, "Client list:")
            await self.send(client, "---Online---")
            were = []
            for nextclient in self.clients.keys():
                user = self.clients[nextclient]['name']
                if self.clients[nextclient]['name'] == \
                        self.clients[client]['name']:
                    user += " ! "
                else:
                    user += " | "
                user += ",".join(self.clients[nextclient]['group'])
                await self.send(client, user)
                were.append(self.clients[nextclient]['name'])
            await self.send(client, "---Offline---")
            for i in self.db[1].execute("SELECT nick, sgroup FROM users"):
                if i[0] in were:
                    continue
                user = i[0] + " | " + i[1]
                await self.send(client, user)
        else:
            await self.send(client, "Nobody is on server now.")

    async def command_login(self, client, command):
        """
        Command functionality
        """
        user = shlex.split(command)[0]
        if " " in user:
            await self.send(
                client,
                "Sorry, no spaces in usernames")
            return
        password = hashlib.sha512(
            bytes(shlex.split(command)[1],
                  "utf8")).hexdigest()
        for i in self.db[1].execute("SELECT * FROM users"):
            if user == i[0] and password == i[1]:
                await self.send(
                    client,
                    "Succesfully logged in as user "
                    f"'{user}' aka '{i[3]}'")
                self.logging(
                    f"{self.clients[client]['address'][0]}:"
                    f"{self.clients[client]['address'][1]} "
                    f"logged in as '{user}'"
                    f" aka '{i[3]}'",
                    self.logtype[1])
                if not self.clients[client]['user'] and\
                        self.clients[client]['name']:
                    await self.broadcast(
                        f"'{self.clients[client]['name']}' "
                        f"logged in as '{i[3]}'.")
                    self.reserved.remove(self.clients[client]['name'])
                else:
                    await self.broadcast(f"'{i[3]}' logged in.")
                self.clients[client]['user'] = user
                self.clients[client]['name'] = i[3]
                self.clients[client]['group'] = i[2].split(",")
                await self.send(
                    client,
                    f"{i[3]}|{user}", "control", "client")
                break
        else:
            await self.send(client, "Invalid username or password")

    async def command_create_account(self, client, command):
        """
        Command functionality
        """
        user = shlex.split(command)[0]
        if len(user) > self.maxchars:
            await self.send(
                client,
                f"Sorry, max {self.maxchars} characters for username"
                " and nick")
            return
        elif " " in user:
            await self.send(
                client,
                "Sorry, no spaces in usernames")
            return
        elif user in ("None"):
            await self.send(client, "Username is restricted.")
            return
        password = hashlib.sha512(
            bytes(shlex.split(command)[1], "utf8")).hexdigest()
        for i in self.db[1].execute("SELECT user FROM users"):
            if user == i[0]:
                await self.send(
                    client,
                    f"User already exist: '{user}'")
                break
        else:
            try:
                self.db[1].execute(
                    f"INSERT INTO users VALUES ('{user}',"
                    f"'{password}','user','{user}')")
            except sqlite3.OperationalError:
                await self.send(
                    client,
                    f"Could not create user '{user}'.")
                return
            self.db[0].commit()
            await self.send(
                client,
                f"User '{user}' succesfully created! "
                "Logging in.")
            self.logging(
                f"{self.clients[client]['address'][0]}:"
                f"{self.clients[client]['address'][1]} "
                f"created user '{user}'", self.logtype[1])
            if not self.clients[client]['user'] and\
                    self.clients[client]['name']:
                await self.broadcast(
                    f"'{self.clients[client]['name']}' "
                    f"logged in as '{user}'.")
                self.reserved.remove(self.clients[client]['name'])
            else:
                await self.broadcast(f"'{user}' logged in.")
            self.clients[client]['user'] = user
            self.clients[client]['name'] = user
            self.clients[client]['group'] = ["user"]
            await self.send(
                client,
                f"{user}|{user}", "control", "client")
            self.reserved.add(user)

    async def command_change_password(self, client, command):
        """
        Command functionality
        """
        if not self.clients[client]['user']:
            await self.send(client, "You are not logged in!")
            return
        else:
            oldpass = hashlib.sha512(
                bytes(shlex.split(command)[0], "utf8")).hexdigest()
            newpass = hashlib.sha512(
                bytes(shlex.split(command)[1], "utf8")).hexdigest()
            if oldpass == self.db[1].execute(
                    "SELECT password FROM users WHERE user = "
                    f"'{self.clients[client]['user']}'").fetchone()[0]:
                try:
                    self.db[1].execute(
                        "UPDATE users SET password = "
                        f"'{newpass}' WHERE user = "
                        f"'{self.clients[client]['user']}'")
                except sqlite3.OperationalError:
                    await self.send(
                        client,
                        "Couldn't manipulate user database!"
                        " (Internal server error)")
                    return
                self.db[0].commit()
                await self.send(client, "Successfully changed password")
                self.logging(
                    f"{self.clients[client]['address'][0]}:"
                    f"{self.clients[client]['address'][1]} "
                    f"changed user '{self.clients[client]['user']}' "
                    "password.",
                    self.logtype[1])
            else:
                await self.send(client, "Invalid password")

    async def command_remove_account(self, client, command):
        """
        Command functionality
        """
        if not self.clients[client]['user']:
            await self.send(client, "You are not logged in!")
            return
        else:
            password = hashlib.sha512(
                bytes(shlex.split(command)[0], "utf8")).hexdigest()
            user = shlex.split(command)[1]
            if " " in user:
                await self.send(
                    client,
                    "Sorry, no spaces in usernames")
                return
            if password == self.db[1].execute(
                    "SELECT password FROM users WHERE user = "
                    f"'{self.clients[client]['user']}'").fetchone()[0] and\
                    user == self.db[1].execute(
                    "SELECT user FROM users WHERE user = "
                    f"'{self.clients[client]['user']}'").fetchone()[0]:
                try:
                    self.db[1].execute(
                        "DELETE FROM users "
                        f"WHERE user = '{self.clients[client]['user']}'")
                except sqlite3.OperationalError:
                    await self.send(
                        client,
                        "Couldn't manipulate user database!"
                        " (Internal server error)")
                    return
                self.db[0].commit()
                await self.send(client, "Successfully removed account")
                self.logging(
                    f"{self.clients[client]['address'][0]}:"
                    f"{self.clients[client]['address'][1]} "
                    f"removed user '{self.clients[client]['user']}' "
                    "account.",
                    self.logtype[1])
                self.clients[client]['user'] = None
                self.clients[client]['group'] = ["guest"]
                await self.send(
                    client,
                    f"{self.clients[client]['name']}",
                    "control", "client")
            else:
                await self.send(client, "Invalid password or username")

    async def command_private_message(self, client, command):
        """
        Command functionality
        """
        nick, message = command.split(" ", 1)
        if not message or not nick:
            await self.send(client, "Not enough arguments")
            return
        if nick == self.clients[client]['name']:
            await self.send(
                client,
                "It would be funny to send messages to lonely self but no")
            return
        for i in self.clients.items():
            if i[1]['name'] == nick:
                priv = i[0]
                break
        else:
            await self.send(client, f"{nick} is unavailable!")
            return
        msg = f"(priv '{nick}' to '{self.clients[client]['name']}')"\
              f"|{self.clients[client]['name']}: {message}"
        await self.send(priv, msg)
        await self.send(client, msg)

    async def handle_connected(self, client):
        """
        Serves client output
        """
        err = 0
        timeout = 0
        while True:
            try:
                data = await asyncio.wait_for(
                    self.loop.sock_recv(client, self.buffer), 1)
                if not data:
                    raise ConnectionResetError
                data = json.loads(data.decode("utf8"))
                if data['type'] == "message":
                    if not self.clients[client]['name']:
                        err += 1
                        if err == 1:
                            await self.send(
                                client,
                                "Type {csep}h for help.",
                                attrib='csep')
                        elif err == 2:
                            await self.send(
                                client,
                                "Last chance. Type {csep}h.",
                                attrib='csep')
                        elif err == 3:
                            raise ConnectionRefusedError
                        continue
                    await self.broadcast(
                        data['content'],
                        prefix=self.clients[client]['name'] + ": ")
                if data['type'] == "command":
                    command = data['content'].split(" ", 1)
                    if command[0] == "cn":
                        await self.command_change_nickname(
                            client, command[1])
                    elif command[0] == "h":
                        await self.command_help(client)
                    elif command[0] == "l":
                        await self.command_login(client, command[1])
                    elif command[0] == "ca":
                        await self.command_create_account(
                            client, command[1])
                    elif not self.clients[client]['name']:
                        err += 1
                        if err == 1:
                            await self.send(
                                client,
                                "Type {csep}h for help.",
                                attrib='csep')
                        elif err == 2:
                            await self.send(
                                client,
                                "Last chance. Type {csep}h.",
                                attrib='csep')
                        elif err == 3:
                            raise ConnectionRefusedError
                        continue
                    elif command[0] == "a":
                        await self.command_list_all(client)
                    elif command[0] == "cap":
                        await self.command_change_password(client, command[1])
                    elif command[0] == "ra":
                        await self.command_remove_account(client, command[1])
                    elif command[0] == "pm":
                        await self.command_private_message(client, command[1])
                    elif command[0] in self.plugins_command:
                        plugin = self.plugins_command[command[0]]
                        try:
                            await plugin.execute(
                                self, client, command[1])
                        except Exception:
                            self.logging(
                                f"Uncaught exception in plugin "
                                f"'{plugin.__module__}' used by "
                                f"{self.clients[client]['address'][0]}:"
                                f"{self.clients[client]['address'][1]}"
                                f":\n{traceback.format_exc()}",
                                self.logtype[3])
                            await self.send(
                                client,
                                f"Plugin '{plugin.__module__}' failed!\n"
                                "Please report it to server administration.")
                    else:
                        await self.send(
                            client,
                            "Unknown command: '{csep}" f"{command[0]}'",
                            attrib="csep")
                if data['type'] == "control":
                    if data['attrib'] == 'alive':
                        pass
                timeout = 0
            except asyncio.TimeoutError:
                if timeout == self.timeout//2:
                    await self.send(client, "", "control", 'alive')
                elif timeout < self.timeout:
                    timeout += 1
                else:
                    await self.client_error(
                        client,
                        f"{self.clients[client]['address'][0]}:"
                        f"{self.clients[client]['address'][1]} hit timeout "
                        "limit and was disconnected.",
                        f"'{self.clients[client]['name']}' timed out.")
                    break
            except (ConnectionAbortedError, ConnectionResetError):
                await self.client_error(
                    client,
                    f"{self.clients[client]['address'][0]}:"
                    f"{self.clients[client]['address'][1]} disconnected.",
                    f"'{self.clients[client]['name']}' left chat.")
                break
            except BrokenPipeError:
                await self.client_error(
                    client,
                    "Connection lost with "
                    f"{self.clients[client]['address'][0]}:"
                    f"{self.clients[client]['address'][1]} .",
                    f"Connection lost with '{self.clients[client]['name']}'.")
                break
            except ConnectionRefusedError:
                await self.client_error(
                    client,
                    f"{self.clients[client]['address'][0]}:"
                    f"{self.clients[client]['address'][1]}"
                    " gave 3 times wrong command for nickname. "
                    "Either they didn't understand or it was an attack.")
                break
            except (UnicodeDecodeError, json.JSONDecodeError):
                await self.client_error(
                    client,
                    f"{self.clients[client]['address'][0]}:"
                    f"{self.clients[client]['address'][1]}"
                    " sent invalid characters and was disconnected.")
                break
            except IndexError:
                await self.send(client, "Invalid command arguments")


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
               "69 - user database error\n70 - plugin load error")
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
    parser.add_argument(
        "-n", "--no_plugins", action="store_true", default=False,
        help="do not load plugins.")
    args = parser.parse_args()
    Server().start(
        args.foreground, args.log, args.overwrite, args.append,
        args.key, args.cert, args.passwd, args.no_plugins)


if __name__ == "__main__":
    parse_args()
