#!/usr/bin/env python3

import os
import sys
import ssl
import socket
import select
import signal
import argparse
import datetime
import threading


class Server():
    def __init__(self):
        self.basedir = os.path.dirname(os.path.realpath(sys.argv[0]))
        self.host = "0.0.0.0"
        self.port = 1111
        self.timeout = 10
        self.sname = "Server"
        self.welcome = "Welcome on this server!\nGive "\
                       "yourself a nickname so others can recognize you!"
        self.help = {
                ":a": "list all clients",
                ":cn": "change nickname",
                ":h": "help",
                }
        self.logtype = ("SEP", "LOG", "CHAT")
        self.logsep = 0
        for i in self.logtype:
            if len(i) > self.logsep:
                self.logsep = len(i)
        self.context = None
        signal.signal(signal.SIGTERM, self.exit)
        signal.signal(signal.SIGINT, self.exit)

    def exit(self, signum, frame=""):
        try:
            self.logging("<<Logging ended at {}>>".format(
                     str(datetime.datetime.now())),
                     self.logtype[0])
            self.logfile.close()
            self.server.close()
        finally:
            sys.exit(signum)

    def logging(self, text, logtype):
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

    def start(self, foreground=False, log=None, overwrite=False, append=False,
              key=None, cert=None, passwd=None):
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
            if os.path.exists(dirname) or dirname == "":
                if os.path.exists(log):
                    if append:
                        answer = "1"
                    elif overwrite:
                        answer = "2"
                    else:
                        print("Given log file exists. What to do?\n"
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
        self.clients = {}
        self.addresses = {}
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
        self.foreground = foreground
        self.log = log
        self.server.listen()
        self.logging("<<Logging started at {}>>".format(
                 str(datetime.datetime.now())),
                 self.logtype[0])
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

    def send(self, data, client):
        client.sendall(bytes(data, "utf8"))

    def broadcast(self, data, prefix=""):
        if prefix == "":
            prefix = self.sname + ": "
        self.logging(prefix + data, self.logtype[2])
        for sock in self.clients:
            try:
                self.send(prefix + data, sock)
            except BrokenPipeError:
                self.client_error(
                    sock,
                    f"Connection lost with {self.adresses[sock][0]}"
                    f": {self.addresses[sock][1]}.",
                    f"Connection lost with {self.clients[sock]}.")

    def accept_connections(self):
        while True:
            client, address = self.server.accept()
            if self.context:
                try:
                    client = self.context.wrap_socket(client, server_side=True)
                except (ssl.SSLError, OSError):
                    self.logging(f"{address[0]}:{address[1]} SSL handshake "
                                 "failed or disconnected", self.logtype[1])
                    continue
            self.logging(f"{address[0]}:{address[1]} connected.",
                         self.logtype[1])
            self.send(self.welcome, client)
            self.addresses[client] = address
            handle_thread = threading.Thread(
                name="Client: " + address[0] + str(address[1]),
                target=self.handle_connected, args=(client, ))
            handle_thread.daemon = 1
            handle_thread.start()

    def client_error(self, client, text, btext=""):
        self.logging(text, self.logtype[1])
        del self.addresses[client]
        if client in self.clients:
            del self.clients[client]
            self.broadcast(btext)
        client.close()

    def handle_connected(self, client):
        client.settimeout(self.timeout)
        name = ""
        err = 0
        while True:
            try:
                rdy, _, _ = select.select([client], [], [])
                if rdy:
                    data = client.recv(4096).decode("utf8")
                    if data == "":
                        raise ConnectionResetError
                    elif data == ":cn" or data == ":cn ":
                        self.send("Not enough arguments", client)
                    elif data.split(" ", 1)[0] == ":cn":
                        try:
                            oldname = name
                            name = data.split(" ", 1)[1]
                        except IndexError:
                            continue
                        if name in self.clients.values():
                            self.send(
                                    "This nickname is already"
                                    f" taken: {name}",
                                    client)
                            name = oldname
                            continue
                        elif name == self.sname:
                            self.send("You won't disguise as me!", client)
                            continue
                        self.clients[client] = name
                        if oldname == "":
                            self.logging(
                                f"{self.addresses[client][0]}"
                                f":{self.addresses[client][1]}"
                                f" took nickname {name}", self.logtype[1])
                            msg = f"{name} connected to chat!"
                        else:
                            self.logging(
                                f"{self.addresses[client][0]}"
                                f":{self.addresses[client][1]}"
                                f" changed nickname from {oldname} to {name}",
                                self.logtype[1])
                            msg = f"{oldname} changed nickname to {name}"
                        self.broadcast(msg)
                    elif data == ":h":
                        self.send("Server commands:\n", client)
                        for i in self.help.keys():
                            self.send(f"{i} - {self.help[i]}\n", client)
                    elif data == ":a":
                        if self.clients:
                            self.send("Client list:\n", client)
                            self.send(f"*Server*> {self.sname}\n", client)
                            for nick in self.clients.values():
                                if nick == list(self.clients.values())[-1]:
                                    if nick == name:
                                        self.send(f"*You*> {nick}", client)
                                    else:
                                        self.send(nick, client)
                                else:
                                    if nick == name:
                                        self.send(f"*You*> {nick}\n", client)
                                    else:
                                        self.send(f"{nick}\n", client)
                        else:
                            self.send("Nobody is on server.", client)
                    elif name == "":
                        err += 1
                        if err == 1:
                            self.send("Type :h for help.", client)
                        elif err == 2:
                            self.send("Last chance. Type :h.", client)
                        elif err == 3:
                            raise ConnectionRefusedError
                        continue
                    elif data.startswith(":"):
                        self.send(f"Unknown command: '{data}'", client)
                    else:
                        self.broadcast(data, name + ": ")
            except (ConnectionAbortedError, ConnectionResetError):
                self.client_error(
                        client,
                        f"{self.addresses[client][0]}:"
                        f"{self.addresses[client][1]} disconnected.",
                        f"{name} left chat.")
                break
            except BrokenPipeError:
                raise
                self.client_error(
                        client,
                        "Connection lost with "
                        f"{self.addresses[client][0]}:"
                        f"{self.addresses[client][1]} .",
                        f"Connection lost with {name}.")
                break
            except ConnectionRefusedError:
                self.client_error(
                        client,
                        f"{self.addresses[client][0]}:"
                        f"{self.addresses[client][1]}"
                        " gave 3 times wrong command for nickname. "
                        "Either they didn't understand or it was an attack.")
                break
            except UnicodeDecodeError:
                self.client_error(
                        client,
                        f"{self.addresses[client][0]}:"
                        f"{self.addresses[client][1]}"
                        " sent invalid character and was disconnected.")
                break


def parse_args():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Simple chat server intended for personal use",
        epilog="Error codes and their "
               "element:\n65 - log\n66 - socket\n67 - certfile or "
               "keyfile (or its password)\n68 - mutually exclusive arguments")
    parser.add_argument(
            "-f", "--foreground", action="store_true",
            help="run in foreground instead")
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
            " on openssl:\nopenssl req -new -newkey rsa:2048 -sha256 -days"
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
