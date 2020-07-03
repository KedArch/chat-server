#!/usr/bin/env python3

import os
import sys
import socket
import select
import signal
import argparse
import datetime
import threading

if os.name != "nt":
    import readline

basedir = os.path.dirname(os.path.realpath(sys.argv[0]))


class Server():
    def __init__(self):
        self.host = "0.0.0.0"
        self.port = 1111
        self.bufsiz = 4096
        self.code = "utf8"
        self.sname = "Serwer"
        self.logtypes = ("SEP", "LOG", "CHAT")
        self.logsep = 0
        for i in self.logtypes:
            if len(i) > self.logsep:
                self.logsep = len(i)
        signal.signal(signal.SIGTERM, self.exit)
        signal.signal(signal.SIGINT, self.exit)

    def exit(self, signum, frame=""):
        try:
            self.log("<<Logging ended at {}>>".format(
                     str(datetime.datetime.now())),
                     self.logtypes[0])
            self.logfile.close()
            self.server.close()
        finally:
            sys.exit(signum)

    def log(self, text, logtype):
        if self.args.log:
            if logtype == self.logtypes[0]:
                self.logfile.write(text + "\n")
            else:
                self.logfile.write(str(datetime.datetime.now()) + "|"
                                   + logtype.ljust(self.logsep) + "|"
                                   + text + "\n")
            self.logfile.flush()
        if self.args.foreground:
            if logtype == self.logtypes[0]:
                print(text)
            else:
                print(str(datetime.datetime.now()) + "|"
                      + logtype.ljust(self.logsep) + "|"
                      + text)

    def start(self):
        if self.args.log:
            dirname = os.path.dirname(self.args.log)
            if os.path.exists(dirname) or dirname == "":
                if os.path.exists(self.args.log):
                    if self.args.append:
                        answer = "1"
                    elif self.args.overwrite:
                        answer = "2"
                    else:
                        print("Given log file exists. What to do?\n"
                              "1 - append\n2 - overwrite\n"
                              "anything else - exit")
                        answer = input("> ")
                    if answer == "1":
                        self.logfile = open(self.args.log, "a")
                    elif answer == "2":
                        self.logfile = open(self.args.log, "w")
                    else:
                        sys.exit(65)
                else:
                    self.logfile = open(self.args.log, "w")
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
            if self.args.logfile:
                self.logfile.close()
            sys.exit(66)
        if not self.args.foreground:
            pid = os.fork()
            if pid > 0:
                sys.exit(0)
            os.chdir("/")
            os.setsid()
            os.umask(0)
            pid = os.fork()
            if pid > 0:
                sys.exit(0)
        self.server.listen()
        self.log("<<Logging started at {}>>".format(
                 str(datetime.datetime.now())),
                 self.logtypes[0])
        self.log("Waiting for connections...", self.logtypes[1])
        accepting_thread = threading.Thread(name="Accepting connections",
                                            target=self.accept_connections)
        accepting_thread.daemon = 1
        accepting_thread.start()
        try:
            accepting_thread.join()
        except EOFError:
            self.exit(0)

    def send(self, data, client):
        client.sendall(bytes(data, self.code))

    def broadcast(self, data, prefix=""):
        if prefix == "":
            prefix = self.sname + ": "
        self.log(prefix + data, self.logtypes[2])
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
        while 1:
            client, address = self.server.accept()
            self.log(f"{address[0]}:{address[1]} connected.", self.logtypes[1])
            self.send(
                "Welcome on this server!\nFor start give "
                "yourself a nickname so anyone can recognize you!",
                client)
            self.addresses[client] = address
            handle_thread = threading.Thread(
                name="Client: " + address[0] + str(address[1]),
                target=self.handle_connected, args=(client, ))
            handle_thread.daemon = 1
            handle_thread.start()

    def client_error(self, client, text, btext=""):
        self.log(text, self.logtypes[1])
        del self.addresses[client]
        if client in self.clients:
            del self.clients[client]
            self.broadcast(btext)
        client.close()

    def handle_connected(self, client):
        name = ""
        err = 0
        while 1:
            try:
                r, _, _ = select.select([client], [client], [client])
                if r:
                    data = client.recv(self.bufsiz).decode(self.code)
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
                            self.send("This nickname is already"
                                      f" taken: {name}",
                                      client)
                            name = oldname
                            continue
                        self.clients[client] = name
                        if oldname == "":
                            self.log(
                                f"{self.addresses[client][0]}"
                                f":{self.addresses[client][1]}"
                                f" took nickname {name}", self.logtypes[1])
                            msg = f"{name} connected to chat!"
                        else:
                            self.log(
                                f"{self.addresses[client][0]}"
                                f":{self.addresses[client][1]}"
                                f" changed nickname from {oldname} to {name}",
                                self.logtypes[1])
                            msg = f"{oldname} changed nickname to {name}"
                        self.broadcast(msg)
                    elif data == ":h":
                        self.send("List of available server commands:"
                                  "\n:a - list all clients"
                                  "\n:cn $nick - change nickname"
                                  "\n:h - help",
                                  client)
                    elif data == ":a":
                        if self.clients:
                            self.send("Client list:", client)
                            for nick in self.clients.values():
                                if nick == list(self.clients.values())[-1]:
                                    if nick == name:
                                        self.send("*You*>" + nick, client)
                                    else:
                                        self.send(nick, client)
                                else:
                                    if nick == name:
                                        self.send("*You*>" + nick
                                                  + "\n", client)
                                    else:
                                        self.send(nick + "\n", client)
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
                self.client_error(client,
                                  f"{self.addresses[client][0]}:"
                                  f"{self.addresses[client][1]} disconnected.",
                                  f"{name} left chat.")
                break
            except BrokenPipeError:
                raise
                self.client_error(client,
                                  "Connection lost with "
                                  f"{self.addresses[client][0]}:"
                                  f"{self.addresses[client][1]} .",
                                  f"Connection lost with {name}.")
                break
            except ConnectionRefusedError:
                self.client_error(client,
                                  f"{self.addresses[client][0]}:"
                                  f"{self.addresses[client][1]}"
                                  " gave 3 times wrong command for nickname. "
                                  "Either they didn't understand or it was "
                                  "an attack.")
                break

    def parse_args(self):
        parser = argparse.ArgumentParser(
            description="Simple chat server.",
            epilog="Error codes: 65 - log problems; 66 - socket problems")
        parser.add_argument("-l", "--log", required=not {"-f", "--foreground"}
                            & set(sys.argv) or {"-o", "--overwrite", "-a",
                            "--append"} & set(sys.argv), help="log to file; "
                            "required without -f")
        parser.add_argument("-f", "--foreground", action="store_true",
                            help="run in foreground instead")
        loggroup = parser.add_mutually_exclusive_group()
        loggroup.add_argument("-o", "--overwrite", action="store_true",
                              help="overwrite log file")
        loggroup.add_argument("-a", "--append", action="store_true",
                              help="append to log file")
        self.args = parser.parse_args()
        self.start()


if __name__ == "__main__":
    Server().parse_args()
