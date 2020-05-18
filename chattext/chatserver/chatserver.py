#!/usr/bin/env python3

import argparse
import socket
import threading
import sys
import os
import select

if os.name != "nt":
    import readline

basedir = os.path.dirname(os.path.realpath(sys.argv[0]))


class Server():
    def __init__(self):
        self.parser = argparse.ArgumentParser(
            description="Simple chat server.",
            epilog="For now not taking any argument. Starts and logs"
                   " to stdout. If given invalid argument, exit code "
                   "2 will be returned.")
        self.args = self.parser.parse_args()
        self.host = "0.0.0.0"
        self.port = 1111
        self.bufsiz = 4096
        self.code = "utf8"
        self.sname = "Serwer"

    def start(self):
        self.clients = {}
        self.addresses = {}
        addr = (self.host, self.port)
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.server.bind(addr)
        except OSError:
            print(f"{addr[0]}:{addr[1]} is being used!")
            sys.exit(1)
        self.server.listen()
        print("Waiting for connections...")
        accepting_thread = threading.Thread(name="Accepting connections",
                                            target=self.accept_connections)
        accepting_thread.daemon = 1
        accepting_thread.start()
        try:
            accepting_thread.join()
        except (KeyboardInterrupt, EOFError):
            self.server.close()
            sys.exit(0)

    def send(self, data, client):
        client.sendall(bytes(data, self.code))

    def broadcast(self, data, prefix=""):
        if prefix == "":
            prefix = self.sname + ": "
        print(prefix + data)
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
            print(f"{address[0]}:{address[1]} connected.")
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
        print(text)
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
                            print(
                                f"{self.addresses[client][0]}"
                                f":{self.addresses[client][1]}"
                                f" took nickname {name}")
                            msg = f"{name} connected to chat!"
                        else:
                            print(
                                f"{self.addresses[client][0]}"
                                f":{self.addresses[client][1]}"
                                f" changed nickname from {oldname} to {name}")
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
                                  "Either didn't understand or it was"
                                  "an attack.")
                break


if __name__ == "__main__":
    Server().start()
