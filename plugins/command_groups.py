class Plugin():
    def __init__(self):
        self.type = "command"
        self.groups = {"admin"}
        self.command = "g $action $user $group"
        self.help = "manage user groups"

    async def execute(self, app, socket, command):
        if "admin" in app.clients[socket]['group']:
            command = command.split(" ", 3)
            if "usable".startswith(command[0]):
                for i in app.groups:
                    await app.send(socket, i)
                return
            if len(command) < 3:
                await app.send(socket, "Invalid arguments")
                return
            for u, g in app.db[1].execute("SELECT user, sgroup FROM users"):
                if command[1] == u:
                    break
            else:
                await app.send(socket, f"Invalid user '{command[1]}'")
                return
            if "add".startswith(command[0]):
                g = g.split(",")
                if command[2] in g:
                    await app.send(socket,
                        f"'{u}' already have group '{command[2]}'")
                    return
                g.append(command[2])
                await self.update(app, socket, u, g)
            elif "remove".startswith(command[0]):
                g = g.split(",")
                if command[2] not in g:
                    await app.send(socket,
                        f"'{u}' do not have group '{command[2]}'")
                    return
                while command[2] in g:
                    g.remove(command[2])
                await self.update(app, socket, u, g)
            else:
                await app.send(socket,
                    "Invalid action. Make sure it is one of those: "
                    "usable, add, remove")
        else:
            await app.send(
                socket,
                "You do not have required group for this action: 'admin'")

    async def update(self, app, socket, u, g):
        for s, v in list(app.clients.items()):
            if u in v['user']:
                app.clients[s]['group'] = g
        g = ",".join(g)
        app.db[1].execute(
            "UPDATE users SET sgroup = ? WHERE user = ?", (g, u))
        await app.send(socket, "Succesfully updated user groups")

