class Plugin():
    def __init__(self):
        self.type = "command"
        self.groups = {"admin"}
        self.command = "sn $sname"
        self.help = "change server name in chat"

    async def execute(self, app, socket=None, command=None):
        if "admin" in app.clients[socket]['group']:
            if len(command) > app.maxchars:
                await app.send(
                    socket,
                    f"Sorry, max {app.maxchars} characters for username"
                    " and nick")
                return
            if command in app.reserved:
                await app.send(
                    socket,
                    f"Sorry, {command} is being used by someone")
                return
            app.sname = command
            await app.broadcast(
                app.sname, mtype="control", attrib="sname", to_all=True)
            await app.broadcast(
                f"Server now calls itself '{command}'")
        else:
            await app.send(
                socket,
                "You do not have required group for this action: 'admin'")
