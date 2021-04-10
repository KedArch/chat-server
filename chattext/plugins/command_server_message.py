class Plugin():
    def __init__(self):
        self.type = "command"
        self.groups = {"admin"}
        self.command = "ss $message"
        self.help = "say as server"

    async def execute(self, app, socket=None, command=None):
        if "admin" in app.clients[socket]['group']:
            await app.broadcast(command)
        else:
            await app.send(
                socket,
                "You do not have required group for this action: 'admin'")
