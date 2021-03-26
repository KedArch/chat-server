class Plugin():  # required class name
    def __init__(self):
        # this function should only contain start variables
        # command or startup
        self.type = "command"
        # both can be omitted when type is startup
        # they are used for completion
        # parameter names (starting with "$") can be added after space
        self.command = "e $string"
        # help string
        self.help = "echo specified string (echo_example test plugin)"

    async def execute(self, app, socket=None, command=None):
        # required method
        # socket and command parameters can be omitted if type is startup
        # should be async
        if command:
            await app.send(socket, "".join(command))
        else:
            await app.send(socket, "Looks like empty string")
