class Plugin():  # required class name
    def __init__(self):
        # this function should only contain start variables
        # command/startup
        # command handles shortcuts, command arguments as string
        # startup is executed at startup, before accepting connections
        self.type = "command"
        # advertise new usable groups, usefull only in type command
        # if no groups are used use empty set as below
        self.groups = set()
        # both can be omitted when type is startup or before_command
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
