class WorkbenchError(Exception):
    """A bounded error code suitable for CLI/MCP output; never include secrets."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)
