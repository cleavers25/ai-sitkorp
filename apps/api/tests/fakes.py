import re

from app.services.ssh_client import CommandResult


class FakeRunner:
    """Answers commands by the first matching regex; records everything it was asked to run."""

    def __init__(self, responses: dict[str, str | tuple[str, int]]):
        self.responses = [(re.compile(k), v) for k, v in responses.items()]
        self.calls: list[tuple[str, str | None]] = []

    async def run(self, command, *, input=None, timeout=None, max_output_bytes=None):
        self.calls.append((command, input))
        for pattern, value in self.responses:
            if pattern.search(command):
                out, code = value if isinstance(value, tuple) else (value, 0)
                return CommandResult(command, code, out, "", False)
        return CommandResult(command, 0, "", "", False)
