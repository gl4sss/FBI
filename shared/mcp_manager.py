"""Register optional MCP servers with the local Codex CLI."""

import subprocess


class McpManager:
    def __init__(self, servers: list, apply_to: list):
        self.servers = servers or []
        self.apply_to = apply_to or []

    def register_codex_servers(self):
        if not self.servers or not set(self.apply_to) & {"orchestrator", "worker"}:
            return

        registered = self._codex_registered_names()
        for server in self.servers:
            name = server["name"]
            if name in registered:
                continue

            command = ["codex", "mcp", "add", name]
            if "url" in server:
                command.extend(["--url", server["url"]])
                if server.get("bearer_token_env"):
                    command.extend([
                        "--bearer-token-env-var", server["bearer_token_env"]
                    ])
            else:
                for key, value in server.get("env", {}).items():
                    command.extend(["--env", f"{key}={value}"])
                command.extend(["--", server["command"], *server.get("args", [])])

            result = subprocess.run(command, capture_output=True, text=True)
            if result.returncode:
                raise RuntimeError(
                    f"Could not register MCP server {name}: {result.stderr[:200]}"
                )
            registered.add(name)

    @staticmethod
    def _codex_registered_names() -> set[str]:
        result = subprocess.run(
            ["codex", "mcp", "list"], capture_output=True, text=True
        )
        if result.returncode:
            raise RuntimeError(f"Could not list MCP servers: {result.stderr[:200]}")
        names = set()
        for line in result.stdout.splitlines():
            line = line.strip()
            if line and not line.startswith("-") and not line.lower().startswith("name"):
                names.add(line.split()[0])
        return names
