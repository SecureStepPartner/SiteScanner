from __future__ import annotations

import sys
import types

#test cases added
def _install_arq_stub() -> None:
    arq_module = types.ModuleType("arq")

    async def create_pool(*args, **kwargs):  # noqa: ANN001, ANN002
        return None

    arq_module.create_pool = create_pool  # type: ignore[attr-defined]

    connections_module = types.ModuleType("arq.connections")

    class ArqRedis:  # noqa: D401
        """Test stub for the arq Redis client."""

    class RedisSettings:  # noqa: D401
        """Test stub with the constructor used by the app."""

        @classmethod
        def from_dsn(cls, dsn: str) -> RedisSettings:
            return cls()

    connections_module.ArqRedis = ArqRedis  # type: ignore[attr-defined]
    connections_module.RedisSettings = RedisSettings  # type: ignore[attr-defined]

    arq_module.connections = connections_module  # type: ignore[attr-defined]

    sys.modules["arq"] = arq_module
    sys.modules["arq.connections"] = connections_module


try:
    import arq  # noqa: F401
except ModuleNotFoundError:
    _install_arq_stub()
