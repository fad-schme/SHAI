"""EnvSecrets — resolves secret://NAME from environment variables.

Called only at Harness.from_yaml() time — not in the hot path.
resolve() is intentionally synchronous: secret resolution happens once
at startup before the async event loop handles turns.
"""
from __future__ import annotations

import logging
import os

from harness.core.errors import ConfigError

log = logging.getLogger(__name__)

_PREFIX = "secret://"


class EnvSecrets:
    """Reference SecretsProvider. Resolves secret://NAME → os.environ[NAME]."""

    name = "env"

    def __init__(self, prefix: str = "") -> None:
        """
        Args:
            prefix: optional namespace prepended to the env var name.
                    secret://TOKEN with prefix="APP_" looks up APP_TOKEN.
        """
        self._prefix = prefix

    def resolve(self, ref: str) -> str:
        """Resolve a secret://NAME reference to its plaintext value.

        Raises ConfigError when ref is not a valid secret URI or the
        referenced variable is missing or empty.
        Never logs the resolved value — only the variable name and outcome.
        """
        if not ref.startswith(_PREFIX):
            raise ConfigError(
                f"invalid secret reference {ref!r}: must start with 'secret://'",
                op="resolve_secret",
            )

        var_name = self._prefix + ref[len(_PREFIX):]
        if not var_name:
            raise ConfigError(
                "invalid secret reference: name is empty after 'secret://'",
                op="resolve_secret",
            )

        value = os.environ.get(var_name)
        if not value:  # missing OR empty string — both are errors
            raise ConfigError(
                f"secret reference secret://{ref[len(_PREFIX):]} requires "
                f"env var {var_name!r} to be set and non-empty",
                op="resolve_secret",
            )

        log.debug("secret resolved", extra={"var": var_name, "op": "resolve_secret"})
        return value
