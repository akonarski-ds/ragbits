import base64
import logging
import os
import secrets
import warnings
from functools import lru_cache

logger = logging.getLogger(__name__)

# Environment variable name for the secret key
RAGBITS_KEY_ENV_VAR = "RAGBITS_SECRET_KEY"

# Default key length in bytes (32 bytes = 256 bits)
DEFAULT_KEY_LENGTH = 32


@lru_cache(maxsize=None)
def _cached_secret_key(env_var: str, key_length: int) -> str:
    """Load a secret key for the given environment variable and key length."""
    secret_key = os.environ.get(env_var)

    if secret_key:
        logger.debug(f"Using secret key from environment variable: {env_var}")
        return secret_key

    random_key = base64.urlsafe_b64encode(secrets.token_bytes(key_length)).decode("utf-8")
    warnings.warn(
        f"No secret key found in environment variable {env_var}. "
        f"Using an ephemeral randomly generated key: '{random_key}'. "
        f"This key will be regenerated on restart, breaking any existing signatures. "
        f"Set the {env_var} environment variable to use a persistent key.",
        UserWarning,
        stacklevel=2,
    )

    return random_key


def get_secret_key(env_var: str = RAGBITS_KEY_ENV_VAR, key_length: int = DEFAULT_KEY_LENGTH) -> str:
    """Get a secret key from environment or generate one if missing.

    The results are cached per ``env_var`` and ``key_length`` combination.
    """

    return _cached_secret_key(env_var, key_length)


# Expose cache control for tests
get_secret_key.cache_clear = _cached_secret_key.cache_clear  # type: ignore[attr-defined]
