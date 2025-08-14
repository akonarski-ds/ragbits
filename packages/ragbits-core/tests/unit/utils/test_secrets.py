import base64
import os
from unittest.mock import patch

import pytest

from ragbits.core.utils.secrets import RAGBITS_KEY_ENV_VAR, get_secret_key


def test_get_secret_key_from_env():
    """Test getting the secret key from an environment variable."""
    get_secret_key.cache_clear()
    test_key = "test-env-secret-key"
    with patch.dict(os.environ, {RAGBITS_KEY_ENV_VAR: test_key}, clear=True):
        assert get_secret_key() == test_key


def test_get_secret_key_generates_random():
    """Test that a random key is generated when neither env var nor default is provided."""
    get_secret_key.cache_clear()
    with patch.dict(os.environ, {}, clear=True):
        key1 = get_secret_key(env_var="TEST_KEY_1")
        key2 = get_secret_key(env_var="TEST_KEY_2")

        # Keys should be different and not empty
        assert key1 != key2
        assert key1
        assert key2


def test_get_secret_key_warning():
    """Test that a warning is emitted when generating a random key."""
    with (
        patch.dict(os.environ, {}, clear=True),
        pytest.warns(UserWarning, match=f"No secret key found in environment variable {RAGBITS_KEY_ENV_VAR}"),
    ):
        get_secret_key(env_var=RAGBITS_KEY_ENV_VAR)


def test_get_secret_key_caching():
    """Test that caching depends on env_var and key_length."""
    get_secret_key.cache_clear()
    with patch.dict(os.environ, {}, clear=True):
        key1 = get_secret_key(env_var="TEST_CACHE_KEY", key_length=16)
        key2 = get_secret_key(env_var="TEST_CACHE_KEY", key_length=16)
        key3 = get_secret_key(env_var="TEST_CACHE_KEY", key_length=32)
        key4 = get_secret_key(env_var="TEST_CACHE_KEY_2", key_length=16)

        assert key1 == key2
        assert key1 != key3
        assert key1 != key4
        assert len(base64.urlsafe_b64decode(key1.encode())) == 16
        assert len(base64.urlsafe_b64decode(key3.encode())) == 32
