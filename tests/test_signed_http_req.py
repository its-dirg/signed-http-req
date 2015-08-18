# pylint: disable=missing-docstring
from collections import Counter

from jwkest.jwk import SYMKey
import pytest

from signed_http_req import _serialize_dict
from signed_http_req import _get_hash_size
from signed_http_req import UnknownHashSizeError
from signed_http_req import _hash_value
from signed_http_req import sign_http_request
from signed_http_req import verify_http_request
from signed_http_req import ValidationError
from signed_http_req import EmptyHTTPRequestError

__author__ = 'DIRG'

ALG = "HS256"
SIGN_KEY = SYMKey(key="a_key", alg=ALG)

TEST_DATA = {"key": SIGN_KEY, "method": "GET", "host": "host",
             "path": "/foo/bar", "query_params": {"k1": "v1", "k2": "v2"},
             "headers": {"h1": "d1", "h2": "d2"},
             "body": "my body"}


def test_sign_empty_http_req():
    with pytest.raises(EmptyHTTPRequestError):
        sign_http_request(SIGN_KEY, ALG)


def test_serialize():
    data = {"key_1": "v1", "key_2": "v2", "key_3": "v3"}
    form = ".{}:{}"
    keys, serialized_data = _serialize_dict(data, form)

    assert Counter(keys) == Counter(data.keys())

    data_parts = serialized_data.split(".")[1:]
    for index, part in enumerate(data_parts):
        key, value = part.split(":")

        assert key == keys[index]
        assert value == data[key]


@pytest.mark.parametrize("value,expected", [
    ("RS256", 256),
    ("RS384", 384),
    ("RS512", 512),
])
def test_get_hash_size(value, expected):
    assert _get_hash_size(value) == expected


def test_hash_value():
    data = "some_test_string"
    with pytest.raises(UnknownHashSizeError):
        _hash_value(123, data)
    assert _hash_value(256, data)


def test_verify():
    timestamp = 12347456
    result = sign_http_request(alg=ALG, time_stamp=12347456, **TEST_DATA)
    signature = verify_http_request(signature=result, **TEST_DATA)

    assert signature["ts"] == timestamp


@pytest.mark.parametrize("key,value", [
    ("key", SYMKey(key="wrong_key", alg="HS256")),
    ("method", "FAIL"),
    ("host", "FAIL"),
    ("path", "FAIL"),
    ("query_params", {"k1": "v1", "k2": "FAIL"}),
    ("headers", {"h1": "d1", "h2": "FAIL"}),
    ("body", "FAIL"),
])
def test_verify_fail(key, value, monkeypatch):
    result = sign_http_request(alg=ALG, **TEST_DATA)
    monkeypatch.setitem(TEST_DATA, key, value)
    with pytest.raises(ValidationError):
        verify_http_request(signature=result, **TEST_DATA)


@pytest.mark.parametrize("key,value", [
    ("query_params", {"k1": "v1", "k2": "v2", "k3": "v3"}),
    ("headers", {"h1": "d1", "h2": "d2", "h3": "d3"}),
])
def test_verify_strict(key, value, monkeypatch):
    result = sign_http_request(alg=ALG, **TEST_DATA)
    monkeypatch.setitem(TEST_DATA, key, value)
    with pytest.raises(ValidationError):
        verify_http_request(signature=result,
                            strict_query_param_verification=True,
                            strict_headers_verification=True, **TEST_DATA)


@pytest.mark.parametrize("key,value", [
    ("query_params", {"k1": "v1", "k2": "v2", "k3": "v3"}),
    ("headers", {"h1": "d1", "h2": "d2", "h3": "d3"}),
])
def test_verify_not_strict(key, value, monkeypatch):
    result = sign_http_request(alg=ALG, **TEST_DATA)
    monkeypatch.setitem(TEST_DATA, key, value)
    verify_http_request(signature=result,
                        strict_query_param_verification=False,
                        strict_headers_verification=False, **TEST_DATA)
