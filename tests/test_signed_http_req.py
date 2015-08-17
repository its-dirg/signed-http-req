# pylint: disable=missing-docstring
from collections import Counter
from jwkest.jwk import SYMKey
import pytest
from signed_http_req import _serialize_dict
from signed_http_req import _get_hash_size
from signed_http_req import UnknownAlgError
from signed_http_req import _hash_value
from signed_http_req import sign_http
from signed_http_req import verify
from signed_http_req import ValidationError
from signed_http_req import EmptyHTTPRequestError

__author__ = 'DIRG'

ALG = "HS256"
SIGN_KEY = SYMKey(key="a_key", alg=ALG)

METHOD = "GET"
URL_HOST = "host"
PATH = "/foo/bar"
QUERY_PARAM = {"k1": "v1", "k2": "v2"}
REQ_HEADER = {"h1": "d1", "h2": "d2"}
REQ_BODY = "my body"
TIME_STAMP = 12347456

TEST_DATA = {"key": SIGN_KEY, "method": METHOD, "url_host": URL_HOST,
             "path": PATH, "query_param": QUERY_PARAM, "req_header": REQ_HEADER,
             "req_body": REQ_BODY}


def test_empty_http_req():
    with pytest.raises(EmptyHTTPRequestError):
        sign_http(SIGN_KEY, ALG)


def test_serialize():
    data = {"key_1": "v1", "key_2": "v2", "key_3": "v3"}
    form = ".{}:{}"
    keys, serialized_data = _serialize_dict(data, form)

    assert Counter(keys) == Counter(data.keys())

    data_parts = serialized_data.split(".")[1:]
    for index, part in enumerate(data_parts):
        key_value = part.split(":")

        assert key_value[0] == keys[index]
        assert key_value[1] == data[key_value[0]]


@pytest.mark.parametrize("value,expected", [
    ("RS256", 256),
    ("RS512", 512),
])
def test_get_hash_size(value, expected):
    assert _get_hash_size(value) == expected


def test_hash_value():
    data = "some_test_string"
    with pytest.raises(UnknownAlgError):
        _hash_value(123, data)
    assert _hash_value(256, data)


def test_verify():
    result = sign_http(alg=ALG, time_stamp=TIME_STAMP, **TEST_DATA)
    verify(http_req=result, **TEST_DATA)


@pytest.mark.parametrize("key,value", [
    ("key", SYMKey(key="wrong_key", alg="HS256")),
    ("method", "FAIL"),
    ("url_host", "FAIL"),
    ("path", "FAIL"),
    ("query_param", {"k1": "v1", "k2": "FAIL"}),
    ("req_header", {"h1": "d1", "h2": "FAIL"}),
    ("req_body", "FAIL"),
])
def test_verify_fail(key, value, monkeypatch):
    result = sign_http(alg=ALG, time_stamp=TIME_STAMP, **TEST_DATA)
    monkeypatch.setitem(TEST_DATA, key, value)
    with pytest.raises(ValidationError):
        verify(http_req=result, **TEST_DATA)


@pytest.mark.parametrize("key,value", [
    ("query_param", {"k1": "v1", "k2": "v2", "k3": "v3"}),
    ("req_header", {"h1": "d1", "h2": "d2", "h3": "d3"}),
])
def test_verify_strict(key, value, monkeypatch):
    result = sign_http(alg=ALG, time_stamp=TIME_STAMP, **TEST_DATA)
    monkeypatch.setitem(TEST_DATA, key, value)
    with pytest.raises(ValidationError):
        verify(http_req=result, strict_query_param=True, strict_req_header=True, **TEST_DATA)


@pytest.mark.parametrize("key,value", [
    ("query_param", {"k1": "v1", "k2": "v2", "k3": "v3"}),
    ("req_header", {"h1": "d1", "h2": "d2", "h3": "d3"}),
])
def test_verify_not_strict(key, value, monkeypatch):
    result = sign_http(alg=ALG, time_stamp=TIME_STAMP, **TEST_DATA)
    monkeypatch.setitem(TEST_DATA, key, value)
    verify(http_req=result, strict_query_param=False, strict_req_header=False, **TEST_DATA)
