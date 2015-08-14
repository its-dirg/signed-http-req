from collections import Counter
from jwkest.jwk import SYMKey
import pytest
from signed_http_req import _serialize_dict, _get_hash_size, UnknownAlgException, _hash_value, \
    sign_http, EmptyHTTPRequestException, verify

__author__ = 'DIRG'


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


@pytest.mark.parametrize("input,expected", [
    ("RS256", 256),
    ("RS512", 512),
])
def test_get_hash_size(input, expected):
    assert _get_hash_size(input) == expected


def test_hash_value():
    data = "some_test_string"
    with pytest.raises(UnknownAlgException):
        _hash_value(123, data)
    assert _hash_value(256, data)


def test_sign_http():
    alg = "HS256"
    key = SYMKey(key="a_key", alg=alg)

    with pytest.raises(EmptyHTTPRequestException):
        sign_http(key=key, alg=alg)

    method = "GET"
    url_host = "host"
    path = "/foo/bar"
    query_param = {"k1": "v1", "k2": "v2"}
    req_header = {"h1": "d1", "h2": "d2"}
    req_body = "my body"
    time_stamp = 12347456
    result = sign_http(key=key, alg=alg, method=method, url_host=url_host,
                       path=path, query_param=query_param, req_header=req_header,
                       req_body=req_body, time_stamp=time_stamp)


def test_verify():
    alg = "HS256"
    key = SYMKey(key="a_key", alg=alg)

    method = "GET"
    url_host = "host"
    path = "/foo/bar"
    query_param = {"k1": "v1", "k2": "v2"}
    req_header = {"h1": "d1", "h2": "d2"}
    req_body = "my body"
    time_stamp = 12347456
    result = sign_http(key=key, alg=alg, method=method, url_host=url_host,
                       path=path, query_param=query_param, req_header=req_header,
                       req_body=req_body, time_stamp=time_stamp)

    verify(key, result, method=method, url_host=url_host,
           path=path, query_param=query_param, req_header=req_header,
           req_body=req_body)


test_verify()
