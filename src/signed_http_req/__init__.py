# pylint: disable=missing-docstring
from base64 import urlsafe_b64encode
import hashlib
import json
from jwkest import jws
from jwkest.jws import JWS
from jwkest.jwt import JWT

__author__ = 'DIRG'


class UnknownAlgException(Exception):
    pass


class EmptyHTTPRequestException(Exception):
    pass


def sign_http(key, alg, method="", url_host="", path="", query_param=None,
              req_header=None, req_body=None, time_stamp=""):
    http_json = {}
    hash_size = _get_hash_size(alg)

    if method:
        method = method.upper()
        http_json["m"] = method

    if url_host:
        http_json["u"] = url_host

    if path:
        http_json["p"] = path

    if query_param:
        param_keys, param_buffer = _serialize_dict(query_param, "{}={}")
        param_hash = urlsafe_b64encode(_hash_value(hash_size, param_buffer)).decode("utf-8")
        http_json["q"] = [param_keys, param_hash]

    if req_header:
        header_keys, header_buffer = _serialize_dict(query_param, "{}: {}")
        header_hash = urlsafe_b64encode(_hash_value(hash_size, header_buffer)).decode("utf-8")
        http_json["h"] = [header_keys, header_hash]

    if req_body:
        req_body = urlsafe_b64encode(req_body.encode("utf-8")).decode("utf-8")
        http_json["b"] = req_body

    if time_stamp:
        http_json["ts"] = time_stamp

    if not http_json:
        raise EmptyHTTPRequestException("No data to sign")

    jws = JWS(json.dumps(http_json), alg=alg)
    return jws.sign_compact(keys=[key])


def _get_hash_size(alg):
    return int(alg[2:])


def _hash_value(size, data):
    data = data.encode("utf-8")
    if size == 256:
        return hashlib.sha256(data).digest()
    elif size == 384:
        return hashlib.sha384(data).digest()
    elif size == 512:
        return hashlib.sha512(data).digest()

    raise UnknownAlgException("Unknown hash size: {}".format(size))


def _serialize_dict(data, form):
    buffer = []
    keys = []
    for key in data:
        keys.append(key)
        buffer.append(form.format(key, data[key]))

    return keys, "".join(buffer)


def verify(key, http_req, method="", url_host="", path="", query_param=None,
           req_header=None, req_body=None):
    _jw = jws.factory(http_req)
    if _jw:
        _jwt = JWT().unpack(http_req)
        unpacked_req = _jwt.payload()
        _header = _jwt.headers
        _jw.verify_compact(http_req, keys=[key])

        try:
            if method:
                unpacked_req["m"] = method
                del unpacked_req["m"]
            if url_host:
                pass
            if path:
                pass
            if query_param:
                pass
            if req_header:
                pass
            if req_body:
                pass
            if not unpacked_req:
                pass
                # TODO Exception
        except KeyError:
            pass
            # TODO Fail
