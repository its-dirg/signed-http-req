# pylint: disable=missing-docstring
from base64 import urlsafe_b64encode
import hashlib
import json
from jwkest import jws, BadSignature
from jwkest.jws import JWS
from jwkest.jwt import JWT

__author__ = 'DIRG'


class UnknownAlgError(Exception):
    pass


class EmptyHTTPRequestError(Exception):
    pass


class ValidationError(Exception):
    pass


QUERY_PARAM_FORMAT = "{}={}"
REQUEST_HEADER_FORMAT = "{}: {}"


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
        param_keys, param_buffer = _serialize_dict(query_param,
                                                   QUERY_PARAM_FORMAT)
        param_hash = urlsafe_b64encode(
            _hash_value(hash_size, param_buffer)).decode("utf-8")
        http_json["q"] = [param_keys, param_hash]

    if req_header:
        header_keys, header_buffer = _serialize_dict(req_header,
                                                     REQUEST_HEADER_FORMAT)
        header_hash = urlsafe_b64encode(
            _hash_value(hash_size, header_buffer)).decode("utf-8")
        http_json["h"] = [header_keys, header_hash]

    if req_body:
        req_body = urlsafe_b64encode(req_body.encode("utf-8")).decode("utf-8")
        http_json["b"] = req_body

    if time_stamp:
        http_json["ts"] = time_stamp

    if not http_json:
        raise EmptyHTTPRequestError("No data to sign")

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

    raise UnknownAlgError("Unknown hash size: {}".format(size))


def _serialize_dict(data, form):
    buffer = []
    keys = []
    for key in data:
        keys.append(key)
        buffer.append(form.format(key, data[key]))

    return keys, "".join(buffer)


def verify_http(key, http_req, method="", url_host="", path="",
                query_param=None,
                req_header=None, req_body=None, strict_query_param=False,
                strict_req_header=False):
    _jw = jws.factory(http_req)
    if _jw:
        _jwt = JWT().unpack(http_req)
        unpacked_req = _jwt.payload()
        _header = _jwt.headers
        try:
            _jw.verify_compact(http_req, keys=[key])
        except BadSignature:
            raise ValidationError("Could not verify signature")

        if "m" in unpacked_req:
            _equal(unpacked_req["m"], method)
        if "u" in unpacked_req:
            _equal(unpacked_req["u"], url_host)
        if "p" in unpacked_req:
            _equal(unpacked_req["p"], path)
        if "q" in unpacked_req:
            param_keys, param_hash = unpacked_req["q"]
            cmp_hash_str = "".join(
                [QUERY_PARAM_FORMAT.format(k, query_param[k]) for k in
                 param_keys])
            cmp_hash = urlsafe_b64encode(
                _hash_value(_get_hash_size(_header["alg"]),
                            cmp_hash_str)).decode("utf-8")
            _equal(cmp_hash, param_hash)
            if strict_query_param and len(param_keys) != len(query_param):
                raise ValidationError("To many or to few query params")
        if "h" in unpacked_req:
            header_keys, header_hash = unpacked_req["h"]
            cmp_hash_str = "".join(
                [REQUEST_HEADER_FORMAT.format(k, req_header[k]) for k in
                 header_keys])
            cmp_hash = urlsafe_b64encode(
                _hash_value(_get_hash_size(_header["alg"]),
                            cmp_hash_str)).decode("utf-8")
            _equal(cmp_hash, header_hash)
            if strict_req_header and len(header_keys) != len(req_header):
                raise ValidationError("To many or to few headers")
        if "b" in unpacked_req:
            cmp_body = urlsafe_b64encode(req_body.encode("utf-8")).decode(
                "utf-8")
            _equal(cmp_body, unpacked_req["b"])


def _equal(value_A, value_B):
    if value_A != value_B:
        raise ValidationError("{} != {}".format(value_A, value_B))
