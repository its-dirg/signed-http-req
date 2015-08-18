# pylint: disable=missing-docstring
from base64 import urlsafe_b64encode
import hashlib
import json

from jwkest import jws, BadSignature
from jwkest.jws import JWS

__author__ = 'DIRG'


class UnknownHashSizeError(Exception):
    pass


class EmptyHTTPRequestError(Exception):
    pass


class ValidationError(Exception):
    pass


QUERY_PARAM_FORMAT = "{}={}"
REQUEST_HEADER_FORMAT = "{}: {}"


def sign_http_request(key, alg, method="", host="", path="", query_params=None,
                      headers=None, body=None, time_stamp=0):
    """
    Sign an HTTP request as a JWT.
    :param key: signing key
    :param alg: signing algorithm
    :param method: HTTP method
    :param host: url host
    :param path: url path
    :param query_params: query parameters
    :param headers: HTTP headers
    :param body: request body
    :param time_stamp: timestamp
    :return: signature of the request as a JWS
    """
    http_json = {}
    hash_size = _get_hash_size(alg)

    if method:
        http_json["m"] = method.upper()

    if host:
        http_json["u"] = host

    if path:
        http_json["p"] = path

    if query_params:
        param_keys, param_buffer = _serialize_dict(query_params,
                                                   QUERY_PARAM_FORMAT)
        param_hash = urlsafe_b64encode(
            _hash_value(hash_size, param_buffer)).decode("utf-8")
        http_json["q"] = [param_keys, param_hash]

    if headers:
        header_keys, header_buffer = _serialize_dict(headers,
                                                     REQUEST_HEADER_FORMAT)
        header_hash = urlsafe_b64encode(
            _hash_value(hash_size, header_buffer)).decode("utf-8")
        http_json["h"] = [header_keys, header_hash]

    if body:
        body = urlsafe_b64encode(_hash_value(hash_size, body)).decode("utf-8")
        http_json["b"] = body

    if time_stamp:
        http_json["ts"] = int(time_stamp)

    if not http_json:
        raise EmptyHTTPRequestError("No data to sign")

    jws = JWS(json.dumps(http_json), alg=alg)
    return jws.sign_compact(keys=[key])


def verify_http_request(key, signature, method="", host="", path="",
                        query_params=None, headers=None, body=None,
                        strict_query_param_verification=False,
                        strict_headers_verification=False):
    """

    :param key: verification key
    :param signature: signature of the request
    :param method: HTTP method
    :param host: url host
    :param path: url path
    :param query_params: query parameters
    :param headers: HTTP headers
    :param body: request body
    :param strict_query_param_verification:
    :param strict_headers_verification:
    :return:
    """
    _jw = jws.factory(signature)
    if not _jw:
        raise ValidationError("Not a signed request")

    try:
        unpacked_req = _jw.verify_compact(signature, keys=[key])
        _header = _jw.jwt.headers
        hash_size = _get_hash_size(_header["alg"])
    except BadSignature:
        raise ValidationError("Could not verify signature")

    if "m" in unpacked_req:
        _equals(unpacked_req["m"], method)
    if "u" in unpacked_req:
        _equals(unpacked_req["u"], host)
    if "p" in unpacked_req:
        _equals(unpacked_req["p"], path)

    if "q" in unpacked_req:
        param_keys, param_hash = unpacked_req["q"]
        cmp_hash_str = "".join(
            [QUERY_PARAM_FORMAT.format(k, query_params[k]) for k in
             param_keys])
        cmp_hash = urlsafe_b64encode(
            _hash_value(hash_size, cmp_hash_str)).decode("utf-8")
        _equals(cmp_hash, param_hash)
        if strict_query_param_verification and len(param_keys) != len(
                query_params):
            raise ValidationError("Too many or too few query params")

    if "h" in unpacked_req:
        header_keys, header_hash = unpacked_req["h"]
        cmp_hash_str = "".join(
            [REQUEST_HEADER_FORMAT.format(k, headers[k]) for k in
             header_keys])
        cmp_hash = urlsafe_b64encode(
            _hash_value(hash_size, cmp_hash_str)).decode("utf-8")
        _equals(cmp_hash, header_hash)
        if strict_headers_verification and len(header_keys) != len(headers):
            raise ValidationError("Too many or too few headers")

    if "b" in unpacked_req:
        cmp_body = urlsafe_b64encode(_hash_value(hash_size, body)).decode("utf-8")
        _equals(cmp_body, unpacked_req["b"])

    return unpacked_req


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

    raise UnknownHashSizeError(str(size))


def _serialize_dict(data, serialization_template):
    buffer = []
    keys = []
    for key in data:
        keys.append(key)
        buffer.append(serialization_template.format(key, data[key]))

    return keys, "".join(buffer)


def _equals(value, expected):
    if value != expected:
        raise ValidationError("{} != {}".format(value, expected))
