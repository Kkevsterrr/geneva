
# This file gutted from scapy as the module there doesn't quite work there.

# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) 2019 Gabriel Potter <gabriel@potter.fr>
# Copyright (C) 2012 Luca Invernizzi <invernizzi.l@gmail.com>
# Copyright (C) 2012 Steeve Barbeau <http://www.sbarbeau.fr>
# This file is a modified version of the former scapy_http plugin.
# It was reimplemented for scapy 2.4.3+ using sessions, stream handling.
# Original Authors : Steeve Barbeau, Luca Invernizzi
# Originally published under a GPLv2 license

import os
import re
import struct
import subprocess

from scapy.compat import plain_str, bytes_encode, \
    gzip_compress, gzip_decompress
from scapy.config import conf
from scapy.consts import WINDOWS
from scapy.error import warning
from scapy.fields import StrField
from scapy.packet import Packet, bind_layers, bind_bottom_up, Raw
from scapy.utils import get_temp_file, ContextManagerSubprocess

from scapy.layers.inet import TCP, TCP_client

from scapy.modules import six

if "http" not in conf.contribs:
    conf.contribs["http"] = {}
    conf.contribs["http"]["auto_compression"] = True

# https://en.wikipedia.org/wiki/List_of_HTTP_header_fields

GENERAL_HEADERS = [
    "Cache-Control",
    "Connection",
    "Permanent",
    "Content-Length",
    "Content-MD5",
    "Content-Type",
    "Date",
    "Keep-Alive",
    "Pragma",
    "Upgrade",
    "Via",
    "Warning"
]

COMMON_UNSTANDARD_GENERAL_HEADERS = [
    "X-Request-ID",
    "X-Correlation-ID"
]

REQUEST_HEADERS = [
    "A-IM",
    "Accept",
    "Accept-Charset",
    "Accept-Encoding",
    "Accept-Language",
    "Accept-Datetime",
    "Access-Control-Request-Method",
    "Access-Control-Request-Headers",
    "Authorization",
    "Cookie",
    "Expect",
    "Forwarded",
    "From",
    "Host",
    "HTTP2-Settings",
    "If-Match",
    "If-Modified-Since",
    "If-None-Match",
    "If-Range",
    "If-Unmodified-Since",
    "Max-Forwards",
    "Origin",
    "Proxy-Authorization",
    "Range",
    "Referer",
    "TE",
    "User-Agent"
]

COMMON_UNSTANDARD_REQUEST_HEADERS = [
    "Upgrade-Insecure-Requests",
    "Upgrade-Insecure-Requests",
    "X-Requested-With",
    "DNT",
    "X-Forwarded-For",
    "X-Forwarded-Host",
    "X-Forwarded-Proto",
    "Front-End-Https",
    "X-Http-Method-Override",
    "X-ATT-DeviceId",
    "X-Wap-Profile",
    "Proxy-Connection",
    "X-UIDH",
    "X-Csrf-Token",
    "Save-Data",
]

RESPONSE_HEADERS = [
    "Access-Control-Allow-Origin",
    "Access-Control-Allow-Credentials",
    "Access-Control-Expose-Headers",
    "Access-Control-Max-Age",
    "Access-Control-Allow-Methods",
    "Access-Control-Allow-Headers",
    "Accept-Patch",
    "Accept-Ranges",
    "Age",
    "Allow",
    "Alt-Svc",
    "Content-Disposition",
    "Content-Encoding",
    "Content-Language",
    "Content-Location",
    "Content-Range",
    "Delta-Base",
    "ETag",
    "Expires",
    "IM",
    "Last-Modified",
    "Link",
    "Location",
    "Permanent",
    "P3P",
    "Proxy-Authenticate",
    "Public-Key-Pins",
    "Retry-After",
    "Server",
    "Set-Cookie",
    "Strict-Transport-Security",
    "Trailer",
    "Transfer-Encoding",
    "Tk",
    "Vary",
    "WWW-Authenticate",
    "X-Frame-Options",
]

COMMON_UNSTANDARD_RESPONSE_HEADERS = [
    "Content-Security-Policy",
    "X-Content-Security-Policy",
    "X-WebKit-CSP",
    "Refresh",
    "Status",
    "Timing-Allow-Origin",
    "X-Content-Duration",
    "X-Content-Type-Options",
    "X-Powered-By",
    "X-UA-Compatible",
    "X-XSS-Protection",
]

def _strip_header_name(name):
    """Takes a header key (i.e., "Host" in "Host: www.google.com",
    and returns a stripped representation of it
    """
    return plain_str(name.strip()).replace("-", "_")

def _header_line(name, val):
    """Creates a HTTP header line"""
    # Python 3.4 doesn't support % on bytes
    return bytes_encode(name) + b": " + bytes_encode(val)

def _parse_headers(s):
    headers = s.split(b"\r\n")
    headers_found = {}
    for header_line in headers:
        try:
            key, value = header_line.split(b':', 1)
        except ValueError:
            continue
        header_key = _strip_header_name(key).lower()
        # headers_found[header_key] = (key, value.strip())   # The first big change occurs here, using the header_line instead of value.strip()
        headers_found[header_key] = (key, header_line   .strip())
    return headers_found

def _parse_headers_and_body(s):
    ''' Takes a HTTP packet, and returns a tuple containing:
      _ the first line (e.g., "GET ...")
      _ the headers in a dictionary
      _ the body
    '''
    crlfcrlf = b"\r\n\r\n"
    crlfcrlfIndex = s.find(crlfcrlf)
    if crlfcrlfIndex != -1:
        headers = s[:crlfcrlfIndex + len(crlfcrlf)]
        body = s[crlfcrlfIndex + len(crlfcrlf):]
    else:
        headers = s
        body = b''
    first_line, headers = headers.split(b"\r\n", 1)
    return first_line.strip(), _parse_headers(headers), body

def _dissect_headers(obj, s):
    """Takes a HTTP packet as the string s, and populates the scapy layer obj
    (either HTTPResponse or HTTPRequest). Returns the first line of the
    HTTP packet, and the body
    """
    first_line, headers, body = _parse_headers_and_body(s)
    for f in obj.fields_desc:
        # We want to still parse wrongly capitalized fields
        stripped_name = _strip_header_name(f.name).lower()
        try:
            _, value = headers.pop(stripped_name)
        except KeyError:
            continue
        obj.setfieldval(f.name, value)
    if headers:
        headers = {key: value for key, value in six.itervalues(headers)}
        obj.setfieldval('Unknown_Headers', headers)
    return first_line, body

class _HTTPContent(Packet):
    # https://developer.mozilla.org/fr/docs/Web/HTTP/Headers/Transfer-Encoding
    def _get_encodings(self):
        encodings = []
        if isinstance(self, HTTPResponse):
            if self.Transfer_Encoding:
                encodings += [plain_str(x).strip().lower() for x in
                              plain_str(self.Transfer_Encoding).split(",")]
            if self.Content_Encoding:
                encodings += [plain_str(x).strip().lower() for x in
                              plain_str(self.Content_Encoding).split(",")]
        return encodings

    def hashret(self):
        # The only field both Answers and Responses have in common
        return self.Http_Version

    def post_dissect(self, s):
        if not conf.contribs["http"]["auto_compression"]:
            return s
        encodings = self._get_encodings()
        # Un-chunkify
        if "chunked" in encodings:
            data = b""
            while s:
                length, _, body = s.partition(b"\r\n")
                try:
                    length = int(length, 16)
                except ValueError:
                    # Not a valid chunk. Ignore
                    break
                else:
                    load = body[:length]
                    if body[length:length + 2] != b"\r\n":
                        # Invalid chunk. Ignore
                        break
                    s = body[length + 2:]
                    data += load
            if not s:
                s = data
        # Decompress
        try:
            if "deflate" in encodings:
                import zlib
                s = zlib.decompress(s)
            elif "gzip" in encodings:
                s = gzip_decompress(s)
            elif "compress" in encodings:
                import lzw
                s = lzw.decompress(s)
        except Exception:
            # Cannot decompress - probably incomplete data
            pass
        return s

    def post_build(self, pkt, pay):
        if not conf.contribs["http"]["auto_compression"]:
            return pkt + pay
        encodings = self._get_encodings()
        # Compress
        if "deflate" in encodings:
            import zlib
            pay = zlib.compress(pay)
        elif "gzip" in encodings:
            pay = gzip_compress(pay)
        elif "compress" in encodings:
            import lzw
            pay = lzw.compress(pay)
        return pkt + pay

    def self_build(self, field_pos_list=None):
        ''' Takes an HTTPRequest or HTTPResponse object, and creates its
        string representation.'''
        if not isinstance(self.underlayer, HTTP):
            warning(
                "An HTTPResponse/HTTPRequest should always be below an HTTP"
            )
        p = b""
        # Walk all the fields, in order
        for f in self.fields_desc:
            if f.name == "Unknown_Headers":
                continue
            # Get the field value
            val = self.getfieldval(f.name)
            if not val:
                # Not specified. Skip
                continue
            # Fields used in the first line have a space as a separator,
            # whereas headers are terminated by a new line
            if isinstance(self, HTTPRequest):
                if f.name in ['Method', 'Path']:
                    separator = b' '
                else:
                    separator = b'\r\n'
            elif isinstance(self, HTTPResponse):
                if f.name in ['Http_Version', 'Status_Code']:
                    separator = b' '
                else:
                    separator = b'\r\n'
            # Add the field into the packet
            p = f.addfield(self, p, val + separator)
        # Handle Unknown_Headers
        if self.Unknown_Headers:
            headers_text = b""
            for name, value in six.iteritems(self.Unknown_Headers):
                headers_text += _header_line(name, value) + b"\r\n"
            p = self.get_field("Unknown_Headers").addfield(
                self, p, headers_text
            )
        # The packet might be empty, and in that case it should stay empty.
        if p:
            # Add an additional line after the last header
            p = f.addfield(self, p, b'\r\n')
        return p

    def guess_payload_class(self, payload):
        """Detect potential payloads
        """
        if self.Connection and b"Upgrade" in self.Connection:
            from scapy.contrib.http2 import H2Frame
            return H2Frame
        return super(_HTTPContent, self).guess_payload_class(payload)

class _HTTPHeaderField(StrField):
    """Modified StrField to handle HTTP Header names"""
    __slots__ = ["real_name"]

    def __init__(self, name, default):
        self.real_name = name
        name = _strip_header_name(name)
        StrField.__init__(self, name, default, fmt="H")

def _generate_headers(*args):
    """Generate the header fields based on their name"""
    # Order headers
    all_headers = []
    for headers in args:
        all_headers += headers
    # Generate header fields
    results = []
    for h in sorted(all_headers):
        results.append(_HTTPHeaderField(h, None))
    return results

# Create Request and Response packets
class HTTPRequest(_HTTPContent):
    name = "HTTPRequest"
    fields_desc = [
        # First line
        _HTTPHeaderField("Method", "GET"),
        _HTTPHeaderField("Path", "/"),
        _HTTPHeaderField("Http-Version", "HTTP/1.1"),
        # Headers
    ] + (
        _generate_headers(
            GENERAL_HEADERS,
            REQUEST_HEADERS,
            COMMON_UNSTANDARD_GENERAL_HEADERS,
            COMMON_UNSTANDARD_REQUEST_HEADERS
        )
    ) + [
        _HTTPHeaderField("Unknown-Headers", None),
    ]

    def do_dissect(self, s):
        """From the HTTP packet string, populate the scapy object"""
        first_line, body = _dissect_headers(self, s)
        try:
            Method, Path, HTTPVersion = re.split(br"\s+", first_line, 2)
            self.setfieldval('Method', Method)
            self.setfieldval('Path', Path)
            self.setfieldval('Http_Version', HTTPVersion)
        except ValueError:
            pass
        if body:
            self.raw_packet_cache = s[:-len(body)]
        else:
            self.raw_packet_cache = s
        return body

    def mysummary(self):
        return self.sprintf(
            "%HTTPRequest.Method% %HTTPRequest.Path% "
            "%HTTPRequest.Http_Version%"
        )

# TODO: decide to keep or not
class HTTPResponse(_HTTPContent):
    name = "HTTP Response"
    fields_desc = [
        # First line
        _HTTPHeaderField("Http-Version", "HTTP/1.1"),
        _HTTPHeaderField("Status-Code", "200"),
        _HTTPHeaderField("Reason-Phrase", "OK"),
        # Headers
    ] + (
        _generate_headers(
            GENERAL_HEADERS,
            RESPONSE_HEADERS,
            COMMON_UNSTANDARD_GENERAL_HEADERS,
            COMMON_UNSTANDARD_RESPONSE_HEADERS
        )
    ) + [
        _HTTPHeaderField("Unknown-Headers", None),
    ]

    def answers(self, other):
        return HTTPRequest in other

    def do_dissect(self, s):
        ''' From the HTTP packet string, populate the scapy object '''
        first_line, body = _dissect_headers(self, s)
        try:
            HTTPVersion, Status, Reason = re.split(br"\s+", first_line, 2)
            self.setfieldval('Http_Version', HTTPVersion)
            self.setfieldval('Status_Code', Status)
            self.setfieldval('Reason_Phrase', Reason)
        except ValueError:
            pass
        if body:
            self.raw_packet_cache = s[:-len(body)]
        else:
            self.raw_packet_cache = s
        return body

    def mysummary(self):
        return self.sprintf(
            "%HTTPResponse.Http_Version% %HTTPResponse.Status_Code% "
            "%HTTPResponse.Reason_Phrase%"
        )

class HTTP(Packet):
    name = "HTTP 1"
    fields_desc = []
    show_indent = 0

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt and len(_pkt) >= 9:
            from scapy.contrib.http2 import _HTTP2_types, H2Frame
            # To detect a valid HTTP2, we check that the type is correct
            # that the Reserved bit is set and length makes sense.
            while _pkt:
                if len(_pkt) < 9:
                    # Invalid total length
                    return cls
                if ord(_pkt[3:4]) not in _HTTP2_types:
                    # Invalid type
                    return cls
                length = struct.unpack("!I", b"\0" + _pkt[:3])[0] + 9
                if length > len(_pkt):
                    # Invalid length
                    return cls
                sid = struct.unpack("!I", _pkt[5:9])[0]
                if sid >> 31 != 0:
                    # Invalid Reserved bit
                    return cls
                _pkt = _pkt[length:]
            return H2Frame
        return cls

    # tcp_reassemble is used by TCPSession in session.py
    @classmethod
    def tcp_reassemble(cls, data, metadata):
        detect_end = metadata.get("detect_end", None)
        is_unknown = metadata.get("detect_unknown", True)
        if not detect_end or is_unknown:
            metadata["detect_unknown"] = False
            http_packet = HTTP(data)
            # Detect packing method
            if not isinstance(http_packet.payload, _HTTPContent):
                return http_packet
            length = http_packet.Content_Length
            if length is not None:
                # The packet provides a Content-Length attribute: let's
                # use it. When the total size of the frags is high enough,
                # we have the packet
                length = int(length)
                # Subtract the length of the "HTTP*" layer
                if http_packet.payload.payload or length == 0:
                    http_length = len(data) - len(http_packet.payload.payload)
                    detect_end = lambda dat: len(dat) - http_length >= length
                else:
                    # The HTTP layer isn't fully received.
                    detect_end = lambda dat: False
                    metadata["detect_unknown"] = True
            else:
                # It's not Content-Length based. It could be chunked
                encodings = http_packet[HTTP].payload._get_encodings()
                chunked = ("chunked" in encodings)
                if chunked:
                    detect_end = lambda dat: dat.endswith(b"\r\n\r\n")
                else:
                    # If neither Content-Length nor chunked is specified,
                    # it means it's the TCP packet that contains the data,
                    # or that the information hasn't been given yet.
                    detect_end = lambda dat: metadata.get("tcp_end", False)
                    metadata["detect_unknown"] = True
            metadata["detect_end"] = detect_end
            if detect_end(data):
                return http_packet
        else:
            if detect_end(data):
                http_packet = HTTP(data)
                return http_packet

    def guess_payload_class(self, payload):
        """Decides if the payload is an HTTP Request or Response, or
        something else.
        """
        try:
            prog = re.compile(
                br"^(?:OPTIONS|GET|HEAD|POST|PUT|DELETE|TRACE|CONNECT) "
                br"(?:.+?) "
                br"HTTP/\d\.\d$"
            )
            crlfIndex = payload.index(b"\r\n")
            req = payload[:crlfIndex]
            result = prog.match(req)
            if result:
                return HTTPRequest
            else:
                prog = re.compile(br"^HTTP/\d\.\d \d\d\d .*$")
                result = prog.match(req)
                if result:
                    return HTTPResponse
        except ValueError:
            # Anything that isn't HTTP but on port 80
            pass
        return Raw


class GenevaHTTPRequest():
    """ 
    Defines a Geneva HTTP request, where we can replace, set, delete, or insert to existing fields.
    """
    def __init__(self, content):
        """ 
        content: Raw string of the request (Bytes)
        Creates a Geneva HTTP request
        """
        self.original_content = content # Save off the original just in case
        self.parsed_content = HTTPRequest(content)
    
    def replace(self, header, index, content):
        # replace contents at index
        if header not in self.parsed_content["HTTPRequest"].fields:
            # TODO: throw some sort of error, this header doesn't exist
            return None

        if index+len(content) > len(self.parsed_content["HTTPRequest"].fields[header]):
            # TODO: throw some sort of error, this index is too large
            return None

        self.parsed_content["HTTPRequest"].fields[header] = self.parsed_content["HTTPRequest"].fields[header][0:index] \
                                    + content + \
                                    self.parsed_content["HTTPRequest"].fields[header][index+len(content):]
        return str(self)

    def delete(self, header, index, num):
        # delete num characters from header beginning at index
        if header not in self.parsed_content["HTTPRequest"].fields:
            # TODO: throw some sort of error, this header doesn't exist
            return None

        if index+num > len(self.parsed_content["HTTPRequest"].fields[header]):
            # TODO: throw some sort of error, this index is too large
            return None

        self.parsed_content["HTTPRequest"].fields[header] = self.parsed_content["HTTPRequest"].fields[header][0:index] \
                                    + self.parsed_content["HTTPRequest"].fields[header][index+num:]
        return str(self)

    def set_header(self, header, content):
        # Completely replaces a header with content. We don't care if the 
        # field already exists.

        self.parsed_content["HTTPRequest"].fields[header] = content

        return str(self)

    def __str__(self):
        return str(self.parsed_content)
