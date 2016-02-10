#!/usr/bin/env python

import logging
import sys
import threading
import time
import urlparse
import uuid
import datetime
import requests

import tornado.ioloop
import tornado.web
import tornado.httpserver

from tornado import httputil

__version_info__ = (1, 0)
__version__ = '.'.join(map(str, __version_info__))


# The Python system version, truncated to its first component.
python_version = "Python/" + sys.version.split()[0]

# The server software version.
# The format is multiple whitespace-separated strings,
# where each string is of the form name[/version].
deproxy_version = "Deproxy/%s" % __version__

version_string = deproxy_version + ' ' + python_version


logger = logging.getLogger(__name__)

request_id_header_name = 'Deproxy-Request-ID'


class HeaderCollection(object):
    """
    A collection class for HTTP Headers. This class combines aspects of a list
    and a dict. Lookup is always case-insenitive. A key can be added multiple
    times with different values, and all of those values will be kept.
    """

    def __init__(self, mapping=None, **kwargs):
        self.headers = []
        if mapping is not None:
            for k, v in mapping.iteritems():
                self.add(k, v)
        if kwargs is not None:
            for k, v in kwargs.iteritems():
                self.add(k, v)

    def __contains__(self, item):
        item = item.lower()
        for header in self.headers:
            if header[0].lower() == item:
                return True
        return False

    def __len__(self):
        return self.headers.__len__()

    def __getitem__(self, key):
        key = key.lower()
        for header in self.headers:
            if header[0].lower() == key:
                return header[1]

    def __setitem__(self, key, value):
        lower = key.lower()
        for i, header in enumerate(self.headers):
            if header[0].lower() == lower:
                self.headers[i] = (header[0], value)
                return
        else:
            self.add(key, value)

    def __delitem__(self, key):
        self.delete_all(name=key)

    def __iter__(self):
        return self.iterkeys()

    def add(self, name, value):
        self.headers.append((name, value,))

    def find_all(self, name):
        name = name.lower()
        for header in self.headers:
            if header[0].lower() == name:
                yield header[1]

    def delete_all(self, name):
        lower = name.lower()
        self.headers = [header for header in self.headers
                        if header[0].lower() != lower]

    def iterkeys(self):
        for header in self.headers:
            yield header[0]

    def itervalues(self):
        for header in self.headers:
            yield header[1]

    def iteritems(self):
        for header in self.headers:
            yield header

    def keys(self):
        return [key for key in self.iterkeys()]

    def values(self):
        return [value for value in self.itervalues()]

    def items(self):
        return self.headers

    def clear(self):
        raise NotImplementedError

    def copy(self):
        raise NotImplementedError

    @classmethod
    def from_keys(cls, seq, value=None):
        raise NotImplementedError

    def get(self, key, default=None):
        if key in self:
            return self[key]
        return default

    def has_key(self, key):
        raise NotImplementedError

    def pop(self, key, default=None):
        raise NotImplementedError

    def popitem(self):
        raise NotImplementedError

    def setdefault(self, key, default=None):
        raise NotImplementedError

    def update(self, other=None, **kwargs):
        raise NotImplementedError

    def viewitems(self):
        raise NotImplementedError

    def viewkeys(self):
        raise NotImplementedError

    def viewvalues(self):
        raise NotImplementedError

    @staticmethod
    def from_stream(rfile):
        headers = HeaderCollection()
        line = rfile.readline()
        while line and line != '\x0d\x0a':
            name, value = line.split(':', 1)
            name = name.strip()
            line = rfile.readline()
            while line.startswith(' ') or line.startswith('\t'):
                # Continuation lines - see RFC 2616, section 4.2
                value += ' ' + line
                line = rfile.readline()
            headers.add(name, value.strip())
        return headers

    def __str__(self):
        return self.headers.__str__()

    def __repr__(self):
        return self.headers.__repr__()


class Response(object):
    """A simple HTTP Response, with status code, status message, headers, and
    body."""
    def __init__(self, code, message=None, headers=None, body=None):
        """
        Parameters:

        code - A numerical status code. This doesn't have to be a valid HTTP
            status code; 600+ values are acceptable also.
        message - An optional message to go along with the status code. If
            None, a suitable default will be provided based on the given status
            .code If ``code`` is not a valid HTTP status code, then the default
            is the empty string.
        headers - An optional collection of name/value pairs, either a mapping
            object like ``dict``, or a HeaderCollection. Defaults to an empty
            collection.
        body - An optional response body. Defaults to the empty string.
        """

        if message is None:
            message = ''

        if headers is None:
            headers = {}

        if body is None:
            body = ''

        self.code = str(code)
        self.message = str(message)
        self.headers = HeaderCollection(headers)
        self.body = str(body)

    @property
    def body_text(self):
        return self.body

    def __repr__(self):
        return ('Response(code=%r, message=%r, headers=%r, body=%r)' %
                (self.code, self.message, self.headers, self.body))


class Request(object):
    """A simple HTTP Request, with method, path, headers, and body."""
    def __init__(self, method, path, headers=None, body=None):
        """
        Parameters:

        method - The HTTP method to use, such as 'GET', 'POST', or 'PUT'.
        path - The relative path of the resource requested.
        headers - An optional collection of name/value pairs, either a mapping
            object like ``dict``, or a HeaderCollection. Defaults to an empty
            collection.
        body - An optional request body. Defaults to the empty string.
        """

        if headers is None:
            headers = {}

        if body is None:
            body = ''

        self.method = str(method)
        self.path = str(path)
        self.headers = HeaderCollection(headers)
        self.body = body

    def __repr__(self):
        return ('Request(method=%r, path=%r, headers=%r, body=%r)' %
                (self.method, self.path, self.headers, self.body))


def simple_handler(request):
    """
    Handler function.
    Returns a 200 OK Response, with no additional headers or response body.
    """
    logger.debug('')
    return Response(200, 'OK', {}, '')


def echo_handler(request):
    """
    Handler function.
    Returns a 200 OK Response, with the same headers and body as the request.
    """
    logger.debug('')
    return Response(200, 'OK', request.headers, request.body)


def delay(timeout, next_handler=simple_handler):
    """
    Factory function.
    Returns a handler that delays the request for the specified number of
    seconds, forwards it to the next handler function, and returns that
    handler function's Response.

    Parameters:

    timeout - The amount of time, in seconds, to delay before passing the
        request on to the next handler.
    next_handler - The next handler to process the request after the delay.
        Defaults to ``simple_handler``.
    """
    def delayer(request):
        logger.debug('delaying for %i seconds' % timeout)
        time.sleep(timeout)
        return next_handler(request)

    delayer.__doc__ = ('Delay for %s seconds, then forward the Request to the '
                       'next handler' % str(timeout))

    return delayer


def route(scheme, host, deproxy):
    """
    Factory function.
    Returns a handler that forwards the request to a specified URL, using
    either HTTP or HTTPS (regardless of what protocol was used in the initial
    request), and returning the response from the host so routed to.
    """
    logger.debug('')

    def route_to_host(request):
        logger.debug('scheme, host = %s, %s' % (scheme, host))
        logger.debug('request = %s %s' % (request.method, request.path))

        request2 = Request(request.method, request.path, request.headers,
                           request.body)

        if 'Host' in request2.headers:
            request2.headers.delete_all('Host')
        request2.headers.add('Host', host)

        logger.debug('sending request')
        response = deproxy.send_request('%s://%s%s' % (scheme, host, request2.path), request2)
        logger.debug('received response')

        return response, False

    route_to_host.__doc__ = "Route responses to %s using %s" % (host, scheme)

    return route_to_host


class Handling(object):
    """
    An object representing a request received by an endpoint and the
    response it returns.
    """
    def __init__(self, endpoint, request, response):
        self.endpoint = endpoint
        self.request = request
        self.response = response

    def __repr__(self):
        return ('Handling(endpoint=%r, request=%r, response=%r)' %
                (self.endpoint, self.request, self.response))


class MessageChain(object):
    """
    An object containing the initial request sent via the make_request method,
    and all request/response pairs (Handling objects) processed by
    DeproxyEndpoint objects.
    """
    def __init__(self, default_handler, handlers):
        """
        Params:
        default_handler - An optional handler function to use for requests
            related to this MessageChain, if not specified elsewhere
        handlers - A mapping object that maps endpoint references or names of
            endpoints to handlers
        """
        self.sent_request = None
        self.received_response = None
        self.default_handler = default_handler
        self.handlers = handlers
        self.handlings = []
        self.orphaned_handlings = []
        self.lock = threading.Lock()

    def add_handling(self, handling):
        with self.lock:
            self.handlings.append(handling)

    def add_orphaned_handling(self, handling):
        with self.lock:
            self.orphaned_handlings.append(handling)

    def __repr__(self):
        return ('MessageChain(default_handler=%r, handlers=%r, '
                'sent_request=%r, handlings=%r, received_response=%r, '
                'orphaned_handlings=%r)' %
                (self.default_handler, self.handlers, self.sent_request,
                 self.handlings, self.received_response,
                 self.orphaned_handlings))


class Deproxy(object):
    """The main class."""

    def __init__(self, default_handler=None):
        """
        Params:
        default_handler - An optional handler function to use for requests, if
            not specified elsewhere
        """
        self._message_chains_lock = threading.Lock()
        self._message_chains = dict()
        self._endpoint_lock = threading.Lock()
        self._endpoints = []
        self.default_handler = default_handler

    def make_request(self, url, method='GET', headers=None, request_body='',
                     default_handler=None, handlers=None,
                     add_default_headers=True, ssl_options={}, verify=False):
        """
        Make an HTTP request to the given url and return a MessageChain.

        Parameters:

        url - The URL to send the client request to
        method - The HTTP method to use, default is 'GET'
        headers - A collection of request headers to send, defaults to None
        request_body - The body of the request, as a string, defaults to empty
            string
        default_handler - An optional handler function to use for requests
            related to this client request
        handlers - A mapping object that maps endpoint references or names of
            endpoints to handlers. If an endpoint or its name is a key within
            ``handlers``, all requests to that endpoint will be handled by the
            associated handler
        add_default_headers - If true, the 'Host', 'Accept', 'Accept-Encoding',
            and 'User-Agent' headers will be added to the list of headers sent,
            if not already specified in the ``headers`` parameter above.
            Otherwise, those headers are not added. Defaults to True.
        """
        logger.debug('')

        if headers is None:
            headers = HeaderCollection()
        else:
            headers = HeaderCollection(headers)

        request_id = str(uuid.uuid4())
        if request_id_header_name not in headers:
            headers.add(request_id_header_name, request_id)

        message_chain = MessageChain(default_handler=default_handler,
                                     handlers=handlers)
        self.add_message_chain(request_id, message_chain)

        parsed = urlparse.urlparse(url)
        path = "{uri.path}?{uri.query}".format(uri=parsed)

        if add_default_headers:
            if 'Host' not in headers:
                headers.add('Host', parsed.netloc)
            if 'Accept' not in headers:
                headers.add('Accept', '*/*')
            if 'Accept-Encoding' not in headers:
                headers.add('Accept-Encoding',
                            'identity, deflate, compress, gzip')
            if 'User-Agent' not in headers:
                headers.add('User-Agent', version_string)

        request = Request(method, path, headers, request_body)

        response = self.send_request(url, request, ssl_options, verify)

        self.remove_message_chain(request_id)

        message_chain.sent_request = request
        message_chain.received_response = response

        return message_chain

    def send_request(self, url, request, ssl_options={}, verify=False):
        """Send the given request to the host and return the Response."""
        logger.debug('sending request %s' % url)

        cert = None
        if "certfile" in ssl_options and "keyfile" in ssl_options:
            cert = (ssl_options["certfile"], ssl_options["keyfile"])


        headers = pack_headers(request.headers)

        get_data = lambda: request.body

        if isinstance(request.body, list):
            def get_data():
                for chunk in request.body:
                    yield chunk

        elif headers.get("Transfer-Encoding") == "chunked" and isinstance(request.body, str):

            def get_data():
                parse_body = request.body.split("\r\n")

                for i in xrange(len(parse_body) - 1):
                    if (i + 1)%2 == 0:
                        yield parse_body[i]

        res = requests.request(request.method, url, headers=headers,
                               data=get_data(),
                               cert=cert, verify=verify,
                               stream=False)
        response = Response(res.status_code, res.reason, res.headers, res.text)

        logger.debug('Returning Response object')
        return response

    def add_endpoint(self, port, name=None, hostname=None,
                     default_handler=None, ssl_enable=False,
                     ssl_certs=None):
        """Add a DeproxyEndpoint object to this Deproxy object's list of
        endpoints, giving it the specified server address, and then return the
        endpoint.

        Params:
        port - The port on which the new endpoint will listen
        name - An optional descriptive name for the new endpoint. If None, a
            suitable default will be generated
        hostname - The ``hostname`` portion of the address tuple passed to
            ``socket.bind``. If not specified, it defaults to 'localhost'
        default_handler - An optional handler function to use for requests that
            the new endpoint will handle, if not specified elsewhere
        ssl_enable - Boolean flag to enable to https support for endpoint
        ssl_certs - If SSL is enabled, should contain keyword arguments as dict
            to be passed to ssl.wrap_socket, should include ``certfile`` and
            ``keyfile``
        """

        logger.debug('')
        endpoint = None
        with self._endpoint_lock:
            if name is None:
                name = 'Endpoint-%i' % len(self._endpoints)
            endpoint = DeproxyEndpoint(self, port=port, name=name,
                                       hostname=hostname,
                                       default_handler=default_handler,
                                       ssl_enable=ssl_enable,
                                       ssl_certs=ssl_certs)
            self._endpoints.append(endpoint)
            return endpoint

    def _remove_endpoint(self, endpoint):
        """Remove a DeproxyEndpoint from the list of endpoints. Returns True if
        the endpoint was removed, or False if the endpoint was not in the list.
        This method should normally not be called by user code. Instead, call
        the endpoint's shutdown method."""
        logger.debug('')
        with self._endpoint_lock:
            count = len(self._endpoints)
            self._endpoints = [e for e in self._endpoints if e != endpoint]
            return (count != len(self._endpoints))

    def shutdown_all_endpoints(self):
        """Shutdown and remove all endpoints in use."""
        logger.debug('Removing all endpoints')
        endpoints = []
        with self._endpoint_lock:
            endpoints = list(self._endpoints)
        # be sure we're not holding the lock when shutdown calls
        # _remove_endpoint.
        for e in endpoints:
            e.shutdown()

    def add_message_chain(self, request_id, message_chain):
        """Add a MessageChain to the internal list for the given request ID."""
        logger.debug('request_id = %s' % request_id)
        with self._message_chains_lock:
            self._message_chains[request_id] = message_chain

    def remove_message_chain(self, request_id):
        """Remove a particular MessageChain from the internal list."""
        logger.debug('request_id = %s' % request_id)
        with self._message_chains_lock:
            del self._message_chains[request_id]

    def get_message_chain(self, request_id):
        """Return the MessageChain for the given request ID."""
        logger.debug('request_id = %s' % request_id)
        with self._message_chains_lock:
            if request_id in self._message_chains:
                return self._message_chains[request_id]
            else:
                #logger.debug('no message chain found for request_id %s' %
                # request_id)
                #for rid, mc in self._message_chains.iteritems():
                #    logger.debug('  %s - %s' % (rid, mc))
                return None

    def add_orphaned_handling(self, handling):
        """Add the handling to all available MessageChains."""
        logger.debug('Adding orphaned handling')
        with self._message_chains_lock:
            for mc in self._message_chains.itervalues():
                mc.add_orphaned_handling(handling)


class DeproxyEndpoint(object):
    """A class that acts as a mock HTTP server."""

    def __init__(self, deproxy, port, name, hostname=None,
                 default_handler=None, ssl_enable=False, ssl_certs=None):
        """
        Initialize a DeproxyEndpoint

        Params:
        deproxy - The parent Deproxy object that contains this endpoint
        port - The port on which this endpoint will listen
        name - A descriptive name for this endpoint
        hostname - The ``hostname`` portion of the address tuple passed to
            ``socket.bind``. If not specified, it defaults to 'localhost'
        default_handler - An optional handler function to use for requests that
            this endpoint services, if not specified elsewhere
        ssl_enable - Boolean flag to enable to https support for endpoint
        ssl_certs - If SSL is enabled, should contain keyword arguments as dict
            to be passed to ssl.wrap_socket, should include ``certfile`` and
            ``keyfile``
        """

        logger.debug('port=%s, name=%s, hostname=%s', port, name, hostname)

        if hostname is None:
            hostname = 'localhost'

        self.deproxy = deproxy
        self.name = name
        self.port = port
        self.hostname = hostname
        self.default_handler = default_handler
        self.ssl_enable = ssl_enable
        self.ssl_certs = ssl_certs
        self.ioloop = tornado.ioloop.IOLoop()

        thread_name = 'Thread-%s' % self.name
        self.server_thread = threading.Thread(target=self.serve_forever,
                                              name=thread_name)

        self.start_event = threading.Event()
        self.server_thread.daemon = True
        self.server_thread.start()
        self.start_event.wait(timeout=5)

    def serve_forever(self):
        self.ioloop.make_current()

        params = {}

        if self.ssl_enable:
            params["ssl_options"] = self.ssl_certs
        app = self.make_app()

        self.server = tornado.httpserver.HTTPServer(app, **params)
        self.server.listen(self.port, address=self.hostname)
        self.ioloop.add_callback(lambda: self.start_event.set())
        self.ioloop.start()

    def make_app(self):
        return tornado.web.Application([(r"/.*", AllMethodsHandler, dict(handler=self.handle_request)),])

    def shutdown(self):
        logger.debug('Shutting down "%s"' % self.name)
        self.ioloop.stop()
        self.server.stop()
        self.server_thread.join(timeout=5)
        self.deproxy._remove_endpoint(self)

    def handle_request(self, request_handler):
        incoming_request = Request(request_handler.request.method, request_handler.request.uri, request_handler.request.headers, request_handler.request.body)
        message_chain = None
        request_id = incoming_request.headers.get(request_id_header_name)
        if request_id:
            logger.debug('The request has a request id: %s=%s' %
                         (request_id_header_name, request_id))
            message_chain = self.deproxy.get_message_chain(request_id)
        else:
            logger.debug('The request does not have a request id')

        # Handler resolution:
        #  1. Check the handlers mapping specified to ``make_request``
        #    a. By reference
        #    b. By name
        #  2. Check the default_handler specified to ``make_request``
        #  3. Check the default for this endpoint
        #  4. Check the default for the parent Deproxy
        #  5. Fallback to simple_handler
        if (message_chain and message_chain.handlers is not None and
                    self in message_chain.handlers):
            handler = message_chain.handlers[self]
        elif (message_chain and message_chain.handlers is not None and
                      self.name in message_chain.handlers):
            handler = message_chain.handlers[self.name]
        elif message_chain and message_chain.default_handler is not None:
            handler = message_chain.default_handler
        elif self.default_handler is not None:
            handler = self.default_handler
        elif self.deproxy.default_handler is not None:
            handler = self.deproxy.default_handler
        else:
            # last resort
            handler = simple_handler

        logger.debug('calling handler')
        resp = handler(incoming_request)
        logger.debug('returned from handler')

        add_default_headers = True
        if type(resp) == tuple:
            logger.debug('Handler gave back a tuple: %s',
                         (type(resp[0]), resp[1:]))
            if len(resp) > 1:
                add_default_headers = resp[1]
            resp = resp[0]

        if add_default_headers:
            if 'Server' not in resp.headers:
                resp.headers['Server'] = version_string
            if 'Date' not in resp.headers:
                resp.headers['Date'] = datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
        else:
            logger.debug('Don\'t add default response headers.')

        found = resp.headers.get(request_id_header_name)
        if not found and request_id is not None:
            resp.headers[request_id_header_name] = request_id

        outgoing_response = resp

        h = Handling(self, incoming_request, outgoing_response)
        if message_chain:
            message_chain.add_handling(h)
        else:
            self.deproxy.add_orphaned_handling(h)

        response_code = int(resp.code)
        request_handler.set_status(response_code, resp.message)
        headers = pack_headers(resp.headers)
        for name, value in headers.iteritems():
            request_handler.set_header(name, value)
        if response_code >= 200 and response_code != 204 and response_code != 304:
            limit = resp.headers.get("Content-Length")
            if limit is not None:
                body = resp.body[:int(limit)]
            else:
                body = resp.body
            request_handler.write(body)
        request_handler.finish()


class AllMethodsHandler(tornado.web.RequestHandler):

    def initialize(self, handler):
        methods = ["get", "post", "put", "patch", "options", "delete", "head"]

        def handle(*args, **kwargs):
            handler(self)

        for method in methods:
            setattr(self, method, handle)

    def clear(self):
        self._headers = httputil.HTTPHeaders({})
        self.set_default_headers()
        self._write_buffer = []
        self._status_code = 200
        self._reason = messages_by_response_code[200][0]


def pack_headers(request_headers):
    headers = {}
    for key, value in request_headers.iteritems():
        if key in headers:
            headers[key] = "%s, %s" % (headers[key], value)
        else:
            headers[key] = value

    return headers


# Table mapping response codes to messages; entries have the
# form {code: (shortmessage, longmessage)}.
# See RFC 2616.
messages_by_response_code = {
    100: ('Continue', 'Request received, please continue'),
    101: ('Switching Protocols',
          'Switching to new protocol; obey Upgrade header'),

    200: ('OK', 'Request fulfilled, document follows'),
    201: ('Created', 'Document created, URL follows'),
    202: ('Accepted',
          'Request accepted, processing continues off-line'),
    203: ('Non-Authoritative Information', 'Request fulfilled from cache'),
    204: ('No Content', 'Request fulfilled, nothing follows'),
    205: ('Reset Content', 'Clear input form for further input.'),
    206: ('Partial Content', 'Partial content follows.'),

    300: ('Multiple Choices',
          'Object has several resources -- see URI list'),
    301: ('Moved Permanently', 'Object moved permanently -- see URI list'),
    302: ('Found', 'Object moved temporarily -- see URI list'),
    303: ('See Other', 'Object moved -- see Method and URL list'),
    304: ('Not Modified',
          'Document has not changed since given time'),
    305: ('Use Proxy',
          'You must use proxy specified in Location to access this '
          'resource.'),
    307: ('Temporary Redirect',
          'Object moved temporarily -- see URI list'),

    400: ('Bad Request',
          'Bad request syntax or unsupported method'),
    401: ('Unauthorized',
          'No permission -- see authorization schemes'),
    402: ('Payment Required',
          'No payment -- see charging schemes'),
    403: ('Forbidden',
          'Request forbidden -- authorization will not help'),
    404: ('Not Found', 'Nothing matches the given URI'),
    405: ('Method Not Allowed',
          'Specified method is invalid for this resource.'),
    406: ('Not Acceptable', 'URI not available in preferred format.'),
    407: ('Proxy Authentication Required', 'You must authenticate with '
          'this proxy before proceeding.'),
    408: ('Request Timeout', 'Request timed out; try again later.'),
    409: ('Conflict', 'Request conflict.'),
    410: ('Gone',
          'URI no longer exists and has been permanently removed.'),
    411: ('Length Required', 'Client must specify Content-Length.'),
    412: ('Precondition Failed', 'Precondition in headers is false.'),
    413: ('Request Entity Too Large', 'Entity is too large.'),
    414: ('Request-URI Too Long', 'URI is too long.'),
    415: ('Unsupported Media Type', 'Entity body in unsupported format.'),
    416: ('Requested Range Not Satisfiable',
          'Cannot satisfy request range.'),
    417: ('Expectation Failed',
          'Expect condition could not be satisfied.'),

    500: ('Internal Server Error', 'Server got itself in trouble'),
    501: ('Not Implemented',
          'Server does not support this operation'),
    502: ('Bad Gateway', 'Invalid responses from another server/proxy.'),
    503: ('Service Unavailable',
          'The server cannot process the request due to a high load'),
    504: ('Gateway Timeout',
          'The gateway server did not receive a timely response'),
    505: ('HTTP Version Not Supported', 'Cannot fulfill request.'),
}
