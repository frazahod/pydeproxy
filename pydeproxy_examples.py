import ssl
import urlparse
import socket
import deproxy
import tornado
from tornado import httpclient
import threading

# Example socket based responder
class CustomResponder:
    def send_response(self, wfile, response):
        """
        Send the given Response over the socket. Add Server and Date headers
        if not already present.
        """

        message = response.message
        wfile.write("HTTP/1.1 %s %s\r\n" %
                    (response.code, message))

        for name, value in response.headers.iteritems():
            wfile.write("%s: %s\r\n" % (name, value))
        wfile.write("\r\n")

        if response.body is not None and len(response.body) > 0:
            wfile.write(response.body)
        if response.headers["Connection"] and response.headers["Connection"].lower == 'close':
            wfile.close()

# Example socket based requestor
class CustomRequestor:
    def send_request(self, url, request, ssl_options=None, verify=None):
        urlparts = list(urlparse.urlsplit(url, 'http'))
        scheme = urlparts[0]
        host = urlparts[1]
        urlparts[0] = ''
        urlparts[1] = ''
        path = urlparse.urlunsplit(urlparts)
        hostparts = host.split(':')
        if len(hostparts) > 1:
            port = hostparts[1]
        else:
            if scheme == 'https':
                port = 443
            else:
                port = 80
        hostname = hostparts[0]
        hostip = socket.gethostbyname(hostname)
        request_line = '%s %s HTTP/1.1\r\n' % (request.method, path if path else '/')
        print(request_line)
        lines = [request_line]

        for name, value in request.headers.iteritems():
            lines.append('%s: %s\r\n' % (name, value))
        lines.append('\r\n')
        if request.body is not None and len(request.body) > 0:
            lines.append(request.body)

        address = (hostname, port)
        if scheme == 'https':
            s = self.create_ssl_connection(address)
        else:
            s = socket.create_connection(address)

        s.send(''.join(lines))

        rfile = s.makefile('rb', -1)

        response_line = rfile.readline(65537)
        if (len(response_line) > 65536):
            raise ValueError
        response_line = response_line.rstrip('\r\n')

        words = response_line.split()

        proto = words[0]
        code = words[1]
        message = ' '.join(words[2:])

        response_headers = deproxy.HeaderCollection.from_stream(rfile)
        body = read_body_from_stream(rfile, response_headers)
        response = deproxy.Response(code, message, response_headers, body)

        return response

    def create_ssl_connection(self, address,
                              timeout=socket._GLOBAL_DEFAULT_TIMEOUT,
                              source_address=None):
        host, port = address
        err = None
        for res in socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM):
            af, socktype, proto, canonname, sa = res
            sock = None
            try:
                sock = socket.socket(af, socktype, proto)
                sock = ssl.wrap_socket(sock)

                if timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:
                    sock.settimeout(timeout)
                if source_address:
                    sock.bind(source_address)
                sock.connect(sa)
                return sock

            except socket.error as _:
                err = _
                if sock is not None:
                    sock.close()

def read_body_from_stream(stream, headers):
    if ('Transfer-Encoding' in headers and
            headers['Transfer-Encoding'] not in ['identity', 'chunked']):
        raise NotImplementedError
    elif 'Transfer-Encoding' in headers and headers['Transfer-Encoding'] == 'chunked':
        body = ""
        while True:
            line = stream.readline()
            i = line.find(';')  # ignore extenstions
            if i >= 0:
                line = line[:i]
            chunk_length = int(line, 16)
            if chunk_length == 0:
                break

            body = body + stream.read(chunk_length)
            stream.read(2)  # remove CRLF

    elif 'Content-Length' in headers:
        # 3
        length = int(headers['Content-Length'])
        body = stream.read(length)
    elif False:
        raise NotImplementedError
    else:
        body = None
    return body

# Template naive proxy
class MainHandler(tornado.web.RequestHandler):
    def get(self):
        # Route by path
        aux_port = self.request.path.split('/')[-1]
        service_port = self.request.path.split('/')[-2]

        http_client = httpclient.HTTPClient()
        try:
            # Generate requests to forward
            aux_request = clone_request(self.request)
            service_request = clone_request(self.request)
            aux_request.url = "http://localhost:" + aux_port + '/' + self.request.uri
            service_request.url = "http://localhost:" + service_port + '/' + self.request.uri

            # Make requests
            aux_response = http_client.fetch(aux_request)
            service_response = http_client.fetch(service_request)

            # Respond to client
            self.set_status(service_response.code, service_response.reason)
            for k, v in service_response.headers.get_all():
                self.set_header(k,v)
            self.write(service_response.body)

        except httpclient.HTTPError as e:
            # HTTPError is raised for non-200 responses; the response
            # can be found in e.response.

            # Catch possible 401 from aux service
            self.set_status(e.response.code, e.response.reason)
            for k, v in e.response.headers.get_all():
                self.set_header(k, v)
            self.write(e.response.body)
        except Exception as e:
            print(e)

        http_client.close()
        self.flush()

def clone_request(source):
    return httpclient.HTTPRequest('', source.method,source.headers, None)

def make_app():
    return tornado.web.Application([
        (r"/.*", MainHandler),
    ])

def test_handler(req):
    return deproxy.Response(200, message='OK')

def auth_handler(req):
    if req.path.split('?')[-1] == 'true':
        return deproxy.Response(200, message='OK', headers=req.headers)
    else:
        return deproxy.Response(401, message='OK', headers=req.headers, body='unauthorized')

def service_handler(req):
    h = {'Service-Header': 'I is a service'}
    h.update(req.headers)
    return deproxy.Response(200, message='OK', headers=h, body="Hi! I am a service!")

#PROXY
def start_proxy():
    application = make_app()
    application.listen(8888)
    tornado.ioloop.IOLoop.current().start()


def run_proxy():
    dp = deproxy.Deproxy()

    auth_port = 9997
    service_port = 9998

    threading.Thread(target=start_proxy).start()
    auth_ep = dp.add_endpoint(port=auth_port, default_handler=auth_handler)
    service_ep = dp.add_endpoint(port=service_port, default_handler=service_handler)

    mc = dp.make_request(url='http://localhost:8888/{}/{}'.format(service_port, auth_port))
    for handling in mc.handlings:
        print(handling.request)
        print(handling.response)

    mc2 = dp.make_request(url='http://localhost:8888/{}/{}?true'.format(service_port, auth_port))
    for handling in mc2.handlings:
        print(handling.request)
        print(handling.response)

    print(mc.sent_request)
    print(mc.received_response)

    auth_ep.shutdown()
    service_ep.shutdown()

def use_custom_requester_responder():
    dp = deproxy.Deproxy()

    ep1 = dp.add_endpoint(port=9997)
    ep2 = dp.add_endpoint(port=9998, responder=CustomResponder())
    ep3 = dp.add_endpoint(port=9999, set_reserved_headers=False)
    mc1 = dp.make_request(url='http://localhost:9997')
    mc2 = dp.make_request(url='http://localhost:9998', default_handler=test_handler)
    mc3 = dp.make_request(url='http://localhost:9999', default_handler=test_handler, requestor=CustomRequestor())
    print(mc1.handlings[0].request)
    print(mc1.handlings[0].response)
    print(mc2.handlings[0].request)
    print(mc2.handlings[0].response)
    print(mc3.handlings[0].request)
    print(mc3.handlings[0].response)

def main():
    run_proxy()
    use_custom_requester_responder()

main()