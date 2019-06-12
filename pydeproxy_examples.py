import deproxy

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
            print(name)
            print(value)
            wfile.write("%s: %s\r\n" % (name, value))
        wfile.write("%s: %s\r\n" % ('Content-Length', '0'))
        wfile.write("%s: %s\r\n" % ('Connection', 'close'))
        wfile.write("\r\n")

        if response.body is not None and len(response.body) > 0:
            wfile.write(response.body)
        if response.headers["Connection"] and response.headers["Connection"].lower == 'close':
            wfile.close()
        # wfile.close()


def test_handler(req):
    return deproxy.Response(200, message='OK', headers={'Content-Length': '0', 'Test-Header': 'this is a test header'})

dp = deproxy.Deproxy()
# ep = dp.add_endpoint(port=9999, responder=CustomResponder())
# ep = dp.add_endpoint(port=9999, set_reserved_headers=False)
ep = dp.add_endpoint(port=9999)
mc = dp.make_request(url='http://localhost:9999', default_handler=test_handler)
print(mc.received_response)
print(mc)