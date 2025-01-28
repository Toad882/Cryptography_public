import threading
import http.server
import ssl
import os
import json

# Define the handler to serve the index.html file
class MyHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.path = 'index.html'
        return http.server.SimpleHTTPRequestHandler.do_GET(self)

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        response = {
            "message": "Login successful"
        }
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(bytes(json.dumps(response), 'utf-8'))

# Define the handler to serve the indexfake.html file and handle /download
class FakeHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.path = 'indexfake.html'
        elif self.path == '/download':
            self.send_response(200)
            self.send_header('Content-type', 'application/zip')
            self.send_header('Content-Disposition', 'attachment; filename="FrecciarossaBank.zip"')
            self.end_headers()
            with open('FrecciarossaBank.zip', 'rb') as file:
                self.wfile.write(file.read())
        else:
            self.send_error(404, "File not found")
        return http.server.SimpleHTTPRequestHandler.do_GET(self)

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        response = {
            "message": "Fake login successful"
        }
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(bytes(json.dumps(response), 'utf-8'))

# Set the directory to the location of index.html
os.chdir(os.path.dirname(os.path.abspath(__file__)))

# Create the first server
server_address1 = ('localhost', 8443)
httpd1 = http.server.HTTPServer(server_address1, MyHTTPRequestHandler)

# Create an SSL context for the first server
context1 = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
try:
    context1.load_cert_chain(certfile="Website.pem", keyfile="website_private.pem")
except Exception as e:
    print(f"Error loading certificate or key for server 1: {e}")
    exit(1)

# Wrap the first server socket with SSL
httpd1.socket = context1.wrap_socket(httpd1.socket, server_side=True)

# Create the second server
server_address2 = ('localhost', 8444)
httpd2 = http.server.HTTPServer(server_address2, FakeHTTPRequestHandler)

# Create an SSL context for the second server
context2 = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
try:
    context2.load_cert_chain(certfile="fakewebsite.pem", keyfile="fakewebsite_private.pem")
except Exception as e:
    print(f"Error loading certificate or key for server 2: {e}")
    exit(1)

# Wrap the second server socket with SSL
httpd2.socket = context2.wrap_socket(httpd2.socket, server_side=True)

# Function to start the first server
def start_server1():
    print("Serving on https://localhost:8443")
    httpd1.serve_forever()

# Function to start the second server
def start_server2():
    print("Serving on https://localhost:8444")
    httpd2.serve_forever()

# Start both servers in separate threads
thread1 = threading.Thread(target=start_server1)
thread2 = threading.Thread(target=start_server2)
thread1.start()
thread2.start()
thread1.join()
thread2.join()