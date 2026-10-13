"""Small explicit loopback-only fixture server. No external target connections."""
from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import sys

sys.path.insert(0,str(Path(__file__).parents[1]/'src'))
from reconmap.demo import fixtures


def main() -> None:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port',type=int,default=8765)
    args=parser.parse_args()
    corpus=fixtures()
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            response=corpus.get('https://example.com'+self.path)
            body=response.body if response else b'<title>Missing page</title><p>demo soft 404</p>'
            body=body.replace(b'https://example.com/',(origin+'/').encode())
            self.send_response(response.status if response else 200)
            headers=response.headers if response else {'content-type':'text/html'}
            for key,value in headers.items():self.send_header(key,value.replace('https://example.com/',origin+'/'))
            self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
        def log_message(self,*args):pass
    server=ThreadingHTTPServer(('127.0.0.1',args.port),Handler)
    origin=f'http://127.0.0.1:{server.server_port}'
    print(f'Loopback fixture listening at {origin}; Ctrl+C stops it',flush=True)
    try:server.serve_forever()
    except KeyboardInterrupt:pass
    finally:server.server_close()


if __name__=='__main__':main()
