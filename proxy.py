import socket, traceback, threading, re


def load_blacklist(path):
    with open(path, 'rb') as f:
        lines = f.read().splitlines()
        expr = b'|'.join(lines)
        match = re.compile(expr).search
        return lambda x: bool(match(x))
        

def recv_all(sock, timeout=1, recv_size=1024):
    result = b''
    sock.settimeout(timeout)
    try:
        while 1:
            data = sock.recv(recv_size)
            result += data
            if not data:
                break
    except: 
        pass
    return result


def get_request_info(req_bytes):
    try:
        hdr, body = req_bytes.split(b'\r\n\r\n')
        rline, *rheaders = hdr.splitlines()
        method, url, version = rline.split()
        headers = dict(map(lambda x: x.lower().split(b': ', 1), rheaders))
        return url.decode(), headers.get(b'host', '').decode(), \
            method.lower().decode(), body, headers
    except:
        return [None] * 5


def tunnel(client, server):
    while 1:
        req = recv_all(client)
        if not req: break
        server.sendall(req)
        res = recv_all(server)
        if not res: break
        client.sendall(res)


def connect(host):
    host, *port = host.split(':', 1)
    port = int(port[0]) if port else 80
    sock2 = socket.socket()
    sock2.connect((host, port))
    return sock2


def on_connection(conn, addr, is_blacklisted):
    req_bytes = recv_all(conn)
    url, host, method, *_ = get_request_info(req_bytes)
    if host is None: 
        return
    if is_blacklisted(host.encode()):
        print('>> rejected', host, url)
        conn.sendall(b'HTTP/1.0 423 Locked\r\nContent-Length: 10\r\n\r\n423 Locked')
    else:
        sock2 = connect(host)
        if method == 'connect':
            print('>> tunneling', host, url)
            conn.sendall(b'HTTP/1.1 200 OK\r\n\r\n')
            tunnel(conn, sock2)
        else:
            print('>> forwarding', host, url)
            sock2.sendall(req_bytes)
            received = recv_all(sock2)
            conn.sendall(received)
        sock2.close()


def on_conn_async(conn, addr, is_blacklisted):
    try:
        on_connection(conn, addr, is_blacklisted)
    except:
        traceback.print_exc()
    conn.close()


def main(is_blacklisted, proxy_addr):
    sock = socket.socket()
    sock.bind(proxy_addr)
    sock.listen(15)
    print('>> launched adblock proxy at {}:{}'.format(*proxy_addr))
    while 1:
        conn, addr = sock.accept()
        args = (conn, addr, is_blacklisted)
        t = threading.Thread(target=on_conn_async, args=args)
        t.daemon = True
        t.start()


if __name__ == '__main__':
    is_blacklisted = load_blacklist('blacklist.txt')
    proxy_addr = ('localhost', 27500)
    main(is_blacklisted, proxy_addr)