"""Real loopback TLS with delayed masked frame fragments; never contacts APs."""
import base64, os, socket, ssl, struct, subprocess, sys, tempfile, time
from pathlib import Path

def frame(payload, opcode=1):
    mask=b'\x12\x34\x56\x78'
    header=bytes([0x80|opcode,0x80|len(payload)]) if len(payload)<126 else bytes([0x80|opcode,0xfe])+struct.pack('!H',len(payload))
    return header+mask+bytes(v^mask[i%4] for i,v in enumerate(payload))

def recv_exact(s,n):
    b=b''
    while len(b)<n:
        p=s.recv(n-len(b))
        if not p:raise AssertionError('unexpected transport disconnect')
        b+=p
    return b

with tempfile.TemporaryDirectory(prefix='gateway-ws-synthetic-') as tmp:
    p=Path(tmp);key=p/'key.pem';cert=p/'cert.pem'
    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(cert),'-days','1','-subj','/CN=localhost'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    server=subprocess.Popen([sys.argv[1],str(key),str(cert)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    hello=server.stdout.readline().strip()
    if not hello:
        raise RuntimeError('Synthetic server startup failed: '+server.stderr.read())
    print(hello);port=int(hello.split()[1])
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);ctx.check_hostname=False;ctx.verify_mode=ssl.CERT_NONE
    passed=0;failure=None
    try:
        for splits in ([1],[2],[3],[4],[5],[6],[7],[8],[9],[10],[14],[20],[100],[511],[1,2,3,4,5,6,7,8,20,100]):
            with ctx.wrap_socket(socket.create_connection(('127.0.0.1',port),timeout=3),server_hostname='localhost') as s:
                s.settimeout(3)
                nonce=base64.b64encode(os.urandom(16)).decode()
                s.sendall(('GET /synthetic HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: '+nonce+'\r\n\r\n').encode())
                headers=b''
                while not headers.endswith(b'\r\n\r\n'):headers+=recv_exact(s,1)
                assert b'101 Switching Protocols' in headers
                time.sleep(0.04)
                data=frame(b'x'*512);last=0
                for end in splits:
                    s.sendall(data[last:end]);last=end;time.sleep(0.025)
                s.sendall(data[last:]);assert recv_exact(s,4)==b'\x81\x02OK';passed+=1
                s.sendall(frame(b'',9));assert recv_exact(s,2)==b'\x8a\x00';passed+=1
                s.sendall(frame(b'x'*512));assert recv_exact(s,4)==b'\x81\x02OK';passed+=1
                s.sendall(frame(b'',8));time.sleep(0.01)
        # A real EOF is not mistaken for another partial read or kept alive.
        passed+=1
    except Exception as e:
        failure=type(e).__name__+': '+str(e)
    finally:
        out,err=server.communicate('stop\n',timeout=10)
    print(out.strip())
    if failure or server.returncode:
        print('FAIL',failure or 'server error');print(err.strip());sys.exit(1)
    assert 'MESSAGES 30 ERRORS 0' in out,out
    print('PASS',passed,'native delayed TLS/WebSocket partial-frame, heartbeat and continued-session checks; synthetic loopback only')
