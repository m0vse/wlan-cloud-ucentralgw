"""Run inside the isolated synthetic gateway container; never against an AP."""
import base64
import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import struct
import time
import urllib.request
import urllib.error

ROOT = Path('/tmp/runtime')
SERIAL = '001122334455'

def publish(version, revoked=()):
    policy = json.loads((ROOT / 'policy.json').read_text())
    policy.pop('expiresAt', None)
    policy.update(version=version, expires=int(time.time()) + 120, revoked=list(revoked))
    path = ROOT / 'policy.next'
    path.write_text(json.dumps(policy))
    path.chmod(0o640)
    path.replace(ROOT / 'policy.json')
    return policy['inventory'][SERIAL]['fingerprints'][0]

def state():
    # Test-only API has authentication disabled and therefore serves HTTP.
    # It is reachable solely inside this network-none container.
    properties = dict(line.split('=', 1) for line in (ROOT / 'owgw.properties').read_text().splitlines()
                      if '=' in line and not line.lstrip().startswith('#'))
    endpoint = next(value.strip() for key, value in properties.items() if key.strip() == 'openwifi.system.uri.public')
    request = urllib.request.Request(f'http://localhost:17002/api/v1/device/{SERIAL}?completeInfo=true',
        headers={'X-INTERNAL-NAME': 'synthetic-session-test', 'X-API-KEY': hashlib.sha256(endpoint.encode()).hexdigest()})
    with urllib.request.urlopen(request, timeout=3) as response:
        return json.load(response)

def connect(name, serial=SERIAL, nonce='a' * 64):
    context = ssl.create_default_context(cafile=str(ROOT / 'root.pem'))
    context.load_cert_chain(str(ROOT / f'{name}.pem'), str(ROOT / f'{name}-key.pem'))
    stream = context.wrap_socket(socket.create_connection(('localhost', 15002), 3), server_hostname='localhost')
    key = base64.b64encode(os.urandom(16)).decode()
    stream.sendall((f'GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n').encode())
    header = bytearray()
    while not header.endswith(b'\r\n\r\n'):
        part = stream.recv(1)
        if not part:
            return stream
        header.extend(part)
    assert b' 101 ' in header, header
    payload = json.dumps({'jsonrpc': '2.0', 'method': 'connect', 'params': {
        'serial': serial, 'uuid': 1, 'firmware': 'synthetic-session-test',
        'capabilities': {'compatible': 'synthetic_test', 'model': 'Synthetic test', 'platform': 'ap'},
        'privateActivationNonce': nonce}}).encode()
    mask = os.urandom(4)
    frame = b'\x81' + (bytes([0x80 | len(payload)]) if len(payload) < 126 else b'\xfe' + struct.pack('!H', len(payload)))
    stream.sendall(frame + mask + bytes(value ^ mask[index % 4] for index, value in enumerate(payload)))
    return stream

def wait_state(predicate):
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        try:
            result = state()
        except urllib.error.HTTPError as error:
            if error.code != 404:
                raise
            result = {'notYetProvisioned': True}
            time.sleep(0.1)
            continue
        if predicate(result):
            return result
        time.sleep(0.1)
    raise AssertionError(result)

if __name__ == '__main__':
    version = int(time.time())
    fp = publish(version)
    good = connect('good')
    accepted = wait_state(lambda value: value['connectionInfo']['connected'])['connectionInfo']
    assert accepted['verifiedCertificate'] == 'VERIFIED', accepted
    assert accepted['privateLeafSha256'] == fp, accepted
    assert accepted['privateActivationNonce'] == 'a' * 64, accepted
    assert accepted['privatePolicyVersion'] == version, accepted
    assert accepted['privateAcceptedAt'] >= accepted['started'], accepted
    session = accepted['sessionId']
    for name, serial in [('other', SERIAL), ('good', 'aabbccddeeff')]:
        refused = connect(name, serial)
        time.sleep(0.3)
        current = state()['connectionInfo']
        assert current['connected'] and current['sessionId'] == session, current
        refused.close()
    publish(version + 1, [fp])
    wait_state(lambda value: not value['connectionInfo']['connected'])
    good.settimeout(3)
    # An established transport is closed, rather than merely hiding API state.
    closed = False
    try:
        while True:
            data = good.recv(8192)
            if not data:
                closed = True
                break
    except (ssl.SSLError, ConnectionError):
        closed = True
    assert closed, 'revoked transport remained open'
    good.close()
    legacy = connect('legacy', nonce='c' * 64)
    retained = wait_state(lambda value: value['connectionInfo']['connected'])['connectionInfo']
    assert retained['privateLeafSha256'] != fp and retained['privateActivationNonce'] == 'c' * 64, retained
    legacy_session = retained['sessionId']
    denied = connect('good')
    time.sleep(0.3)
    retained = state()['connectionInfo']
    assert retained['connected'] and retained['sessionId'] == legacy_session, 'revoked leaf replaced retained legacy session'
    denied.close()
    legacy.close()
    wait_state(lambda value: not value['connectionInfo']['connected'])
    publish(version + 2)
    recovered = connect('good', nonce='b' * 64)
    current = wait_state(lambda value: value['connectionInfo']['connected'])['connectionInfo']
    assert current['sessionId'] > session and current['privateActivationNonce'] == 'b' * 64, current
    policy = json.loads((ROOT / 'policy.json').read_text())
    policy.update(version=version + 3, expires=int(time.time()) + 1)
    next_policy = ROOT / 'policy.next'
    next_policy.write_text(json.dumps(policy))
    next_policy.chmod(0o640)
    next_policy.replace(ROOT / 'policy.json')
    wait_state(lambda value: not value['connectionInfo']['connected'])
    recovered.close()
    print('PASS: actual gateway admission, serial/leaf/nonce/session acceptance, same-serial denial without replacement, established-session revocation, retained legacy CA session during new-leaf revocation, refused revoked reconnect, restored session, and policy expiry disconnection')
