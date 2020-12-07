# ws-debug-tool

Connect to and debug any Websocket end point

```sh
usage: ws-debug-tool.py [-h] [--no-colour] uri

Tool for debugging websockets, providing bidrectional communication.

positional arguments:
  uri          uri of websocket host

optional arguments:
  -h, --help   show this help message and exit
  --no-colour  strips colour from output - useful for piping to files
```

# Example

```sh
$ ./ws-debug-tool.py wss://echo.websocket.org
Execution time: 0.006s | ---- SETUP START ----
echo.websocket.org 443
Execution time: 0.097s | [SENDING WS INITIATE REQUEST]:
GET / HTTP/1.1
Sec-WebSocket-Key: 7QzHbE/L1OkdLKn/uZ4+vg==
Sec-WebSocket-Version: 13
Connection: Upgrade
Upgrade: websocket
Host: echo.websocket.org
Origin: https://echo.websocket.org


Execution time: 0.198s | --HANDSHAKES RECIEVED--
Execution time: 0.198s | [Handshake/Http portion]:
HTTP/1.1 101 Web Socket Protocol Handshake
Connection: Upgrade
Date: Mon, 07 Dec 2020 21:18:43 GMT
Sec-WebSocket-Accept: shetQ6fBoul7jH+vyTB2ORZg3wk=
Server: Kaazing Gateway
Upgrade: websocket
Execution time: 0.198s | Recieved Sec-WebSocket-Accept header: 'shetQ6fBoul7jH+vyTB2ORZg3wk='
Execution time: 0.198s | Sec-WebSocket-Accept header has passed validation.
Execution time: 0.198s | [Handshake/Ws portion]:
(no websocket side handshake from this endpoint)
Execution time: 0.199s | ---- SETUP END ----
Execution time: 0.199s | ---- BEGIN LISTENING ----
Execution time: 0.199s | ---- Stdin daemon started. Duplex communication active ----
```

```sh
# user types in:
Hello, world!
```

```
Execution time: 3.3s | [User sent a message]:
[Websocket frame headers]:
FIN bit set: True
Opcode: 1 (Text Frame)
Masked frame: True
Payload length: 13
Mask key: 0xe58feab3
[Websocket frame payload]:
Hello, world!

Execution time: 3.324s | --RECEIVED MESSAGE #1--
[Websocket frame headers]:
FIN bit set: True
Opcode: 1 (Text Frame)
Masked frame: False
Payload length: 13
[Websocket frame payload]:
Hello, world!
```

```sh
# user enters ^C
^C
```

```sh
Execution time: 3.845s | ---- Exiting, sending unsubs ----
Execution time: 3.845s | Sending close connection frame:
[Websocket frame headers]:
FIN bit set: True
Opcode: 8 (Connection Close)
Masked frame: True
Payload length: 2
Mask key: 0xdeadc0de
Connection close status code: 1000 (Normal closure)
[Websocket frame payload]:
(no payload)

Execution time: 3.845s | Receiving close connection frame:
[Websocket frame headers]:
FIN bit set: True
Opcode: 8 (Connection Close)
Masked frame: False
Payload length: 2
Connection close status code: 1000 (Normal closure)
[Websocket frame payload]:
(no payload)

Execution time: 3.873s | --- Cleanup complete. Goodbye! ----
```
