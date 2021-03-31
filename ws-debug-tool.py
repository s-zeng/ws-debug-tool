#!/usr/bin/python3
import argparse
import atexit
import logging
import os
import socket
import ssl
import threading
import time
import urllib.parse

import WebsocketUtils

start_time = time.time()

log_format = "%(asctime)s | %(levelname)s | %(name)s | line: %(lineno)s | %(message)s | %(created)f"
log_suffix = os.path.splitext(os.path.basename(__file__))[0]
logging.basicConfig(format=log_format, level=logging.DEBUG)
log = logging.getLogger("ws-debug-tool")

# variable for --no-colour flag
do_colour = True


def _colour_log(string: str) -> None:
    """
    Custom logging method that provides time from execution, as well as colouring

    Why use a custom wrapper around print() rather than the built in logging class?
    Two main reasons:
      1) Configurability of colours. I found it difficult and hacky to do this with the built in logger,
         maybe somebody can prove me wrong here
      2) There was no easy way to put execution time in the logger that I found,
         so I would have had to write a wrapper to the logger class that includes execution time anyway
      3) I didn't want line numbers for the printing done with this method, but wanted to keep them for error logging.
         The ways I've found online to make a different format for log.info and log.error are way hackier than this in my
         opinion - this is the cleanest way I've found to seperate out different methods for error logs and printouts
         intended for the consumer of the tool, rather than for debuggers of the tool

    @param string: the string to add colour + timestamp to and print
    """
    # we get time elapsed by subtracting start time from current time, and rounding to 3 decimal places
    log_string = (
        "Execution time: " + str(round(time.time() - start_time, 3)) + "s | " + string
    )

    # unix terminal colour codes - might need changing if we want to support windows...
    # then again to support windows, we would have to change the unix sockets too
    # not worth it to support windows with this code, especially since we have no windows consumers of this tool
    if do_colour:
        log_string = "\033[93m" + log_string + "\033[0m"
    print(log_string)


class WebSocket:
    """
    This class provides an interface to send and recieve data over the websocket protocol

    This is the main class of the web socket debug tool, and includes all the stateful methods required for the tool,
    including i/o, networking, and
    Stateless/pure functions go in the WebsocketUtils class

    Table to summarize:
    Function type | Class
    Stateful      | WebSocket
    Stateless     | WebsocketUtils

    Uses only standard library methods and classes, and adheres to the rfc 6455 ws specs at https://tools.ietf.org/html/rfc6455
    Why rewrite a websocket library when plenty of good ones exists for python already? A few reasons:
        a) educational purposes
        b) to have a class that we can rely on with no external dependenies or licensing issues
        c) HEADERS! None of the websocket libraries I've found allowed for proper inspection of the websocket headers
    """

    def __init__(self, host: str, port: int, enable_ssl: bool) -> None:
        """
        Init method

        @param host: the host ip/domain to connect to, e.g. 'tools01-qa-integration.cenx.localnet'
        @param port: the port that we are connecting to. usually identical to the http port e.g. '8080'
        """
        # we use AF_INET in the socket protocol argument because we're communicating via ipv4
        # if we want to support ipv6 in the future, we will need to change this

        # and we use SOCK_STREAM for TCP; no reason to change this ever
        # unless the server starts using udp for some reason lol
        self.normal_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.host = host
        self.port = port

        # Message to display when integrity validation fails
        self.failed_validation_message = "\033[41m\033[1m\033[4m\033[5mWARNING: INVALID SEC-WEBSOCKET-ACCEPT HEADER. DATA MAY BE COMPROMISED!\nExpected '{expected}', but got '{actual}'\033[0m"

        # Boolean for whether or not we have recieved a close connection frame
        self.recieved_close_connection = False

        self.ssl = enable_ssl
        try:
            # if ssl is enabled, we wrap the socket here
            if self.ssl:
                self.socket = ssl.wrap_socket(
                    self.normal_socket, ssl_version=ssl.PROTOCOL_SSLv23
                )
            else:
                self.socket = self.normal_socket

            # double bracketing is not a mistake - the socket constructor takes a single tuple of size 2
            # as its sole argument, rather than taking two arguments
            print(self.host, self.port)
            self.socket.connect((self.host, self.port))
        except socket.gaierror as e:
            log.error(
                "Address resolution failed - make sure host and port are correct and that dns servers are functional"
            )
            raise (e)
        except ConnectionRefusedError as e:
            log.error(
                "Connection refused - make sure host and port are correct and that host is up"
            )
            raise (e)
        except ssl.SSLError as e:
            log.error(
                "SSL error - ensure that port is correct, and that the endpoint supports ssl"
            )
            raise (e)
        except Exception as e:
            log.error("Misc exception")
            raise (e)

    def interactive_mode(self) -> None:
        """
        Method that reads from the websocket and pretty prints incoming messages, while allowing for user to send messages concurrently

        This method uses a stdin daemon thread for reading and sending arbitrary ws messages, while constantly listening for
        incoming messages from the server.
        """
        _colour_log("---- BEGIN LISTENING ----")

        # initiate the send from stdin daemon
        thread = threading.Thread(target=self.send_from_stdin)
        # we set the thread as a daemon so that it exits when the main program exits
        # otherwise, the thread will stay alive after the main program terminates,
        # and thats no good for this
        thread.daemon = True
        thread.start()

        # initialize a counter for counting # of messages recieved from the server so far
        messages_recieved = 1

        # possible first bytes for a websocket message inclue 0-15, and 128 + 0-15 (if fin bit is set)
        # since we are operating under the assumption that the server always sends messages with fin bit set,
        # then we reflect that assumption in the list of possible first bytes that we accept
        # theoretically, there's no reason this code can't handle fragmented messages
        # but that faculty is untested as of yet, so i'm excluding it for now.
        # you're free to try it in the future though
        possible_first_bytes = [128 + x for x in range(16)]

        while True:
            next_char = self.read_blocking_strict(1)

            # if sec-websocket-accept validation fails, then rfc6455 states that
            # the client MUST end the connection. however, since this is a debug tool,
            # it can be useful to read the data that comes with an invalid ws-accept header
            # regardless, we take every opportunity to remind the user of the
            # potential of a comprimised connection that is possible when the validation fails
            if not self.passed_validation:
                log.error(self.failed_validation_message)

            # once the server does send something, we check to see if the first byte is something we expect
            # NOTE: this assumes that every message the server sends has fin bit set, and has opcode 0x01
            if next_char[0] in possible_first_bytes:
                _colour_log(f"--RECEIVED MESSAGE #{messages_recieved}--")

                # we then start forming a string with the contents being the raw message from the server
                message_string = next_char

                # the next byte in a websocket transmission is the length byte, so we read that here
                # we then concat that byte to the message_string too
                length = self.read_blocking_strict(1)
                message_string += length

                # rfc6455 states that a length byte of 126 or 127 means that the next 2 or 8 (respectivly) bytes
                # are the actual length, if the actual length is greater than 126 or 2**16 respectively
                # this if branch checks for that, and ensures that we have the correct length in the end
                # NOTE: if we start getting masked data (which SHOULD never happen, if rfc6455 is properly adhered to),
                # then uncomment the following lines (more explanation further below):
                # if length[0] > 128:
                #    mask_bit = True
                #    length[0] = length[0] - 128 #length might be immutable here, and if so, this won't work
                #                                #if it is immutable, try this: length = bytes([length[0] - 128])
                # else:
                #    mask_bit = False
                if length[0] == 126:
                    temp = self.read_blocking_strict(2)
                    message_string += temp
                    length = WebsocketUtils.byte_list_to_int(temp)
                elif length[0] == 127:
                    temp = self.read_blocking_strict(8)
                    message_string += temp
                    length = WebsocketUtils.byte_list_to_int(temp)
                else:
                    length = length[0]

                # once we have the length, we then read the rest of the message by reading {length} amount of bytes
                # NOTE: this assumes that the server sends unmasked frames. if they adhere to the server specs
                # outlined in rfc6455, then this shouldn't be a problem. However, if the data is masked, then few things go wrong:
                # 1) the first bit of the length byte is actually the mask bit, and if that's set to true,
                #    then the actual length byte should be 128 less than what's read
                # 2) there are four bytes of mask key before the actual data, and of course,
                # 3) the data itself is masked!
                # if in the future, we start seeing masked data from the server for whatever reason (should be obvious in the output,
                # since we will be 4 bytes off of the end of each message everytime, we will get unexpected first byte and the last four
                # bytes of masked data will get printed raw via the else branch below), then uncomment the following lines (+ the ones above):
                # if mask_bit:
                #    mask_key = self.read_blocking_strict(4)
                #    message_string += mask_key
                payload = self.read_blocking_strict(length)
                message_string += payload
                print(WebsocketUtils.ws_pretty_format(message_string))
                messages_recieved += 1

                # close connection frame handling (check for opcode in first byte)
                if next_char[0] == 136:
                    self.recieved_close_connection = True
                    _colour_log("Recieved close connection frame, now exiting")
                    exit(
                        0
                    )  # should we exit with 0 or 1 if server sends a close connection frame?

                # ping/pong handling (check for opcode in first byte)
                if next_char[0] == 137:
                    # form the pong message with the same payload as the ping, and send it through
                    # we turn it into a bytearray to make it mutable, then back to bytes for sending
                    pong = bytearray(WebsocketUtils.generate_request(payload))
                    pong[
                        0
                    ] = 138  # generate_request uses the text frame opcode - here we replace that with the pong opcode
                    pong = bytes(pong)

                    _colour_log("Recieved ping, sending pong: ")
                    print(WebsocketUtils.ws_pretty_format(pong))
                    self.socket.send(pong)

            else:
                log.error(
                    f"Unexpected first byte! Recieved value of {hex(next_char[0])}, but expected value in range [0x80,0x90)"
                )
                log.error(
                    f"Rest of message following the unexpected byte:\n{self.read_currently_available()}"
                )

    def read_currently_available(self) -> bytes:
        """
        Method that returns the current contents of the websocket connection buffer.

        @return: byte string of the current contents of the websocket connection buffer
        """
        output = b""
        old_size = 0  # explanation below

        # we set socket to non-blocking so that we can break as soon as there's no data left
        self.socket.setblocking(False)
        while True:
            try:
                output += self.socket.recv(1)
                if len(output) == old_size:
                    # this merits some explanation. for a non-blocking socket, there are three things that can happen upon a read:
                    # 1) we get a byte. in this case, the byte gets appended to output, and we're all happy.
                    # 2) the socket blocks, but since it's in non-blocking mode, we get  BlockingIOError instead.
                    #    this happens when the socket is still open, but data just isn't being sent
                    # 3) the socket doesn't block, but simply returns null (aka b'', not b'\x00')
                    #    this case only happens when the server closes the connection but the client doesn't,
                    #    and is why this if branch and the old_size handling exists
                    log.error("Socket read returned null, socket closed??")
                    log.error("Data recieved so far:\n" + repr(output))
                    raise (EOFError("Socket closed?"))
                else:
                    # ensure that old_size is following the actual size on succesful reads
                    # old_size should always be 1 less than len(output)
                    old_size += 1
            except (BlockingIOError, ssl.SSLWantReadError):
                self.socket.setblocking(
                    True
                )  # the rest of the program assumes blocking socket, so we set it back here
                return output

    def read_blocking(self, size: int) -> bytes:
        """
        Simple wrapper to a blocking read from the socket.

        Note that due to a behaviour of the underlying socket object, this method doesn't guarantee
        that the output is of size 'size'. Rather, the blocking read also breaks when the underlying tcp
        connection sends a fin packet. As such, in order to guarantee a full blocking read, use self.read_blocking_strict()

        @param size: how many bytes to read from the socket

        @return: a bytestring of the bytes read
        """
        return self.socket.recv(size)

    def read_blocking_strict(self, size: int) -> bytes:
        """
        Method that reads a set amount of bytes from the socket, and doesn't return until it gets that many bytes

        Unlike a naive blocking read, this one doesn't terminate on TCP fin packets;
        it returns if and only if it has read {size} bytes from the socket

        @param size: how many bytes to read from the socket

        @return: a bytestring of the bytes read
        """
        output = b""

        # we set socket to non-blocking so that we can handle exactly when we break and stop reading
        self.socket.setblocking(False)
        while len(output) < size:
            try:
                output += self.socket.recv(1)
            except (BlockingIOError, ssl.SSLWantReadError):
                pass
        self.socket.setblocking(True)
        return output

    def ws_connect(self, endpoint: str) -> None:
        """
        Method that initiates the websocket handshake with a given auth token, and sends in applicable websocket requests on the newly opened connection.

        This method also checks then handshake for the 'Sec-WebSocket-Accept' header, and ensures that it is valid.
        If it is not valid, rfc6455 declares that the connection MUST NOT be accepted

        @param endpoint: the endpoint to connect to to initiate a websocket connection with the server
        """
        # create a key used for the 'Sec-WebSocket-Key' field in the client side of the handshake
        # we also prepare the expected ws_accept header for that key, for comparison to the header
        # that the server sends us
        ws_key = WebsocketUtils.create_websocket_key()
        expected_ws_accept = WebsocketUtils.expected_sec_websocket_accept_header(ws_key)

        if self.ssl:
            protocol = "https"
        else:
            protocol = "http"
        # initialize the request we send with the user provided endpoint
        ws_initiate_request = f"GET {endpoint} HTTP/1.1\r\nSec-WebSocket-Key: {ws_key}\r\nSec-WebSocket-Version: 13\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nHost: {self.host}\r\nOrigin: {protocol}://{self.host}\r\n\r\n"

        _colour_log("[SENDING WS INITIATE REQUEST]:")
        print(ws_initiate_request)
        try:
            self.socket.send(ws_initiate_request.encode())
            time.sleep(
                0.1
            )  # make this configurable? or make the next line two blocking reads?

            handshakes = self.read_currently_available().split(b"\r\n\r\n")

            _colour_log("--HANDSHAKES RECIEVED--")
            _colour_log("[Handshake/Http portion]:")
            print(handshakes[0].decode())

            headers = handshakes[0].decode().split()

            # we form an all lowercase version of the headers list for searching purposes,
            # since not every endpoint is consistent about their casing...
            headers_lowercase = handshakes[0].decode().lower().split()

            # grab the Sec-WebSocket-Accept header from the handshake
            # if it's not there, then we exit
            try:
                ws_accept = headers[
                    headers_lowercase.index("sec-websocket-accept:") + 1
                ]
            except ValueError as e:
                log.error(
                    "Sec-WebSocket-Accept header not present... ensure that the endpoint is correct"
                )
                raise (e)
            _colour_log(f"Recieved Sec-WebSocket-Accept header: '{ws_accept}'")

            # check if what the server gave for that header is the same as what we expect
            # if not, it's indicative of a compromised connection
            self.passed_validation = ws_accept == expected_ws_accept

            if self.passed_validation:
                _colour_log(f"Sec-WebSocket-Accept header has passed validation.")
            else:
                # do note that rfc6455 states that a client MUST terminate the connection
                # if it gets an improper Sec-WebSocket-Accept header from the server
                # we don't do that here so that we can use the tool to debug
                # those compromised connections when they happen
                # we do, however, remind the user of the state of the connection with
                # big flashing red text (that can't be decolourized with --no-colour)
                self.failed_validation_message = self.failed_validation_message.format(
                    expected=expected_ws_accept, actual=ws_accept
                )
                log.error(self.failed_validation_message)

            _colour_log("[Handshake/Ws portion]:")
            try:
                print(WebsocketUtils.ws_pretty_format(handshakes[1]))
            except IndexError:
                print("(no websocket side handshake from this endpoint)")

        except OSError as e:
            log.error("OSError - socket seems to be closed?")
            raise (e)

    def send_from_stdin(self) -> None:
        """
        Method that constantly reads from stdin, and sends whatever it recieves through the websocket

        Used in a daemon thread to allow for interactive i/o with a websocket
        """
        _colour_log("---- Stdin daemon started. Duplex communication active ----")
        try:
            while True:
                # this is a probably a good place to explain some of the weird
                # ideosyncracies that happen with the input daemon
                # first of all, python's input() captures ALL input from the user,
                # as far as i can tell. that means, for example, that ^D
                # gets caught by the daemon and not the tty. this also results in
                # being unable to press up arrow for history, or left/right arrow
                # to seek in the text, since pressing an arrow key simply inputs
                # the literal terminal bytes that arrow keys represent
                # e.g. left arrow inserts 0x1b5b44 (which the terminal prints as
                # "^[[D"), instead of moving left one character
                usr_input = input()
                if usr_input:
                    request = WebsocketUtils.generate_request(usr_input)
                else:
                    continue
                print()
                _colour_log("[User sent a message]:")
                print(WebsocketUtils.ws_pretty_format(request))
                self.socket.send(request)
                # eval(input())
        except EOFError:  # happens when user sends ^D
            _colour_log(
                "---- Stdin daemon terminated. Websocket reading will continue ----"
            )

    def clean_up(self) -> None:
        """
        Closes the websocket in a clean manner
        """
        # set the socket to blocking for cleaning up to guarantee getting server reply to close connection frame
        self.socket.setblocking(True)

        # check if program exited because of a close connection frame
        # if thats the case, then the connection is closed and we shouldn't bother reclosing
        if not self.recieved_close_connection:
            _colour_log("---- Now exiting... ----")
            try:
                # we send in the websocket byte code for a masked 'Close Connection (normal)'
                close_connection_frame = WebsocketUtils.close_connection
                _colour_log("Sending close connection frame:")
                print(WebsocketUtils.ws_pretty_format(close_connection_frame))
                self.socket.send(close_connection_frame)

                # we then try to read the final reply from the server
                _colour_log("Receiving close connection frame: ")
                # magic number 4 here since rfc6455 spec says server should reply with
                # a particular 4 byte long message (aka b'\x88\x02\x03\xe8')
                print(WebsocketUtils.ws_pretty_format(self.read_blocking(4)))

            except OSError as e:
                log.error(
                    "OSError - socket seems to be closed?"
                )
                raise (e)

        self.socket.shutdown(socket.SHUT_WR)
        self.socket.close()
        _colour_log("--- Cleanup complete. Goodbye! ----")


if __name__ == "__main__":
    # handling arguments
    arg_parser = argparse.ArgumentParser(
        description="Tool for debugging websockets, providing bidrectional communication."
    )
    arg_parser.add_argument("uri", help="uri of websocket host")
    arg_parser.add_argument(
        "--no-colour",
        action="store_true",
        help="strips colour from output - useful for piping to files",
    )

    args = arg_parser.parse_args()

    if args.no_colour:
        do_colour = False

    _colour_log("---- SETUP START ----")

    parsed = urllib.parse.urlparse(args.uri)

    if parsed.scheme == "wss":
        do_ssl = True
        port = 443
    elif parsed.scheme == "ws":
        do_ssl = False
        port = 8080
    else:
        print(f"Improper scheme: given {parsed.scheme}, expected 'ws' or 'wss'")
        exit(0)

    websocket = WebSocket(parsed.netloc, port, do_ssl)

    if not parsed.path:
        path = "/"
    else:
        path = parsed.path

    websocket.ws_connect(path)

    _colour_log("---- SETUP END ----")

    atexit.register(websocket.clean_up)
    try:
        websocket.interactive_mode()
    except KeyboardInterrupt:
        # gets rid of ugly traceback text when exiting
        exit(0)
