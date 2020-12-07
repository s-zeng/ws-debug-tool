import base64
import hashlib
import itertools
import os
from typing import Sequence, Union

"""
Helper module for the websocket debug tool.

Contains all static and pure functions used by the tool.
"""

# constant that holds the frame we send in when we want to close the connection
# break down of the message:
#   \x88 = 0x80 + 0x08, which when in the first byte of a message means FIN bit set, and opcode 8 (close message)
#   \x82 = 0x80 + 0x02, which when in the second byte of a message means Mask bit set (this is a masked message), and payload length is 2
#   \xde\xad\xc0\xde = the mask key. doesn't really matter that it's hardcoded here, since the security provided by the masking process is not needed for the close message frame here
#   \xdd\x45 = \x03\xe8 unmasked, which is 1000 in decimal. 1000 is the status code for a normal websocket connection closure
close_connection: bytes = b"\x88\x82\xde\xad\xc0\xde\xdd\x45"


def create_websocket_key() -> str:
    """
    Creates a base64 encoded string of random bytes for use with the 'Sec-Websocket-Key' header in the HTTP part of the websocket handshake.

    See section 1.2 and 1.3 of the rfc6455 ws specs: https://tools.ietf.org/html/rfc6455#section-1.2

    @return: 16 bytes of random data encoded in base64
    """
    return base64.encodebytes(os.urandom(16)).decode("utf-8").strip()


def create_ws_mask_key() -> bytes:
    """
    Provides a key to mask websocket data sent from client, as required per section 5.3 of rfc6455.

    Used along with xor(data, key)
    See sections 5 and 10.3 of rfc6455 for more details: https://tools.ietf.org/html/rfc6455#section-5

    @return: 4 random bytes
    """
    return os.urandom(4)


def xor(data: Sequence[int], key: Sequence[int]) -> bytes:
    """
    Helper method that performs bitwise xor on two byte strings.

    Used along with create_ws_mask_key(), which provides the key which we xor the data with

    @param data: websocket payload to mask, as a bytes object
    @param key: masking key (provided by create_ws_mask_key()). should also be a bytes object

    @return: the data xored with the key in a repeating-key manner
    """
    return bytes(a ^ b for a, b in zip(data, itertools.cycle(key)))


def generate_request(request_str: Union[bytes, str]) -> bytes:
    """
    Method that does the grunt work of forming the websocket request, adhering to rfc6455 as strictly as possible

    Forms the appropriate websocket protocol header (including appropriate handling of payload length in the header,
    as well as inclusion of the masking key), then attaches the masked payload at the end.
    See section 5 (particularly 5.2) of rfc6455 for details: https://tools.ietf.org/html/rfc6455#section-5

    @param request_str: payload of ws request

    @return: a properly encoded websocket request with the given payload
    """

    # Note that we are not fully rfc6455 compliant here for all possible ws communications, in that we are making the following assumptions:
    #   a) the FIN bit is set, in other words, we are assuming that each request we are generating is the final fragment in a message (i.e. that we are only sending one fragment messages)
    #      this is true for all data sent by a 7.0 system
    #   b) the server is/has not negotiated any ws protocol extensions, and therefore the rsv1, rsv2, and rsv3 bits are always set to 0
    #   c) we are sending only text frames, and therefore we have a ws opcode of %x1
    # All these assumptions hold true for a 7.0 system as far as I've tested, and therefore the first byte of the header has been hardcoded to a value of
    # 0d129 = 0x81 = 0b10000001
    # To wrap up, here's a breakdown of the first byte: (paraphrasing sec 5.2 of rfc6455)
    #   1  |  0  |  0  |  0  |  0  |  0  |  0  |  1
    #  FIN   RSV1  RSV2  RSV3  OP    OP    OP    OP
    # Should any of the aforementioned assumptions change in future versions, then logic must be added in the setting of this byte. for now, hardcoding the value
    # satisfies all current use cases, with the exception of pong responses to ping requests from the server.
    # note that while are breaking rfc6455 by not sending pong responses, this doesn't seem to affect the connection in anyway,
    # since rfc6455 is ambiguous on the consequences of missed pongs and our current server implementation doesn't do anything about it
    # TODO: implement proper ping/pong handling. this is probably most easily done in the main classes interactive_mode() method
    # an addendum - it seems like ping requests from cenx servers aren't proper ping requests (opcode 0x09)
    # but just regular text data messages (opcode 0x01) with "ws-ping" as a payload...
    # as such, proper ping/pong handling on my side can't be implemented until proper ping/pong handling
    # is implemented server side!
    ws_header = [129]

    # Payload length management. See sec5.2/Payload length of rfc6455
    payload_length = len(request_str)
    if (
        payload_length < 126
    ):  # length field value between 0-125 (inclusive) is just normal length
        # note that we are adding 128 to the payload lengh to set the mask bit to 1 (payload length is only 7 bits, the first bit of the byte is the mask bit)
        ws_header.append(payload_length + 128)
    elif (
        126 <= payload_length < 2 ** 16
    ):  # 126 in the length field signifies extended 2 byte payload in the next two bytes
        # splits the 16 bit length into two seperate bytes to allow the method bytes(ws_header) to work
        # a payload length of 126 specifies a 16 bit extended length, so we set the main payload length header to 126 + 128 = 254 (setting the mask bit too)
        ws_header += [254, payload_length // 256, payload_length % 256]
    else:  # 127 signifies extended 8 byte payload in the next 8 bytes
        # as far as I know, there is no request over length 2^16 that is ever sent by the client, at least as of 7.0. This branch exists merely for rfc6455 compliance
        # payload length of 127 specifies 64 bit extended length, so we set the main length header to 127 + 128 = 255 (setting the mask bit while we're at it)
        ws_header.append(255)
        length_bytes = []
        remaining_length = payload_length

        # this while loop breaks down the payload length into bytes, so that bytes(ws_header) works
        # inverse of byte_list_to_int(), but it's only used once here so it's not worth making it into a function
        while remaining_length:
            length_bytes = [remaining_length % 256] + length_bytes
            remaining_length = remaining_length // 256
        ws_header += length_bytes

    ws_mask_key = create_ws_mask_key()

    if isinstance(request_str, str):
        request_str = request_str.encode()
    ws_request = bytes(ws_header) + ws_mask_key + xor(request_str, ws_mask_key)
    return ws_request


# this is a dict that maps opcodes to the type of message that it represents (see rfc6455)
# e.g. opcode 0 is continuation frame, opcode 0x0a (10) is pong, etc.
# i know i just said that it's a dict, but really, a dict where the keys are integers is just an array, so this is an array...
opcode_deref = [
    "Continuation Frame",
    "Text Frame",
    "Binary Frame",
    "RESERVED",
    "RESERVED",
    "RESERVED",
    "RESERVED",
    "RESERVED",
    "Connection Close",
    "Ping",
    "Pong",
    "RESERVED",
    "RESERVED",
    "RESERVED",
    "RESERVED",
    "RESERVED",
]

# dict that maps connection close status codes to their meanings (see rfc6455)
status_code_dict = {
    1000: "Normal closure",
    1001: "Endpoint going away",
    1002: "Protocol Error",
    1003: "Unacceptable data",
    1004: "RESERVED",
    1005: "This code MUST NOT be set as a status code by an endpoint!",
    1006: "This code MUST NOT be set as a status code by an endpoint!",
    1007: "Inconsistent data types in message",
    1008: "Generic violation",
    1009: "Message too large",
    1010: "This status code should only be sent by a client, not a server...",
    1011: "Cannot fulfill request due to unexpected condition",
    1015: "This code MUST NOT be set as a status code by an endpoint!",
}


def ws_pretty_format(raw_data: bytes) -> str:
    """
    Given a raw websocket transaction, this method parses that data and turns it into a human readable message

    Follows rfc6455 as exactly as possible; pretty much does generate_request() but backwards

    @param data: the websocket data to parse

    @return: the websocket message formatted as a printable string
    """
    # we start by turning the data into a list which we can pop elements off of
    data = list(raw_data)

    # initialize the output variable
    output = ["[Websocket frame headers]:"]

    # parse the first byte here (checks for fin bit, and opcode)
    first_byte = data.pop(0)
    if first_byte >= 128:
        fin_bit = True
        opcode = first_byte - 128
    else:
        fin_bit = False
        opcode = first_byte
    output.append(f"FIN bit set: {fin_bit}")
    output.append(f"Opcode: {opcode} ({opcode_deref[opcode]})")

    # second byte check - check for mask bit, and length/length code
    second_byte = data.pop(0)
    if second_byte >= 128:
        mask_bit = True
        payload_len = second_byte - 128
    else:
        mask_bit = False
        payload_len = second_byte
    output.append(f"Masked frame: {mask_bit}")
    output.append(f"Payload length: {payload_len} ")

    # parse the length - value of 126/127 means extended length, which means
    # we have to parse the next bytes some more.
    if payload_len < 126:
        pass
    else:
        if payload_len == 126:
            bytes_in_len = 2
        elif payload_len == 127:
            bytes_in_len = 8
        else:
            raise Exception("uh oh spaghettio")

        extended_len = byte_list_to_int(data[:bytes_in_len])
        data = data[bytes_in_len:]

        output[-1] += f"(Extended {bytes_in_len*8} bit payload length)"
        output.append(f"Extended payload length: {extended_len}")

    # if mask bit is set, then we read the mask key and unmask the data here
    if mask_bit:
        mask_key = data[:4]
        data = xor(data[4:], mask_key)
        output.append(f"Mask key: {hex(byte_list_to_int(mask_key))}")

    # if the message was a close connection frame, then the next two bytes are a status code
    if first_byte == 8 or first_byte == 136:
        status_code = byte_list_to_int(data[:2])
        data = data[2:]
        output.append(
            f"Connection close status code: {status_code} ({status_code_dict[status_code]})"
        )

    # all headers have been read and acted on, so the rest of the data is just payload
    # here we finalize the output with that, then return it
    output.append("[Websocket frame payload]:")
    payload = ""
    for character in data:
        # chr turns a byte value into the equivalent ascii char
        # however, just doing "output += chr(character)" will render
        # weird binary bytes invisible. so we do repr() to get the
        # pure string representation, and then we do [1:-1] to
        # strip the "'" on either side
        # e.g. chr(22) => '\x16'
        #      print(chr(22)) => (invisible)
        #      print(repr(chr(22))) => '\x16' #printout includes the quotes
        #      print(repr(chr(22))[1:-1]) => \x16
        payload += repr(chr(character))[1:-1]

    # put something if payload is empty
    if not data:
        payload = "(no payload)"

    output.append(payload)

    return os.linesep.join(output) + os.linesep


def byte_list_to_int(byte_list: Sequence[int]) -> int:
    """
    Given a list of integer values between 0-255, returns a single integer
    formed by treating the byte sequence as a single number

    E.g. [128, 64, 10]
    = [0x80, 0x40, 0x0a]
    which we turn into: 0x80400a = 8405002 in decimal

    param byte_list: the list of byte values

    @return: the integer which the list represents
    """
    output = 0
    for index, byte in enumerate(byte_list):
        output += byte * (2 ** 8) ** (len(byte_list) - index - 1)
    return output


def expected_sec_websocket_accept_header(key: str) -> str:
    """
    Derives the expected sec-websocket-accept header from a given
    sec-websocket-key

    The process to turn a given key into an accept header is defined in
    page 19 of rfc6455

    @param key: websocket key to generate the header with

    @return: the appropriate 'Sec-WebSocket-Accept' header for the given
             key, as a string
    """
    uuid = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    hasher = hashlib.sha1()
    hasher.update(key.encode() + uuid)
    expected_header = base64.encodebytes(hasher.digest())[:-1].decode()
    return expected_header
