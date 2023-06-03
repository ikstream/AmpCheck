#!/usr/bin/python3

#    ntp-amp-check - ntp amplification checker
#    Copyright (C) 2023  ikstream <stefan[dot]venz[at]protonamil.com>
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.

import binascii
import socket
import sys
import argparse
import json

# NTP Version and mode
# The first byte consists of 2 Bit Leap Indicaor (00) 3 Bit Version (000 - 100) and 3 Bit mode (011 or 111)
# Leap Indicator needs to be set to either 1 (01 - Add a leap second) or 3 (11 -
# delete a leap second). Here it is set to 0.
# Therefore the order in the list is ntp version 1 to 4
MODE_7_MSG_IDS = [
    "PEER_LIST",
    "PEER_LIST_SUM",
    "PEER_INFO",
    "PEER_STATS",
    "SYS_INFO",
    "SYS_STATS",
    "IO_STATS",
    "MEM_STATS",
    "LOOP_INFO",
    "TIMER_STATS",
    "CONFIG",
    "UNCONFIG",
    "SET_SYS_FLAG",
    "CLR_SYS_FLAG",
    "MONITOR",
    "NONMONITOR",
    "GET_RESTRICT",
    "RESADDFLAGS",
    "RESSUBFLAGS",
    "UNRESTRICT",
    "MON_GETLIST",
    "RESET_STATS",
    "RESET_PEER",
    "REREAD_KEYS",
    "DO_DIRTY_HACK",
    "DONT_DIRTY)HACK",
    "TRUSTKEY",
    "UNTRUSTKEY",
    "AUTHINFO",
    "TRAPS",
    "ADD_TRAP",
    "CLR_TRAP",
    "REQUEST_KEY",
    "CONTROL_KEY",
    "GET_CLSTATS",
    "GET_LEAPINFO",
    "GET_CLOCKINFO",
    "SET_CLKFUDGE",
    "GET_KERNEL",
    "GET_CLKBUGINFO",
    "Unknown",
    "SET_PRECISION",
    "MON_GETLIST_1",
    "HOSTNAME_ASSOCID",
    "IF_STATS",
    "IF_RELOAD",
]


def send_mode_6_probe(host: str, port: int, version: bytes, timeout):
    """
    Send mode 6 requests to server

    The first byte consists of 2 Bit Leap Indicaor (00) 3 Bit Version
    (000 - 100) and 3 Bit mode (011 or 111).
    Leap Indicator needs to be set to either to
     - 0 (00 no leap second)
     - 1 (01 - add a leap second)
     - 3 (11 - delete a leap second).

    Here it is set to 0.
    Using OR on the ntp version passed to this function with the bitmask 0x06
    for mode 6 requests will generate the following values for the first byte

    0x0e, 0x16, 0x1e, 0x26

    Arguemnts:
        host(str):    targeted ntp server (single ip or hostname)
        port(int):    targeted port on targeted server (default 123)
        version(str): hexadecimal value for mode and ntp version (first 8 byte)
        timeout(int): time in seconds to wait for response before sending next
                        request (default 2)
    """

    requests = {}
    items = []
    mode6 = 0x06
    padding = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    msg_id = 'control'

    if VERBOSE: print(f"Timeout: {timeout}")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as serversock:
        serversock.settimeout(timeout)

        for control_message in range(0,32):
            item ={}
            item['response'] = ''
            item['response_length'] = ''
            item['amplification_factor'] = ''
            item['implementation'] = ''
            item['command_id'] = control_message
            item['command_name'] = 'control'
            request = binascii.a2b_hex(hex(version | mode6)[2:].zfill(2)) + \
                     binascii.a2b_hex(hex(control_message)[2:].zfill(2))  + \
                     padding
            if VERBOSE: print(f"Request {request}")
            serversock.sendto(request, (host, port))
            if DEBUG: item['request'] = request.hex()
            item['request_length'] = len(request)

            try:
                # Receive the response packet from the server
                ntp_response, _ = serversock.recvfrom(8192)
                if DEBUG: item['response'] = ntp_response.hex()
                item['response_length'] = len(ntp_response)

                # Calculate the amplification factor based on the size of the response packet
                if ntp_response:
                    amplification_factor = len(ntp_response) / len(request)
                    if VERBOSE: print(f"Amplification factor: {amplification_factor:.2f}; response: {ntp_response}")
                    item['amplification_factor'] = amplification_factor
                else:
                    continue

            except (socket.timeout, socket.error) as e:
                print(f"Response error: {e}")

            items.append(item)

    requests['mode 6'] = items

    return requests


def send_mode_7_probe(host: str, port: int, version: str, timeout: int):
    """
    Send mode 7 requests to server

    The first byte consists of 2 Bit Leap Indicaor (00) 3 Bit Version
    (000 - 100) and 3 Bit mode (011 or 111).
    Leap Indicator needs to be set to either to
     - 0 (00 no leap second)
     - 1 (01 - add a leap second)
     - 3 (11 - delete a leap second).

    Using OR on the ntp version passed to this function with the bitmask 0x07
    for mode 7 requests will generate the following values for the first byte

    0x0f, 0x17, 0x1f, 0x27

    Arguemnts:
        host(str):    targeted ntp server (single ip or hostname)
        port(int):    targeted port on targeted server (default 123)
        version(str): hexadecimal value for mode and ntp version (first 8 byte)
        timeout(int): time in seconds to wait for response before sending next
                        request (default 2)
    """

    requests = {}
    items = []
    mode7 = 0x07
    padding = b'\x00\x00\x00\x00'

    if VERBOSE: print(f"Timeout: {timeout}")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as serversock:
        serversock.settimeout(timeout)

        for implementation in range(2,4):
            for command_value in range(0,46):
                item ={}
                item['response'] = ''
                item['response_length'] = ''
                item['amplification_factor'] = ''
                item['implementation'] = implementation
                item['command_id'] = command_value
                item['command_name'] = MODE_7_MSG_IDS[command_value]
                request = binascii.a2b_hex(hex(version | mode7)[2:].zfill(2)) + \
                         b'\x00' + \
                         binascii.a2b_hex(hex(implementation)[2:].zfill(2))  + \
                         binascii.a2b_hex(hex(command_value)[2:].zfill(2)) + \
                         padding
                if VERBOSE: print(f"Request: {request}")
                serversock.sendto(request, (host, port))
                if DEBUG: item['request'] = request.hex()
                item['request_length'] = len(request)

                try:
                    # Receive the response packet from the server
                    ntp_response, _ = serversock.recvfrom(8192)
                    if DEBUG: item['response'] = ntp_response.hex()
                    item['response_length'] = len(ntp_response)

                    # Calculate the amplification factor based on the size of the response packet
                    if ntp_response:
                        amplification_factor = len(ntp_response) / len(request)
                        item['amplification_factor'] = amplification_factor
                        if VERBOSE: print(f"Amplification factor: {amplification_factor:.2f}; response: {ntp_response}")
                    else:
                        continue
                except socket.timeout as e:
                    print(f"Response error: {e}")
                    #print("Timed out while waiting for response from server")

                items.append(item)

    requests['mode 7'] = items

    return requests


def run_test():
    """
    Parse arguments and start sending requests accordingly
    """
    ntp_version = [ 0x08, 0x10, 0x18, 0x20 ]
    global VERBOSE
    global DEBUG
    data = {}
    versions = []

    parser = argparse.ArgumentParser()
    requiredargs = parser.add_argument_group('Required arguments')
    requiredargs.add_argument('-t',
                        '--target',
                        type=str,
                        help="Single ip adress or hostname to test",
                        required=True)
    parser.add_argument('-p',
                        '--port',
                        type=int,
                        default=123,
                        help='Port to test')
    parser.add_argument('--verbose',
                        action='store_true',
                        help='Print verbose information to stdout')
    parser.add_argument('-d',
                        '--debug',
                        action='store_true',
                        help='Print request and response bytes to output')
    parser.add_argument('--timeout',
                        type=int,
                        default=2,
                        help='Time in seconds to wait for response before sending next request. Default 2')

    args = parser.parse_args()

    VERBOSE = args.verbose
    DEBUG = args.debug
    data['host'] = args.target
    data['port'] = args.port

    try:

        for index, version in enumerate(ntp_version):
            version_data = {}
            requests = []
            if VERBOSE: print(f"Sending ntp version {index + 1} mode 6 requests to {args.target}:{args.port}")
            requests.append(send_mode_6_probe(args.target,
                                              args.port,
                                              version,
                                              args.timeout))

            if VERBOSE: print(f"Sending ntp version {index + 1} mode 7 requests to {args.target}:{args.port}")
            requests.append(send_mode_7_probe(args.target,
                                              args.port,
                                              version,
                                              args.timeout))
            version_data['version'] = index + 1
            version_data['requests'] = requests
            versions.append(version_data)

        data['ntp_version'] = versions
        print(json.dumps(data))

    except KeyboardInterrupt:
        sys.exit("Aborted by user")


if __name__ == '__main__':
    run_test()
