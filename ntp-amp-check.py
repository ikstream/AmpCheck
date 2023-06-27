#!/usr/bin/python3

#    ntp-amp-check - ntp amplification checker
#    Copyright (C) 2023  ikstream <stefan[dot]venz[at]protonmail.com>
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

"""
Check ntp server configuration if they can be used for amplification attacks
"""

import binascii
import socket
import sys
import argparse
import json
import logging as log


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

class Arguments():
    """
    Class to keep command line arguments in a single place
    """

    def __init__(self):
        self.host = ''
        self.port = 123
        self.timeout = 2
        self.debug = ''


def convert_to_hex(data: int|str):
    """
    Conver input data in to a 1-byte hex digit

    Arguments:
        data(int|str): input data
    Returns:
        single byte hex interpretation of input
    """

    return binascii.a2b_hex(hex(data)[2:].zfill(2))


def send_client_request(args: Arguments, version: int):
    # TODO: check if supports version, otherwise skip rest of test for this
    #       version
    # TODO: change padding in other functions like here
    key = f"response_on_client_request_version_{version}"
    verification = dict(key = 'false')
    initial_sync_client = 195
    padding = b'\x00' * 55
    ntp_response = ''

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as testing_sock:
        testing_sock.settimeout(args.timeout)
        request = convert_to_hex(initial_sync_client | version) + padding
        print(request)
        testing_sock.sendto(request, (args.host, args.port))

        try:
            ntp_response, _ = testing_sock.recvfrom(8192)

            if ntp_response:
                verification[key] = 'true'
                print(f"response: {ntp_response}")

        except socket.timeout as t_exc_msg:
            log.error(f"Response error: {t_exc_msg} - no response from "+
                       "server")
        except socket.error as s_exc_msg:
            log.error(f"Socker error: {s_exc_msg}")
            sys.exit("Socker error: {s_exc_msg}")

    return verification


def send_mode_6_probe(args: Arguments, version: int):
    """
    Send mode 6 requests to server

    The first byte consists of 2 bit leap indicaor (00) 3 bit version
    (000 - 100) and 3 bit mode (011 or 111).
    Leap Indicator needs to be set to either to
     - 0 (00 no leap second)
     - 1 (01 - add a leap second)
     - 3 (11 - delete a leap second).

    It is set to 0.
    Using bitwise `or` on the ntp version passed to this function with the
    bitmask 0x06 for mode 6 requests will generate the following values for
    the first byte

    0x0e, 0x16, 0x1e, 0x26

    Arguemnts:
        args(Arguments): Arguments class containing all user provided target
                         and runtime information
        version(str):    bit shifted ntp version
    Returns:
        diticnary with an array of selected requests
    """

    requests = {}
    items = []
    mode = 0x06
    padding = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

    log.info(f"Timeout: {args.timeout}")

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as testing_sock:
        testing_sock.settimeout(args.timeout)

        for control_message in range(0,32):
            item = {}
            item['amplification_factor'] = 0
            item['implementation'] = ''
            item['command_id'] = control_message
            item['command_name'] = 'control'

            if args.debug:
                item['request'] = ''
                item['response'] = ''

            request = convert_to_hex(version | mode) + \
                      convert_to_hex(control_message) + \
                      padding
            log.info(f"Request {request}")
            testing_sock.sendto(request, (args.host, args.port))

            if args.debug:
                item['request'] = request.hex()

            item['request_length'] = len(request)
            item['response_length'] = ''

            try:
                # Receive the response packet from the server
                ntp_response, _ = testing_sock.recvfrom(8192)

                if args.debug:
                    item['response'] = ntp_response.hex()

                item['response_length'] = len(ntp_response)

                # Calculate the amplification factor based on the size of the response packet
                if ntp_response:
                    amplification_factor = len(ntp_response) / len(request)

                    if amplification_factor < args.threshold:
                        continue

                    log.info(f"Amplification factor: {amplification_factor:.2f}; response: {ntp_response}")
                    item['amplification_factor'] = amplification_factor
                else:
                    continue

            except socket.timeout as t_exc_msg:
                log.error(f"Response error: {t_exc_msg} - no response from "+
                           "server")
            except socket.error as s_exc_msg:
                    log.error(f"Socker error: {s_exc_msg}")

            items.append(item)

    requests['mode 6'] = items

    return requests


def send_mode_7_probe(args: Arguments, version: int):
    """
    Send mode 7 requests to server

    The first byte consists of 1 bit request bit(0), one bit more bit (0) and
    3 bit version (000 - 100) followed by 3 mode bits (011 or 111).
    Leap Indicator needs to be set to either to
    Using a bitwise `or` on the ntp version passed to this function with the
    bitmask 0x07 for mode 7 requests will generate the following values for the
    first byte:

    0x0f, 0x17, 0x1f, 0x27

    Arguemnts:
        args(Arguments): Arguments class containing all user provided target
                         and runtime information
        version(int):    bit shifted ntp version
    Returns:
        diticnary with an array of selected requests
    """

    requests = {}
    items = []
    mode = 0x07
    padding = b'\x00\x00\x00\x00'

    log.info(f"Timeout: {args.timeout}")

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as testing_sock:
        testing_sock.settimeout(args.timeout)

        for implementation in range(2,4):
            for command_value in range(0,46):
                item ={}
                item['amplification_factor'] = 0
                item['implementation'] = implementation
                item['command_id'] = command_value
                item['command_name'] = MODE_7_MSG_IDS[command_value]

                if args.debug:
                    item['request'] = ''
                    item['response'] = ''

                request = convert_to_hex(version | mode) + \
                         b'\x00' + \
                         convert_to_hex(implementation) + \
                         convert_to_hex(command_value) + \
                         padding
                log.info(f"Request: {request}")
                testing_sock.sendto(request, (args.host, args.port))

                if args.debug:
                    item['request'] = request.hex()

                item['request_length'] = len(request)
                item['response_length'] = ''

                try:
                    # Receive the response packet from the server
                    ntp_response, _ = testing_sock.recvfrom(8192)

                    if args.debug:
                        item['response'] = ntp_response.hex()

                    item['response_length'] = len(ntp_response)

                    # Calculate the amplification factor based on the size of the response packet
                    if ntp_response:
                        amplification_factor = len(ntp_response) / len(request)

                        if amplification_factor < args.threshold:
                            continue

                        item['amplification_factor'] = amplification_factor
                        log.info(f"Amplification factor: {amplification_factor:.2f}; response: {ntp_response}")
                    else:
                        continue
                except socket.timeout as t_exc_msg:
                    log.error(f"Response error: {t_exc_msg} - no response from "+
                               "server")
                except socket.error as s_exc_msg:
                    log.error(f"Socker error: {s_exc_msg}")

                items.append(item)

    requests['mode 7'] = items

    return requests


def run_test():
    """
    Parse arguments and start sending requests accordingly
    """
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
                        help='Time in seconds to wait for response before ' +
                             'sending next request. Default 2')
    parser.add_argument('--threshold',
                        type=int,
                        default=10,
                        help='Report only packets with amplification factor' +
                             'equal or greater to the provided value. Default' +
                             ' 10')

    args = parser.parse_args()
    arguments = Arguments()
    arguments.debug = args.debug
    arguments.host = args.target
    arguments.port = args.port
    arguments.timeout = args.timeout
    arguments.threshold = args.threshold
    data['host'] = args.target
    data['port'] = args.port

    if args.verbose:
        log.basicConfig(level=log.INFO)

    try:

        for version in range(1,5):
            version_data = {}
            requests = []
            server_response = send_client_request(arguments, version<<3)
            if server_response[version] == 'true'
                log.info(f"Sending ntp version {version} mode 6 requests to {args.target}:{args.port}")
                requests.append(send_mode_6_probe(arguments, version<<3))
                log.info(f"Sending ntp version {version} mode 7 requests to {args.target}:{args.port}")
                requests.append(send_mode_7_probe(arguments, version<<3))
                version_data['version'] = version
                version_data['requests'] = requests
                versions.append(version_data)

        data['ntp_version'] = versions

        if versions:
            print(json.dumps(data))

    except KeyboardInterrupt:
        sys.exit("Aborted by user")


if __name__ == '__main__':
    run_test()
