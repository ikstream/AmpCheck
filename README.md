# ntp-amp-check - NTP amplification checker
This script checks multiple NTP mode 6 and mode 7 requests for their
amplification potential.
Therefore it tries NTP Version 1 to 4 for both mode 6 and 7.
For mode 7 the implementation values 2 and 3 are checked as these seem to
provide the best results during tests.

The script doesn't require any external libraries.

[toc]

## How to use
```sh
$ python ntp-amp-check.py -h
usage: ntp-amp-check.py [-h] -t TARGET [-p PORT] [--verbose] [-d] [--timeout TIMEOUT] [--threshold THRESHOLD]

options:
  -h, --help            show this help message and exit
  -p PORT, --port PORT  Port to test
  --verbose             Print verbose information to stdout
  -d, --debug           Print request and response bytes to output
  --timeout TIMEOUT     Time in seconds to wait for response before sending next request. Default 2
  --threshold THRESHOLD
                        Report only packets with amplification factorequal or greater to the provided value. Default10

Required arguments:
  -t TARGET, --target TARGET
                        Single ip adress or hostname to test
```

The `--verbose` flag adds additional output during the execution and the
`--debug` flag adds the hex values of the request and response packages.

### Examples
To run against a single target with NTP listening on port 123 you can either provide an ip adress or a hostname

```
python ntp-amp-check.py -t ntp.example.com
```

For a NTP server listening on port 10123, the port has to be provided as well
```
python ntp-amp-check.py -t ntp.example.com -p 10123
```

To only show request with an amplification factor of 50 or greater
```
python ntp-amp-check.py -t localhost --threshold 50
```

## Packet structure

NTP control Message Format
from [1]
```
|       0       |       1       |       2       |       3       |
|7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|LI |  VN |Mode |R|E|M| opcode  |       Sequence Number         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            Status             |       Association ID          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- LI: leap indicator: 0..3 (0 - no leap second; 1 - add a leap second; 3 - delete a leap second)
- VN: version number: 1..4
- Mode: 6
- R: response bit (0 - request; 1 - response)
- E: error bit (0 - normal response; 1 - error response)
- M: more bit
- opcode: command ID: 0..31


NTP Mode 7 Message Format
from [2]
```
|       0       |       1       |       2       |       3       |
|7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|R|M| VN  |Mode |A|  Sequence   |Implementation |   Req Code    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Err  | Number of data items  |  MBZ  |   Size of data item   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- R: response bit 0..1 (0 - request; 1 - response)
- M: more bit 0..1 (0 - more; 1 - last bit)
- VN: version number: 1...4
- Mode: 7
- A: authenticated bit: 0..1 (0 - use no authentication; 1 - use authentication)
- Sequence: 0
- Implementation: 2...3
- Req Code: specifies the operation: 0...45 (valid commands)

rest: 0

## Resources

[[1]: rfc9327](https://datatracker.ietf.org/doc/html/rfc9327#section-2)

[[2]: how qualysguard detects vulnerability to ntp amplification attacks](
https://blog.qualys.com/vulnerabilities-threat-research/2014/01/21/how-qualysguard-detects-vulnerability-to-ntp-amplification-attacks
)
