# ntp-amp-check - NTP amplification checker
This script checks multiple NTP mode 6 and mode 7 requests for their
amplification potential.
Therefore it tries NTP Version 1 to 4 for both mode 6 and 7.
For mode 7 the implementation values 2 and 3 are checked as these seem to
provide the best results during tests.

The script doesn't require any external libraries.

## How to use
```sh
$ python ntp-amp-check.py -h
usage: ntp-amp-check.py [-h] -t TARGET [-p PORT] [--verbose] [-d]

options:
  -h, --help            show this help message and exit
  -p PORT, --port PORT  Port to test
  --verbose             Print verbose information to stdout
  -d, --debug           Print request and response bytes to output

Required arguments:
  -t TARGET, --target TARGET
                        Single ip adress or hostname to test
```

The `--verbose` flag adds additional output during the execution and the
`--debug` flag adds the hex values of the request and response packages.

### Examples
To run against a single target with ntp listening on port 123 you can either provide an ip adress or a hostname

```
python ntp-amp-check.py -t ntp.example.com
```

For a ntp server listening on port 10123, the port has to be provided as well
```
python ntp-amp-check.py -t ntp.example.com -p 10123
```

