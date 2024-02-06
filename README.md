# COATHANGER FortiGate IOC Checker

This repository contains:
1. Indicators of Compromise (IOCs) from the MIVD & AIVD advisory on the [COATHANGER malware](https://www.ncsc.nl/documenten/publicaties/2024/februari/6/mivd-aivd-advisory-coathanger-tlp-clear).
2. The `coathanger.py` script which checks for the presence of these IOCs on a FortiGate disk image using the [Dissect](https://github.com/fox-it/dissect) framework.

The following checks are currently implemented in `coathanger.py`:
* Known malicious file locations as provided in the [advisory](https://www.ncsc.nl/documenten/publicaties/2024/februari/6/mivd-aivd-advisory-coathanger-tlp-clear)
* YARA rules as provided in the [advisory](https://www.ncsc.nl/documenten/publicaties/2024/februari/6/mivd-aivd-advisory-coathanger-tlp-clear)
* Binaries with differing modification timestamps
* Non-standard hidden folders in `/data` and `/data2`

> [!WARNING]
> **Please read the following carefully before taking action on your FortiGate device(s):**
> * This script only implements a subset of the detection methods described in the [advisory](https://www.ncsc.nl/documenten/publicaties/2024/februari/6/mivd-aivd-advisory-coathanger-tlp-clear). It should therefore only be used as an addition to the methods described in the advisory.
> * This script should be run on a forensic disk image of a FortiGate system and **not** on the FortiGate device itself.
> * This script is by no means the full replacement of a proper forensic investigation. It is possible the script leads to false negatives or false positives. Please use your own judgement before making any decisions based on the output of this tool.

## Installation and Usage
Use the following steps to install the COATHANGER IOC Checker:

1. `git clone https://github.com/JSCU-NL/COATHANGER.git`
2. `cd COATHANGER/`
3. `python3 -m venv venv && . venv/bin/activate`
4. `pip install -r requirements.txt`

You can now run `python coathanger.py <TARGET>` to start an IOC check against your disk image(s).

```
$ python coathanger.py /path/to/disk.img
  ____ ___    _  _____ _   _    _    _   _  ____ _____ ____  
 / ___/ _ \  / \|_   _| | | |  / \  | \ | |/ ___| ____|  _ \ 
| |  | | | |/ _ \ | | | |_| | / _ \ |  \| | |  _|  _| | |_) |
| |__| |_| / ___ \| | |  _  |/ ___ \| |\  | |_| | |___|  _ < 
 \____\___/_/   \_\_| |_| |_/_/   \_\_| \_|\____|_____|_| \_\


COATHANGER FortiGate IOC Checker
https://github.com/JSCU-NL/COATHANGER


2024-02-06T13:37:01.000000Z [info     ] Scanning target /path/to/disk.img
2024-02-06T13:37:02.000000Z [info     ] Searching for suspicious files
2024-02-06T13:37:03.000000Z [info     ] Scanning using YARA rules
2024-02-06T13:37:04.000000Z [info     ] Searching for non-standard hidden directories
2024-02-06T13:37:05.000000Z [info     ] Searching for deviating file modification times
2024-02-06T13:37:06.000000Z [warning  ] Found 7 COATHANGER indicators of compromise on system /path/to/disk.img

Confidence    Type    Alert                  Source
------------  ------  ---------------------  -------------------------
high          file    Suspicious file found  /data2/.bd.key/httpsd
high          file    Suspicious file found  /data2/.bd.key/newcli
high          file    Suspicious file found  /data2/.bd.key
high          file    Suspicious file found  /data2/.bd.key/preload.so
high          file    Suspicious file found  /data2/.bd.key/sh
high          file    Suspicious file found  /data2/.bd.key/authd
high          file    Suspicious file found  /etc/ld.so.preload
```
