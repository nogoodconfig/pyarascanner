# PyYaraScanner

A simple many-rules to many-files YARA scanner for incident response or malware zoos.
## Prerequisites

Python 2.7 with the Yara-Python package

``` 
pip install yara-python
```

## Running a scan

To run with default settings, just specify a folder for .yar rules and a starting point for files to scan. All directories for both inputs are scanned recursively.

```
yarascan2.py C:\Rules C:\Files
```

Optional arguments:

```
yarascan2.py [-h] [-e] [-a] [-l LOG] [-m MAXSIZE] rules_path scan_path
```

End with an example of getting some data out of the system or using it for a little demo

### Optional Arguments

* -h, --help            show this help message and exit
* -e, --errors          Show all errors
* -a, --alerts          Show alerts only
* -l LOG, --log LOG     Output to specified log file
* -m MAXSIZE, --maxsize MAXSIZE
                        Set maximum file size (MB)

## Built With

* [Yara-Python](https://github.com/VirusTotal/yara-python) - The awesome python implementation of awesome YARA rules