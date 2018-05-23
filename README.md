# PyaraScanner

A simple many-rules to many-files YARA scanner for incident response or malware zoos
## Prerequisites

YARA installed and Python 3.0-3.5 with the Yara-Python package


``` 
pip install yara-python
```

Yara-Python requires Microsoft Visual C++ Build Tools available [here](http://landinghub.visualstudio.com/visual-cpp-build-tools) under 'Build Tools for Visual Studio 2017' 
and the Yara binaries, available [here](https://github.com/VirusTotal/yara/releases) or [here](https://www.dropbox.com/sh/umip8ndplytwzj1/AADdLRsrpJL1CM1vPVAxc5JZa?dl=0&lst=)

Alternatively, you can download an easy installer which should download everything you need for your version of Python [here](https://www.dropbox.com/sh/umip8ndplytwzj1/AADdLRsrpJL1CM1vPVAxc5JZa?dl=0&lst=) (only supports up to Python 3.5)


## Running a scan

To run with default settings, just specify a folder for .yar rules and a starting point for files to scan. All directories for both inputs are scanned recursively

```
pyarascanner.py Yara_Rules C:\
```
Full syntax:

```
pyarascanner.py [-h] [-e] [-a] [-l LOG] [-m MAXSIZE] rules_path scan_path
```

### Optional Arguments

* -h, --help            Show help
* -e, --errors          Show all errors
* -a, --alerts          Show alerts only
* -l LOG, --log LOG     Output to specified log file
* -m MAXSIZE, --maxsize MAXSIZE
                        Set maximum file size (MB)
### Known Problems

* Problematic files can cause a hang in the multiprocessing with each thread needing to finis
* Seperate log files produced for each thread

## Built With

* [Yara-Python](https://github.com/VirusTotal/yara-python) - The awesome python implementation of awesome YARA rules