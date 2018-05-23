# PyaraScanner

A multithreaded many-rules to many-files YARA scanner for incident response or malware zoos
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
pyarascanner.py C:\Yara_Rules_Path C:\Scan_Directory
```
Full syntax:

```
pyarascanner.py [-h] [-e] [-a] [-l LOG] [-m MAXSIZE] [-c CORES] [-x EXISTING_RULES] rules_path scan_path

```

### Optional Arguments

* -h                                            show this help message and exit
* -e                                          Show all errors
* -a                                          Show alerts only
* -l LOG                                     Output to specified log file
* -m MAXSIZE                         Set maximum file size (MB)
* -c CORES                               Number of cores to use (defaults to number on system if unspecified)
* -x EXISTING_RULES    If specified, look for .rules file in same path as
                        script
### Known Problems

* Problematic files can cause a hang in the multiprocessing with each thread needing to finis
* Only scan results are logged, no script messages (including yara compiling)

## Built With

* [Yara-Python](https://github.com/VirusTotal/yara-python) - The awesome python implementation of awesome YARA rules