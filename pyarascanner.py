# PyYaraScanner
# https://github.com/nogoodconfig/pyarascanner

import argparse
import os
import hashlib
from datetime import datetime
# yara-python imported later

yara_hashes = []
yara_filepaths = {}
yara_compiled = []

file_out = open("yarascan_{0}.txt".format(datetime.now().strftime('%Y-%m-%d-%H:%M:%S')), "w")
conf = {'alerts_only': False, 'errors': True, 'log': '', 'maxsize': 150, 'rules_path': '', 'scan_path': ''}


def msg(code, text):
    text = str(text)
    timestamp = datetime.now().strftime('%Y-%m-%d-%H:%M:%S')
    output = '{0}: {1} {2}'.format(timestamp, code, text)
    print(output)
    file_out.write(output + '\n')


def error(text):
    msg('[ERROR:GENERAL]', text)


def file_error(text):
    msg('[ERROR:FILE]', text)


def file_found(text):
    msg('[FOUND]', text)


def info(text):
    msg('[INFO]', text)


try:
    import yara
except Exception as e:
    file_error("Yara-Python module error! Make sure you have 'yara-python' not 'yara'!")
    file_error(e)
    exit(1)


def load_rules(directory):
    rules_counter = 0
    rules_counter_duplicates = 0
    info("Getting rules from " + directory + "...")
    for root, directories, file_names in os.walk(directory):
        for filename in file_names:
            if filename.endswith(".yar"):
                md5 = md5Hash(os.path.join(root, filename))
                # Check for duplicates...
                if md5 in yara_hashes:
                    rules_counter_duplicates = rules_counter_duplicates + 1
                else:
                    yara_hashes.append(md5)
                    rules_counter = rules_counter + 1
                    yara_filepaths[str(filename)] = str(os.path.join(root, filename))
                continue
            else:
                continue
    if rules_counter is 0:
        error("No YARA rules found in the given directory!")
        exit(1)
    info(str(rules_counter + rules_counter_duplicates) + " YARA rules found...")
    info(str(rules_counter_duplicates) + " duplicate YARA rules identified and removed from the set...")
    info(str(rules_counter) + " YARA rules prepared to compile...")

    # Compile .yar files into yara compiled objects, store in list, cleanly error bad files
    compile_success = 0
    compile_error = 0
    for rule in yara_filepaths:
        try:
            yara_compiled.append(yara.compile(filepath=str(yara_filepaths[rule])))
            compile_success += 1
        except:
            compile_error += 1
            continue
    if compile_error > 0:
        error(str(compile_error) + " YARA rules failed to compile...")
    info(str(compile_success) + " YARA rules compiled successfully...")
    # Finished compiling

def md5Hash(file):
    # https://stackoverflow.com/questions/22058048/hashing-a-file-in-python
    BUF_SIZE = 65536
    md5 = hashlib.md5()
    with open(file, 'rb') as f:
        while True:
            data = f.read(BUF_SIZE)
            if not data:
                break
            md5.update(data)

    return "{0}".format(md5.hexdigest())


parser = argparse.ArgumentParser()
parser.add_argument('rules_path')
parser.add_argument('scan_path')
parser.add_argument("-e", "--errors", help="Show all errors", action="store_true")
parser.add_argument("-a", "--alerts", help="Show alerts only", action="store_true")
parser.add_argument("-l", "--log", help="Output to specified log file")
parser.add_argument("-m", "--maxsize", type=int, help="Set maximum file size (MB)")
args = parser.parse_args()
if args.errors:
    conf['errors'] = True
if args.alerts:
    conf['alerts_only'] = True
    conf['errors'] = False
if args.log:
    try:
        conf['log'] = open(args.log, 'w')
    except:
        error("Could not create log file '" + str(args.log) + "'")
        exit(1)
if args.maxsize:
    conf['maxsize'] = args.maxsize
    if args.maxsize > 1024:
        info("Setting the maximum file size above 1GB is strongly discouraged!")

if (os.path.exists(args.rules_path)) and (os.path.exists(args.scan_path)):
    conf['rules_path'] = args.rules_path
    load_rules(conf['rules_path'])
    conf['scan_path'] = args.scan_path
else:
    error("Could not read rules or scan path!")
    exit(1)


for root, directories, file_names in os.walk(conf['scan_path']):
    for filename in file_names:
        path = os.path.join(root, filename)
        mb = round((float(os.path.getsize(path)) * 0.00000095367432), 2)
        if mb > conf['maxsize']:
            file_error(path + " [" + str(mb) + "MB]: File too big")
            break
        file_matches = []
        for rule in yara_compiled:
            try:
                matches = rule.match(str(path))
                if len(matches) > 0:
                    file_matches.append(matches)
            except:
                file_error(path + " [" + str(mb) + "MB]: Unknown error")
                break
        if len(file_matches) > 0:
            file_found(path + " [" + str(mb) + "MB]: " +str(file_matches))
        else:
            info(path + " [" + str(mb) + "MB]: No matches")

info("Finished")
file_out.close()
exit(0)