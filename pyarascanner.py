#PyYaraScanner
#https://github.com/nogoodconfig/pyarascanner

import argparse
import os
import hashlib
import datetime
#import yara (declared later)

yara_hashes = []
yara_filepaths = {}
yara_compiled = []
fout = open("yarascan_" +str(datetime.datetime.now()), "w")
conf = {'alertsonly':False, 'errors':True, 'log':'','maxsize':150, 'rulespath':'', 'scanpath':''}

def msg(code,text):
    if code is 0:
        output = "[ERROR] " +text
    elif code is 1:
        output = "[INFO] " +text
    elif code is 2:
        output = "[ERROR] " +text
    elif code is 3:
        output = "[FOUND] " +text
    print output
    writeout = str(output) +"\n"
    fout.write(writeout)

def err(text):
    msg(0, text)

def ferr(text):
    msg(2, text)

def ffnd(text):
    msg(3, text)

def inf(text):
    msg(1, text)

try:
    import yara
except:
    msg(2, "Yara-Python module error! Make sure you have 'yara-python' not 'yara'!")
    exit(1)

def loadRules(dir):
    rules_counter = 0
    rules_counter_duplicates = 0
    inf("Getting rules from " +dir +"...")
    for root, directories, filenames in os.walk(dir):
        for filename in filenames:
            if filename.endswith(".yar"):
                md5 = md5Hash(os.path.join(root, filename))
                #Check for duplicates...
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
        err("No YARA rules found in the given directory!")
        exit(1)
    inf(str(rules_counter + rules_counter_duplicates) + " YARA rules found...")
    inf(str(rules_counter_duplicates) + " duplicate YARA rules identified and removed from the set...")
    inf(str(rules_counter) + " YARA rules prepared to compile...")

    #Compile .yar files into yara compiled objects, store in list, cleanly error bad files
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
        err(str(compile_error) +" YARA rules failed to compile...")
    inf(str(compile_success) +" YARA rules compiled successfully...")
    # Finished compiling

def md5Hash(file):
    #https://stackoverflow.com/questions/22058048/hashing-a-file-in-python
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
    conf['alertsonly'] = True
    conf['errors'] = False
if args.log:
    try:
        conf['log'] = open(args.log,'w')
    except:
        err("Could not create log file '" +str(args.log) +"'")
        exit(1)
if args.maxsize:
    conf['maxsize'] = args.maxsize
    if args.maxsize > 1024:
        inf("Setting the maximum file size above 1GB is strongly discouraged!")

if (os.path.exists(args.rules_path)) and (os.path.exists(args.scan_path)):
    conf['rulespath'] = args.rules_path
    loadRules(conf['rulespath'])
    conf['scanpath'] = args.scan_path
else:
    err("Could not read rules or scan path!")
    exit(1)


for root, directories, filenames in os.walk(conf['scanpath']):
    for filename in filenames:
        path = os.path.join(root,filename)
        mb = round((float(os.path.getsize(path)) * 0.00000095367432), 2)
        if mb > conf['maxsize']:
            ferr(path + " [" + str(mb) + "MB]: File too big")
            break
        file_matches = []
        for rule in yara_compiled:
            try:
                matches = rule.match(str(path))
                if len(matches) > 0:
                    file_matches.append(matches)
            except:
                ferr(path + " [" + str(mb) + "MB]: Unknown error")
                break
        if len(file_matches) > 0:
            ffnd(path + " [" + str(mb) + "MB]: " +str(file_matches))
        else:
            inf(path + " [" + str(mb) + "MB]: No matches")
inf("Finished")
fout.close()
exit(0)