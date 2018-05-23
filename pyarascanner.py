# PyYaraScanner
# https://github.com/nogoodconfig/pyarascanner

import argparse
import os
import hashlib
import time
import multiprocessing
from datetime import datetime
# yara-python imported later

# define default configuration
config = {'alerts_only': False,
          'errors': True,
          'log': '',
          'maxsize': 150,
          'rules_path': '',
          'scan_path': '',
          'compiled_path': 'compiled_yara_rules.rules',
          'cores': multiprocessing.cpu_count(),
          'existing_rules': False}


class MyError(Exception):
    # Basic class to catch all errors and still print error code
    def __init__(self, message):
        # Call the base class constructor with the parameters it needs
        Exception.__init__(self, message)
        self.message = message


class Messenger:
    """
    Print/logging class
    """

    def __init__(self, log_file_path="yarascan_{0}.txt".format(datetime.now().strftime('%Y-%m-%d-%H-%M-%S'))):
        #Replaced with log_result function
        #self.log_file = open(log_file_path, 'w')
        pass


    @staticmethod

    def make_message(code, text):
        timestamp = datetime.now().strftime('%Y-%m-%d-%H:%M:%S')
        output = '{0}: {1} {2}'.format(timestamp, code, text)
        return output
    
    def output_message(self, message):
        print(message)
        return message
        
    def error(self, text, sub_code='GENERAL'):
        code = '[ERROR:{0}]'.format(sub_code)
        m = self.make_message(code, text)
        return self.output_message(m)
        
    def found(self, text, sub_code=''):
        if sub_code == '':
            code = '[FOUND]'
        else:
            code = '[FOUND:{0}]'.format(sub_code)
        m = self.make_message(code, text)
        return self.output_message(m)

    def info(self, text, sub_code=''):
        if sub_code == '':
            code = '[INFO]'
        else:
            code = '[INFO:{0}]'.format(sub_code)
        m = self.make_message(code, text)
        return self.output_message(m)


# Make global messenger class
MSG = Messenger()

# Try import yara-python, fail if not present
try:
    import yara
except Exception as e:
    MSG.error("Yara-Python module error! Make sure you have 'yara-python' not 'yara'!")
    MSG.error(e)
    exit(1)


def compile_rules(rules_folder, compiled_rules_path='compiled_yara_rules.rules'):
    """
    # Reads files in folder of 'directory'
    # Finds YARA rules, tests them, compiles them, saves them to file
    :param rules_folder: full path to folder containing yara rules
    :param compiled_rules_path: relative or full path to save compiled rules to
    :return: None
    """
    
    global MSG

    # Create list of rules in input directory
    yara_hashes = []
    yara_filepaths = {}
    count_duplicates = 0
    MSG.info("Getting rules from {0}...".format(rules_folder))
    for root, directories, file_names in os.walk(rules_folder):
        for filename in file_names:
            # Check for matching file extension
            if filename.endswith(".yar"):
                # Hash file then check for duplicates
                md5 = md5_hash(os.path.join(root, filename))
                # Check for duplicates...
                if md5 in yara_hashes:
                    count_duplicates += count_duplicates
                else:
                    # Add to list of yara rule hashes
                    yara_hashes.append(md5)
                    # Add to dictionary of rule names, containing full path to each yara rule
                    yara_filepaths[filename] = os.path.join(root, filename)
                continue
            else:
                continue
    if len(yara_hashes) is 0:
        MSG.error("No YARA rules found in directory {0}!".format(rules_folder))
        exit(1)
    MSG.info("{0} YARA rules found...".format(len(yara_hashes) + count_duplicates))
    MSG.info("{0} duplicate YARA rules identified and removed from the set...".format(count_duplicates))
    MSG.info("{0} YARA rules prepared to compile...".format(len(yara_hashes)))

    # Compile .yar files into yara compiled objects, store in list, cleanly error bad files

    # First test each rule to see if it compiles.
    rules_to_delete = []
    MSG.info('Testing each yara rule')
    for rule, file_path in yara_filepaths.items():
        try:
            yara.compile(filepath=file_path)
        except yara.SyntaxError as err:
            MSG.error('YARA syntax error: {0}'.format(err))
            rules_to_delete.append(rule)

    # Discard those that won't compile
    for rule in rules_to_delete:
        del yara_filepaths[rule]

    MSG.info('{0} invalid rules deleted from list of rules to compile'.format(len(rules_to_delete)))

    MSG.info('Compiling {0} remaining rules'.format(len(yara_filepaths)))
    yara_rules = yara.compile(filepaths=yara_filepaths)
    """
    # Old method for compiling lists...
    # This does allow larger number of yara rules to scan for
    # but can cause issues with multi-threading for now
    compile_success = 0
    compile_error = 0
    for rule in yara_filepaths:
        try:
            yara_compiled.append(yara.compile(filepath=str(yara_filepaths[rule])))
            compile_success += 1
        except yara.SyntaxError as e:
            MSG.error('YARA syntax error: {0}'.format(e))
            compile_error += 1
            continue
    if compile_error > 0:
        MSG.error(str(compile_error) + " YARA rules failed to compile...")
    MSG.info(str(compile_success) + " YARA rules compiled successfully...")
    """
    # Finished compiling

    # Write to file
    yara_rules.save(compiled_rules_path)
    MSG.info('Compiled rules saved to {0}'.format(compiled_rules_path))


def md5_hash(file):
    # https://stackoverflow.com/questions/22058048/hashing-a-file-in-python
    buffer_size = 65536
    md5 = hashlib.md5()
    with open(file, 'rb') as f:
        while True:
            data = f.read(buffer_size)
            if not data:
                break
            md5.update(data)

    return "{0}".format(md5.hexdigest())


def parse_file(file_path, yara_rules):
    """

    :param file_path: file path to be scanned for yara rule matches
    :param yara_rules: compiled yara rules object
    :return:
    """
    # Run yara rules across a file
    # print('parsing {0}'.format(file_path))   # For error checking, it's currently printing 'None' for quite a few

    # Don't need yara rules for parsing each file now, as it's passed as an arg
    # yara_rules = yara.load(compiled_rules_path)  # For multi processing, want to make this global
    matches = []
    message = ""
    try:
        matches = yara_rules.match(file_path)
    except yara.Error as err:
        message = MSG.error('{0} Yara.Error parsing this file: {1}'.format(file_path, err))
    except MyError as err:
        message = MSG.error('{0}: Unknown error: {1}'.format(file_path, err))
    # If any matches found, create one string containing all matches within file
    if len(matches) > 0:
        str_matches = ''
        count = 0
        # Run through them, compiling string
        for m in matches:
            str_matches += str(m)
            if count < len(matches) - 1:
                str_matches += ', '
            count += 1
        message = MSG.found('{0}: {1} matches: {2}'.format(file_path, len(matches), str_matches))
    else:
        message = MSG.info('{0}:  No matches'.format(file_path))
    return message


def split_list(input_list, num_sub_lists):
    """

    :param input_list: List to be split
    :param num_sub_lists: Number of sub lists to be split into
    :return: list containing sub lists
    """
    output_list = []
    # First make empty sub lists, one for each process
    for n in range(num_sub_lists):
        output_list.append([])
    # Now add file paths evenly to them
    count = 0
    for item in input_list:
        output_list[count % num_sub_lists].append(item)
        count += 1

    return output_list


def worker(file_list):
    """
    This is the function detailing what each worker (process) will do.
    :param file_list: list of full file paths to process
    :return: list of results for each file
    """

    import time

    global MSG      # Specify global messenger
    global config   # Specify global config

    # Load rules from global variable
    yara_rules = yara.load(config['compiled_path'])
    results = []
    for path in file_list:
        MSG.info('Parsing {}'.format(path))
        #parse_file(path, yara_rules)
        results.append(parse_file(path, yara_rules))
    return results

to_log = []
def log_result(result):
    #Writing directly to file from here causes broken lines, likely IO limitation
    if isinstance(result, list):
        for r1 in result:
            for r2 in r1:
                if r2 is not None:
                    to_log.append(r2)
    elif isinstance(result, str):
        to_log.append(result)


def main(conf):
    # Add and process arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('rules_path', help="Directory containing .yar files to compile and search for")
    parser.add_argument('scan_path', help="Folder or drive letter to parse")
    parser.add_argument("-e", "--errors", help="Show all errors", action="store_true")
    parser.add_argument("-a", "--alerts", help="Show alerts only", action="store_true")
    parser.add_argument("-l", "--log", help="Output to specified log file")
    parser.add_argument("-m", "--maxsize", type=int, help="Set maximum file size (MB)")
    parser.add_argument("-c", "--cores", help="Number of cores to use (defaults to number on system if unspecified)")
    parser.add_argument("-x", "--existing_rules", help="if specified, look for .rules file in same path as script ", action="store_true")
    args = parser.parse_args()
    if args.errors:
        conf["errors"] = True
    if args.alerts:
        conf["alerts_only"] = True
        conf["errors"] = False
    if args.log:
        try:
            conf["log"] = open(args.log, 'w')
        except MyError as err:
            MSG.error("Could not create log file '{0}'".format(args.log))
            MSG.error("Python error: {}".format(err))
            exit(1)
    if args.maxsize:
        conf["maxsize"] = args.maxsize
        if args.maxsize > 1024:
            MSG.info("Setting the maximum file size above 1GB is strongly discouraged!")
    if args.cores:
        try:
            conf["cores"] = int(args.cores)
        except ValueError as err:
            MSG.error("Number of cores specified must be integer")
            MSG.error(err)
            exit(1)

    # Check required arguments provided
    if (os.path.exists(args.rules_path)) and (os.path.exists(args.scan_path)):
        conf["rules_path"] = args.rules_path
        # Check to see if existing rules file should be used
        print(args.existing_rules)
        if args.existing_rules is True:

            # Look for 'compiled_yara_rules.rules' in working directory
            if os.path.isfile(conf["compiled_path"]) is True:
                MSG.info("Existing rules file found, using that")
            else:
                MSG.error("Existing rules file specified, but not found in working directory", sub_code="FILE")
                MSG.error(
                    "Ensure {0} exists in same path as script, or remove '-x' switch".format(conf["compiled_path"]))
                exit(1)
        else:
            MSG.info("Compiling rules from {}".format(conf["rules_path"]))
            compile_rules(conf["rules_path"], conf["compiled_path"])
        conf["scan_path"] = args.scan_path
    else:
        MSG.error("Could not read rules or scan path!")
        exit(1)

    # Build list of files to process, conduct pre-processing
    MSG.info("BUILDING FILE LIST FOR PARSING")
    list_files = []
    for root, directories, file_names in os.walk(conf["scan_path"]):
        for name in file_names:
            path = os.path.join(root, name)
            # Check for file size
            try:
                mb = round(os.path.getsize(path) / 1024 / 1024)
            except:
                MSG.error("Unable to read file " +path +" Check permissions?")
                continue
            if mb > conf['maxsize']:
                MSG.error("{0} ({1}MB): File larger than maxsize ({2}MB)".format(path, mb, conf['maxsize']))
            else:
                # parse_file(path, yara_compiled_path)   # Use this for checking one at a time
                list_files.append(path)

    # Build process pool with specified number of workers
    pool = multiprocessing.Pool(processes=conf["cores"])

    # Split list_files into sub lists for each sub process
    MSG.info("Splitting input file list into {0} sub lists for sub-processes".format(conf["cores"]))
    lists_for_cores = split_list(list_files, conf['cores'])

    # Pass the work to separate workers, one for each sub process
    MSG.info("BEGINNING MULTI-THREADED PARSING OF FILES")
    # Record the start time
    start_time = time.time()

    #results = pool.map(worker, lists_for_cores)
    r = pool.map_async(worker, lists_for_cores, callback=log_result)
    r.wait()
    pool.close()
    pool.join()

    # Record the end time
    end_time = time.time()
    MSG.info("{0} parsed in {1} seconds".format(len(list_files), end_time - start_time))



    """
    # Left out for now, trying it with Pools
    with concurrent.futures.ProcessPoolExecutor(max_workers=12) as executor:
        for file_path in executor.map(parse_file, list_files):
            MSG.info('Parsing {0}'.format(file_path))   # file_path only prints 'None'
            pass
    """

    MSG.info("Finished")
    log_file_path = "yarascan_{0}.txt".format(datetime.now().strftime('%Y-%m-%d-%H-%M-%S'))
    with open(log_file_path, 'w') as log_file:
        if to_log:
            for line in to_log:
                log_file.write(str(line) + "\n")

if __name__ == '__main__':
    main(config)
    exit(0)