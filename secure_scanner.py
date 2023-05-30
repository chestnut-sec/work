#!/usr/bin/env python3

import argparse
import time
import glob
import os
import re
import textwrap
import chardet
from termcolor import colored
from terminaltables import AsciiTable


PREDEFINED_REGEXES = {
    "password": {
        "password": r'^\S*(passwords?|passwd|pass|pwd)_?(hash)?[0-9]*$',
        "username": r'\b(user|username|login)\b',
    },
    "api": {
        "api_key": r"(?i)\b(api|api[_-]?key)\b\s*[:=]\s*([\"']?[a-zA-Z0-9_\-/+=]+[\"']?)",
    },
    "ssh_key": {
        "ssh_key": r"(?i)(?<!\w)(?:ssh[_\-\s]?key|key[_\-\s]?ssh|ssh[_\-\s]?private[_\-\s]?key|private[_\-\s]?key[_\-\s]?ssh|ssh[_\-\s]?public[_\-\s]?key|public[_\-\s]?key[_\-\s]?ssh)\s*[:=]\s*([\"']?[a-zA-Z0-9_\-/+=]+[\"']?)|(?:\b[\w]+\b\s*=\s*['\"]([\"']?[a-zA-Z0-9_\-/+=]+[\"']?)['\"])"
    },
    "comments": {
        "comments": r"(?:\/\/[^\n]*|\/\*(?:.|[\r\n])*?\*\/|\"\"\"[\s\S]*?\"\"\"|\'\'\'\s*[\s\S]*?'')"
    },
    "ip_address": {
        "ipv4": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        "ipv6": r"\b(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}\b",
    },
    "url": {
        "url": r"\bhttps?://[\w./?&=\-]+\b",
    }
}

# Constants
SKIP_LARGER_THAN_BYTES = 10000 * 2 ** 10  # 100 KB
MAX_DIRECTORY_SIZE = 1000 * 1024 * 1024  # 100MB threshold


def get_ignored_files_file_name(args):
    regex_options = []
    
    if args.comments:
        regex_options.append("comments")
    if args.password:
        regex_options.append("password")
    if args.ssh_key:
        regex_options.append("ssh_key")
    if args.api:
        regex_options.append("api")
    if args.ip_address:
        regex_options.append("ip_address")
    if args.url:
        regex_options.append("url")
    
    if regex_options:
        regex_name = "_".join(regex_options)
        return f"ignored_files_{regex_name}.txt"
    else:
        return "ignored_files.txt"


def is_human_readable(file):
    """
    Check if a file is human-readable by attempting to decode it as ASCII or UTF-8.
    """
    try:
        with open(file, "rb") as f:
            content = f.read()
            content.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False
    except (OSError, IOError):
        return False

def crawl(paths):
    discovered_files = []
    ignored_files = []

    for path in paths:
        if os.path.isdir(path):
            directory_size = get_directory_size(path)
            if directory_size > MAX_DIRECTORY_SIZE:
                print(colored("Directory/file too big (size) -- Skipping scan of '{}'".format(path), "red"))
                ignored_files.append(path)
                continue

            for root, _, files in os.walk(path, topdown=True):  # Set topdown=True to include hidden files
                for file in files:
                    file_path = os.path.join(root, file)
                    if is_human_readable(file_path):
                        discovered_files.append(file_path)
                    else:
                        ignored_files.append(file_path)
        elif os.path.isfile(path):
            if is_human_readable(path):
                discovered_files.append(path)
            else:
                ignored_files.append(path)
        else:
            ignored_files.append(path)

    return discovered_files, ignored_files

#def crawl(paths):
#    discovered_files = []
#    ignored_files = []
#
#    for path in paths:
#        if os.path.isdir(path):
#            directory_size = get_directory_size(path)
#            if directory_size > MAX_DIRECTORY_SIZE:
#                print(colored("Directory/file too big (size) -- Skipping scan of '{}'".format(path), "red"))
#                ignored_files.append(path)
#                continue
#
#            for root, _, files in os.walk(path):
#                for file in files:
#                    file_path = os.path.join(root, file)
#                    if is_human_readable(file_path):
#                        discovered_files.append(file_path)
#                    else:
#                        ignored_files.append(file_path)
#        elif os.path.isfile(path):
#            if is_human_readable(path):
#                discovered_files.append(path)
#            else:
#                ignored_files.append(path)
#        else:
#            ignored_files.append(path)
#
#    return discovered_files, ignored_files

def get_directory_size(directory):
    total_size = 0
    for dirpath, _, filenames in os.walk(directory):
        for filename in filenames:
            file_path = os.path.join(dirpath, filename)
            total_size += os.path.getsize(file_path)
    return total_size

def scan_file(file, regexes):
    matched_lines = set()
    try:
        with open(file, "rb") as f:
            content = f.read()
    except (OSError, IOError):
        return []

    # Detect file encoding
    detected_encoding = chardet.detect(content)["encoding"]
    if not detected_encoding:
        return []

    try:
        content = content.decode(detected_encoding)
    except UnicodeDecodeError:
        return []

    lines = content.split("\n")
    results = []

    for i, line in enumerate(lines):
        for code_type, regex_group in regexes.items():
            for regex_subtype, regex in regex_group.items():
                matches = re.findall(regex, line)
                if matches:
                    for match in matches:
                        line_num = (file, code_type, regex_subtype, match, i + 1, line)
                        if line_num not in matched_lines:
                            results.append(line_num)
                            matched_lines.add(line_num)

        # Check if the line ends with an incomplete comment
        if i < len(lines) - 1 and re.match(r".*(?:#|\/\/|\/\*|\"\"\"|''').*[^\'\"]$", line.strip()):
            # Combine with the next line and continue matching
            line += lines[i + 1]

    return results


def scan_files(files, regexes):
    results = []

    for file in files:
        results.extend(scan_file(file, regexes))

    return results


def get_regexes(options):
    regexes = {}

    if options.password:
        regexes["password"] = PREDEFINED_REGEXES.get("password")
    if options.ssh_key:
        regexes["ssh_key"] = PREDEFINED_REGEXES.get("ssh_key")
    if options.api:
        regexes["api"] = PREDEFINED_REGEXES.get("api")
    if options.comments:
        regexes["comments"] = PREDEFINED_REGEXES.get("comments")
    if options.ip_address:
        regexes["ip_address"] = PREDEFINED_REGEXES.get("ip_address")
    if options.url:
        regexes["url"] = PREDEFINED_REGEXES.get("url")

    return regexes

def parse_args():
    """
    Parse the command-line arguments using the argparse module.
    """

    parser = argparse.ArgumentParser(description="Search for insecure code patterns in files.")

    parser.add_argument(
        "-c",
        "--comments",
        action="store_true",
        help="Search for commented strings."
    )

    parser.add_argument(
        "paths",
        metavar="path",
        type=str,
        nargs="+",
        help="Paths to files or directories to scan."
    )

    parser.add_argument(
        "-p",
        "--password",
        action="store_true",
        help="Search for potential password strings."
    )

    parser.add_argument(
        "-s",
        "--ssh-key",
        action="store_true",
        help="Search for potential SSH key strings."
    )

    parser.add_argument(
        "-a",
        "--api",
        action="store_true",
        help="Search for potential API key strings."
    )

    parser.add_argument(
        "-i",
        "--ip-address",
        action="store_true",
        help="Search for IP address patterns."
    )

    parser.add_argument(
        "-u",
        "--url",
        action="store_true",
        help="Search for URL patterns."
    )

    parser.add_argument(
        "-o",
        "--output",
        help="Write results to the specified file."
    )

    parser.add_argument(
        "-nc",
        "--no-color",
        action="store_true",
        help="Disable colored output."
    )

    parser.add_argument(
        "--timer",
        action="store_true",
        help="Enable timer to measure execution time."
    )

    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug mode."
    )

    return parser.parse_args()


def print_results(results, use_color):
    """
    Display the scan results in an ASCII table format and optionally write them
    to a file if the output option is specified.
    """

    headers = ["File", "Code Type", "Match", "Line Number", "Line"]
    table_data = [headers]

    for result in results:
        file, code_subtype, regex_subtype, match, line_num, line = result
        table_data.append([file, code_subtype, regex_subtype, str(line_num), textwrap.shorten(line, width=80)])

    table = AsciiTable(table_data)
    table.justify_columns[-1] = 'left'

    if use_color:
        for i in range(1, len(table_data)):
            table_data[i][0] = colored(table_data[i][0], "yellow")
            table_data[i][1] = colored(table_data[i][1], "red")
            table_data[i][2] = colored(table_data[i][2], "green")
            table_data[i][3] = colored(table_data[i][3], "blue")
            table_data[i][4] = colored(table_data[i][4], "white")

    print(table.table)


def main():

# Declare ignored_files_list
    ignored_files_list = []

    args = parse_args()

    if args.timer:
        start_time = time.time()

    use_color = not args.no_color

    regexes = get_regexes(args)

    discovered_files, ignored_files = crawl(args.paths)

    print(f"Discovered {len(discovered_files)} human-readable files.")

    results = scan_files(discovered_files, regexes)

    print(f"Scanned {len(discovered_files)} files.")

    print_results(results, use_color)

    if args.output:
        with open(args.output, "w") as f:
            for result in results:
                f.write(f"{result}\n")

    if ignored_files:
        print("\nIgnored files:")
        for file in ignored_files:
            print(file)
            ignored_files_list.append(file)  # Append to ignored_files_list

    if ignored_files_list:
        ignored_files_file = get_ignored_files_file_name(args)  # Generate more specific file name
        with open(ignored_files_file, "a") as f:
            for file_path in ignored_files_list:
                f.write(file_path + "\n")
        print(f"Ignored files list written to {ignored_files_file}")

    if args.timer:
        elapsed_time = time.time() - start_time
        print(f"\nElapsed Time: {elapsed_time:.2f} seconds")

    if args.debug:
        print("\n--- Debug Mode ---")
        print(f"Arguments: {args}")

if __name__ == "__main__":
    main()
