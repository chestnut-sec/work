import os
import sys
import chardet

def check_encoding(file_path):
    with open(file_path, 'rb') as f:
        raw_data = f.read()
        result = chardet.detect(raw_data)
        return result['encoding']

def count_encodings(directory, include_hidden=False):
    encoding_counter = {}
    filenames = []
    for root, dirs, files in os.walk(directory):
        if not include_hidden:
            files = [f for f in files if not f[0] == '.']  # Exclude hidden files
        for file in files:
            file_path = os.path.join(root, file)
            filenames.append(file_path)
            if os.access(file_path, os.R_OK):  # Check if file is readable
                encoding = check_encoding(file_path)
                if encoding:
                    if encoding in encoding_counter:
                        encoding_counter[encoding] += 1
                    else:
                        encoding_counter[encoding] = 1
                else:
                    encoding_counter['Unknown'] = encoding_counter.get('Unknown', 0) + 1
    return encoding_counter, filenames

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: python encoding_checker.py <directory_path> [--include_hidden]')
        sys.exit(1)

    directory_to_check = sys.argv[1]
    include_hidden = False
    if len(sys.argv) == 3 and sys.argv[2] == '--include_hidden':
        include_hidden = True

    print(f'Starting encoding check in directory: {directory_to_check}')
    if include_hidden:
        print('Including hidden files.')

    try:
        encoding_counter, filenames = count_encodings(directory_to_check, include_hidden=include_hidden)

        print('Encoding Counter:')
        for encoding, count in encoding_counter.items():
            print(f'{encoding}: {count}')

        print('Files encoded with types occurring less than 10 times:')
        for filename in filenames:
            encoding = check_encoding(filename)
            if encoding and encoding_counter.get(encoding, 0) < 10:
                print(filename)

    except Exception as e:
        print('An error occurred during encoding check:')
        print(str(e))
        sys.exit(1)
