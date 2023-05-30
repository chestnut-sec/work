import argparse
import subprocess
import logging
import shutil
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='[%(levelname)s] %(message)s')

def find_encoded_files(directory, encodings):
    encoded_files = []
    for file_path in Path(directory).rglob('**/*'):
        if file_path.is_file():
            logging.debug(f"Checking file: {file_path}")
            result = subprocess.run(['chardetect', str(file_path)], capture_output=True, text=True)
            output = result.stdout.lower()
            logging.debug(f"chardetect output for {file_path}: {output}")
            detected_encoding = output.split(':')[0].strip()  # Extract detected encoding
            if detected_encoding in encodings:
                encoded_files.append(file_path)
    return encoded_files


def convert_to_utf8(file_path):
    temp_file = file_path.with_suffix('.tmp')
    logging.debug(f"Converting file: {file_path}")
    try:
        output = subprocess.run(['strings', str(file_path)], capture_output=True, text=True).stdout
        detected_encoding = subprocess.run(['chardetect', str(file_path)], capture_output=True, text=True).stdout
        detected_encoding = detected_encoding.strip().split(':')[0].strip()  # Extract detected encoding
        if detected_encoding != 'utf-8':
            with temp_file.open('w', encoding='utf-8') as f:
                f.write(output)
            shutil.move(str(temp_file), str(file_path))
    except subprocess.CalledProcessError as e:
        logging.error(f"Error converting file {file_path}: {e}")
    except IOError as e:
        logging.error(f"Error writing to file {temp_file}: {e}")

def main(directory):
    # Find encoded files (Windows-1254, Windows-1252, and MacRoman)
    logging.info("Searching for encoded files...")
    encodings = ['windows-1254', 'windows-1252', 'macroman']
    files_to_convert = find_encoded_files(directory, encodings)

    # Convert files to UTF-8
    logging.info("Converting files to UTF-8...")
    for file_path in files_to_convert:
        convert_to_utf8(file_path)
        logging.debug(f"Converted: {file_path}")

    logging.info("Conversion completed.")

if __name__ == '__main__':
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description='Convert Windows- and MacRoman-encoded files to UTF-8.')
    parser.add_argument('directory', help='Directory to search for files')
    args = parser.parse_args()

    # Call the main function
    main(args.directory)
