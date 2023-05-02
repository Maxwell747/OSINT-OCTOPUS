import exiftool
import os


def extractMetadata(files: list[str]) -> (dict[str, object]):
    valid_files = []
    invalid_files = []
    metadata = []

    for file in files:
        if os.path.isfile(file):
            valid_files.append(file)
        else:
            invalid_files.append(file)

    if len(valid_files) > 0:
        with exiftool.ExifToolHelper() as et:
            metadata = et.get_metadata(valid_files)

    if len(valid_files) == 0:
        return {'Invalid Files': invalid_files}
    elif len(invalid_files) > 0:
        return {'metadata': metadata, 'Invalid Files': invalid_files}
    else:
        return {'metadata': metadata}
