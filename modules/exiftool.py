import exiftool
import os


def extractMetadata(files: list[str]) -> (dict[str, list[str]] | list[str]):
    valid_files = []
    invalid_files = []
    for file in files:
        if os.path.isfile(file):
            valid_files.append(file)
        else:
            invalid_files.append(file)
    with exiftool.ExifToolHelper() as et:
        metadata = et.get_metadata(valid_files)

    if len(invalid_files) > 0:
        return {'metadata': metadata, 'Invalid Files': invalid_files}

    return metadata
