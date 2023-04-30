import exiftool


def extractMetadata(files: list[str]) -> list[object]:
    with exiftool.ExifToolHelper() as et:
        metadata = et.get_metadata(files)
    return metadata
