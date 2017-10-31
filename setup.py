from distutils.core import setup
import py2exe
import os
import glob

def find_data_files(source,target,patterns):
    """Locates the specified data-files and returns the matches
    in a data_files compatible format.
    source is the root of the source data tree.
    Use '' or '.' for current directory.
    target is the root of the target data tree.
    Use '' or '.' for the distribution directory.
    patterns is a sequence of glob-patterns for the
    files you want to copy.
    """
    if glob.has_magic(source) or glob.has_magic(target):
        raise ValueError("Magic not allowed in src, target")
    ret = {}
    for pattern in patterns:
        pattern = os.path.join(source,pattern)
        for filename in glob.glob(pattern):
            if os.path.isfile(filename):
                targetpath = os.path.join(target,os.path.relpath(filename,source))
                path = os.path.dirname(targetpath)
                ret.setdefault(path,[]).append(filename)
    return sorted(ret.items())


setup(
        name="Sysventory",
        version="1.0",
        description="Cross-Platform application to gather system hardware and software information",
        author="Hal Riker",
        console=['main.py'],
        includes=['sqlite3', 'wmi', 'yaml', 'subprocess32', 'os', 'logging'],
        data_files=find_data_files('sqlite', 'sqlite', [
            './*',
        ]),
        # Will copy data/README to dist/README, and all files in data/images/ to dist/images/
        # (not checking any subdirectories of data/images/)
)



