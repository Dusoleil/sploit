from hatchling.builders.hooks.plugin.interface import BuildHookInterface

import os
import re

filename = os.path.normpath(os.path.join("sploit","__init__.py"))

#put the file back when the build ends
class RestoreVersionFile:
    def __init__(self,contents):
        self.contents = contents
    def __del__(self):
        with open(filename,"w") as f:
            f.write(self.contents)

class BakeVersionBuildHook(BuildHookInterface):
    def initialize(self,version,build_data):
        with open(filename,"r") as f:
            self.restore = RestoreVersionFile(f.read())
        pattern = r'(?i)^__version__ *= *(?P<version>.+?)$'
        match = re.search(pattern, self.restore.contents, flags=re.MULTILINE)
        if not match:
            raise ValueError("regex of version file failed")
        span = match.span('version')
        with open(filename,"w") as f:
            f.write(f'{self.restore.contents[:span[0]]}"v{self.metadata.version}"{self.restore.contents[span[1]:]}')
