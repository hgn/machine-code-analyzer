#!/usr/bin/env python3
#
# Email: Hagen Paul Pfeifer <hagen@jauu.net>

# Machine-Code-Analyzer is free software: you can redistribute it
# and/or modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation, either version 3 of
# the License, or (at your option) any later version.
#
# MachineCodeAnalyzer is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with MachineCodeAnalyzer. If not, see <http://www.gnu.org/licenses/>.


import sys
import os
import logging
import optparse
import time
import datetime
import subprocess
import pprint
import re


pp = pprint.PrettyPrinter(indent=4)

__programm__ = "machine-code-analyzer"
__author__   = "Hagen Paul Pfeifer"
__version__  = "1"
__license__  = "GPLv3"

# custom exceptions
class ArgumentException(Exception): pass
class InternalSequenceException(Exception): pass
class InternalException(Exception): pass
class SequenceContainerException(InternalException): pass
class NotImplementedException(InternalException): pass
class SkipProcessStepException(Exception): pass
class UnitException(Exception): pass


class FunctionAnatomyAnalyzer:

    def __init__(self):
        pass

    def dependency(self):
        return None


class InstructionAnalyzer:

    def __init__(self):
        pass

    def dependency(self):
        return None



class MachineCodeAnalyzer:

    modes = {
       "function-anatomy":     [ "FunctionAnatomyAnalyzer", "Function anatomy information" ],
       "instruction-analyzer": [ "InstructionAnalyzer",     "Information about instructions" ]
            }

    def __init__(self):
        pass


    def which(self, program):
        for path in os.environ["PATH"].split(os.pathsep):
            path = path.strip('"')
            full_path = os.path.join(path, program)
            if os.path.isfile(full_path) and os.access(full_path, os.X_OK):
                return full_path
        return None


    def check_program(self, program):
        status = "FAILED"
        path = self.which(program["name"])
        if path:
            status = "OK"
        else:
            path = ""

        required = "Required" if program["required"] else "Optional"
        help     = "" if not program["help"] else program["help"]
        sys.stdout.write("%-6s %-10s Need: %7s   Path: %-20s  Help: %s\n" % (status, program["name"], required, path, help))


    def check_environment(self):
        programs = [
          # Required program section
          { "name":"make",     "required":True, "os":None, "help":"Build environment" },

          # Optional programs
          { "name":"ss",      "required":False, "os":"linux", "help":"Required Foo" }
        ]

        sys.stdout.write("Platform: %s\n" % (sys.platform))
        major, minor, micro, releaselevel, serial = sys.version_info
        sys.stdout.write("Python: %s.%s.%s [releaselevel: %s, serial: %s]\n\n" %
                (major, minor, micro, releaselevel, serial))

        sys.stdout.write("Check programs:\n")
        for program in programs:
            self.check_program(program)
        

    def print_version(self):
        sys.stdout.write("%s\n" % (__version__))


    def print_usage(self):
        sys.stderr.write("Usage: mca [-h | --help]" +
                         " [--version]" +
                         " <modulename> [<module-options>] <binary>\n")


    def print_welcome(self):
        major, minor, micro, releaselevel, serial = sys.version_info
        self.logger.critical("mca 2010-2013 Hagen Paul Pfeifer and others (c)")
        self.logger.critical("http://research.protocollabs.com/mca/")
        self.logger.info("python: %s.%s.%s [releaselevel: %s, serial: %s]" %
                (major, minor, micro, releaselevel, serial))


    def print_modules(self):
        for i in MachineCodeAnalyzer.modes.keys():
            sys.stderr.write("   %-15s - %s\n" % (i, MachineCodeAnalyzer.modes[i][1]))


    def args_contains(self, argv, *cmds):
        for cmd in cmds:
            for arg in argv:
                if arg == cmd: return True
        return False

    def check_binary_path(self, binary):
        statinfo = os.stat(binary)
        if not statinfo.st_size > 0:
            sys.stderr.write("File %s contains no content" % (binary))
            return False
        return True


    def parse_global_otions(self):
        if len(sys.argv) <= 2:
            self.print_usage()
            sys.stderr.write("Available modules:\n")
            self.print_modules()
            return None

        self.binary_path = sys.argv[-1]
        if self.check_binary_path(self.binary_path) == False:
            sys.stderr.write("Failed to open binary\n")
            return None

        # --version can be placed somewhere in the
        # command line and will evalutated always: it is
        # a global option
        if self.args_contains(sys.argv, "--version"):
            self.print_version()
            return None

        # -h | --help as first argument is treated special
        # and has other meaning as a submodule
        if self.args_contains(sys.argv[1:2], "-h", "--help"):
            self.print_usage()
            sys.stderr.write("Available modules:\n")
            self.print_modules()
            return None

        # -c | --check as first argument is treated special
        if self.args_contains(sys.argv[1:2], "-c", "--check"):
            self.check_environment()
            return None

        submodule = sys.argv[1].lower()
        if submodule not in MachineCodeAnalyzer.modes:
            self.print_usage()
            sys.stderr.write("Module \"%s\" not known, available modules are:\n" %
                             (submodule))
            self.print_modules()
            return None

        classname = MachineCodeAnalyzer.modes[submodule][0]
        return classname


    def run(self):
        classtring = self.parse_global_otions()
        if not classtring:
            return 1

        classinstance = globals()[classtring]()
        #classinstance.run()

        return 0



if __name__ == "__main__":
    try:
        mca = MachineCodeAnalyzer()
        sys.exit(mca.run())
    except KeyboardInterrupt:
        sys.stderr.write("SIGINT received, exiting\n")
