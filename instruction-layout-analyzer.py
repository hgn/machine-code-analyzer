#!/usr/bin/env python3


import sys
import argparse
import logging


class InstructionLayoutAnalyzer:


    def __init__(self, filename):
        self.filename = filename
        self.log = logging.info

    def parse_line(self, line):
        pass

    def open_parse(self):
        pass

    def run(self):
        self.log("Filename to analyze: %s" % args.argument)
        pass


def main(args, loglevel):
    logging.basicConfig(format="%(levelname)s: %(message)s", level=loglevel)

    ila = InstructionLayoutAnalyzer(args.argument)
    ila.run()

 
if __name__ == '__main__':
    parser = argparse.ArgumentParser(
            description = "Does a thing to some stuff.",
            fromfile_prefix_chars = '@')

    parser.add_argument("argument",
            help = "filename tp parse",
            metavar = "filename")
    parser.add_argument("-v", "--verbose",
            help="increase output verbosity",
            action="store_true")
    args = parser.parse_args()
  
  # Setup logging
    if args.verbose:
        loglevel = logging.DEBUG
    else:
        loglevel = logging.INFO
        
        
    main(args, loglevel)
