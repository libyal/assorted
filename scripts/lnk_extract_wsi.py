#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Script to extract Windows Shell items from an LNK file."""

from __future__ import print_function
import argparse
import logging
import sys

import pylnk

import hexdump


# pylint: disable=logging-format-interpolation

def Main():
  """The main program function.

  Returns:
    A boolean containing True if successful or False if not.
  """
  argument_parser = argparse.ArgumentParser(description=(
      u'Extracts Windows Shell items from LNK files.'))

  argument_parser.add_argument(
      u'-o', u'--output-file', u'--output_file', dest=u'output_file',
      action=u'store', metavar=u'FILE', default=None, help=(
          u'name of the output file to write the data to.'))

  argument_parser.add_argument(
      u'source', nargs=u'?', action=u'store', metavar=u'PATH',
      default=None, help=u'path of the Windows Jump List file.')

  options = argument_parser.parse_args()

  if not options.source:
    print(u'Source file missing.')
    print(u'')
    argument_parser.print_help()
    print(u'')
    return False

  logging.basicConfig(
      level=logging.INFO, format=u'[%(levelname)s] %(message)s')

  lnk_file = pylnk.file()
  lnk_file.open(options.source)

  if not options.output_file:
    print(hexdump.Hexdump(lnk_file.link_target_identifier_data))

  else:
    with open(options.output_file, 'wb') as output_file:
      output_file.write(lnk_file.link_target_identifier_data)

  lnk_file.close()

  return True


if __name__ == '__main__':
  if not Main():
    sys.exit(1)
  else:
    sys.exit(0)
