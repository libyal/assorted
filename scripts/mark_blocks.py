#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Script to mark every block in a file."""

import argparse
import os
import sys


def Main():
  """The main program function.

  Returns:
    bool: True if successful or False if not.
  """
  parser = argparse.ArgumentParser(
      description=u'Marks every block in a file.')

  parser.add_argument(
      u'filename', metavar=u'FILENAME', type=unicode, nargs=1,
     help=u'the name of the file to mark')

  parser.add_argument(
      u'-b', dest=u'block_size', metavar=u'SIZE', type=int, action=u'store',
      default=512, help=u'the block size')

  arguments = parser.parse_args()

  file_object = open(arguments.filename[ 0 ], 'r+b')

  try:
    file_object.seek(0, os.SEEK_END)
    file_size = file_object.tell()

    for offset in range(0, file_size, arguments.block_size):
      marker_data = b'0x{0:08x}'.format(offset)
      file_object.seek(offset, os.SEEK_SET)
      file_object.write(marker_data)

  finally:
    file_object.close()

  return True


if __name__ == '__main__':
  if not Main():
    sys.exit(1)
  else:
    sys.exit(0)
