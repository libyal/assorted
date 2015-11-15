#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Script to parse WMI Common Information Model (CIM) repository files."""

from __future__ import print_function
import argparse
import logging
import os
import sys

import construct

import hexdump


# pylint: disable=logging-format-interpolation

class IndexBinaryTreeFile(object):
  """Class that contains an binary-tree index (Index.btr) file."""

  _PAGE_SIZE = 8192

  _PAGE_HEADER = construct.Struct(
      u'page_header',
      construct.ULInt32(u'page_type'),
      construct.ULInt32(u'unknown1'),
      construct.ULInt32(u'unknown2'),
      construct.ULInt32(u'root_page_number'),
      construct.ULInt32(u'number_of_page_values'))

  def __init__(self, debug=False):
    """Initializes the binary-tree index file object.

    Args:
      debug: optional boolean value to indicate if debug information should
             be printed. The default is false.
    """
    super(IndexBinaryTreeFile, self).__init__()
    self._debug = debug
    self._file_object = None
    self._file_object_opened_in_object = False
    self._file_size = 0

    self._page_key_data = b''
    self._page_key_offsets = None

    self._page_value_data = b''
    self._page_value_offsets = None

  def _ReadPageHeader(self, file_offset):
    """Reads a page header.

    Args:
      file_offset: integer containing the offset of the page relative
                   from the start of the file.

    Raises:
      IOError: if the page header cannot be read.
    """
    if self._debug:
      print(u'Seeking page header offset: 0x{0:08x}'.format(file_offset))

    self._file_object.seek(file_offset, os.SEEK_SET)

    page_header_data = self._file_object.read(self._PAGE_HEADER.sizeof())

    try:
      page_header_struct = self._PAGE_HEADER.parse(page_header_data)
    except construct.FieldError as exception:
      raise IOError((
          u'Unable to parse page header at offset: 0x{0:08x} '
          u'with error: {1:s}').format(file_offset, exception))

    page_type = page_header_struct.get(u'page_type')
    root_page_number = page_header_struct.get(u'root_page_number')
    number_of_page_values = page_header_struct.get(u'number_of_page_values')

    if self._debug:
      print(u'Page header data:')
      print(hexdump.Hexdump(page_header_data))

    if self._debug:
      print(u'Page type\t\t\t\t\t\t\t\t: 0x{0:04x}'.format(page_type))
      print(u'Unknown1\t\t\t\t\t\t\t\t: 0x{0:08x}'.format(
          page_header_struct.get(u'unknown1')))
      print(u'Unknown2\t\t\t\t\t\t\t\t: 0x{0:08x}'.format(
          page_header_struct.get(u'unknown2')))
      print(u'Root page number\t\t\t\t\t\t\t: {0:d}'.format(root_page_number))
      print(u'Number of pages\t\t\t\t\t\t\t\t: {0:d}'.format(
          number_of_page_values))
      print(u'')

    array_data_size = number_of_page_values * 4
    array_data = self._file_object.read(array_data_size)

    if self._debug:
      print(u'Unknown array data:')
      print(hexdump.Hexdump(array_data))

    array_data_size = (number_of_page_values + 1) * 4
    array_data = self._file_object.read(array_data_size)

    if self._debug:
      print(u'Child pages array data:')
      print(hexdump.Hexdump(array_data))

    self._ReadKeyOffsets(number_of_page_values)
    self._ReadKeyData()

    self._ReadValueOffsets()
    self._ReadValueData()

    trailing_data_size = (
        (file_offset + self._PAGE_SIZE) - self._file_object.tell())
    trailing_data = self._file_object.read(trailing_data_size)

    if self._debug:
      print(u'Trailing data:')
      print(hexdump.Hexdump(trailing_data))

  def _ReadKeyOffsets(self, number_of_offsets):
    """Reads page key offsets.

    Args:
      number_of_offset: integer containing the number of offsets.

    Raises:
      IOError: if the page key offsets cannot be read.
    """
    file_offset = self._file_object.tell()
    if self._debug:
      print(u'Seeking page key offsets at offset: 0x{0:08x}'.format(
          file_offset))

    if self._debug:
      print(u'Number of offsets\t\t\t\t\t\t\t: {0:d}'.format(number_of_offsets))

    offsets_data = self._file_object.read(number_of_offsets * 2)

    if self._debug:
      print(u'Page key offsets:')
      print(hexdump.Hexdump(offsets_data))

    try:
      self._page_key_offsets = construct.Array(
          number_of_offsets, construct.ULInt16(u'offset')).parse(offsets_data)
    except construct.FieldError as exception:
      raise IOError((
          u'Unable to parse page key offsets at offset: 0x{0:08x} '
          u'with error: {1:s}').format(file_offset, exception))

    if self._debug:
      for index in range(number_of_offsets):
        print(u'Page key: {0:d} offset\t\t\t\t\t\t\t: 0x{1:04x}'.format(
            index, self._page_key_offsets[index]))
      print(u'')

  def _ReadKeyData(self):
    """Reads page key data.

    Raises:
      IOError: if the page key data cannot be read.
    """
    file_offset = self._file_object.tell()
    if self._debug:
      print(u'Seeking page key data at offset: 0x{0:08x}'.format(file_offset))

    try:
      data_size = construct.ULInt16(u'data_size').parse_stream(
          self._file_object)
    except construct.FieldError as exception:
      raise IOError((
          u'Unable to parse page key data size at offset: 0x{0:08x} '
          u'with error: {1:s}').format(file_offset, exception))

    data_size *= 2

    if self._debug:
      print(u'Page key data size\t\t\t\t\t\t\t: {0:d} bytes'.format(
          data_size))

    data = self._file_object.read(data_size)

    if self._debug:
      print(u'Page key data:')
      print(hexdump.Hexdump(data))

    if self._debug:
      for index in range(len(self._page_key_offsets)):
        page_key_offset = self._page_key_offsets[index] * 2
        # TODO: determine size
        page_key_size = page_key_offset + 6

        print(u'Page key: {0:d} data:'.format(index))
        print(hexdump.Hexdump(data[page_key_offset:page_key_size]))
      print(u'')

  def _ReadValueOffsets(self):
    """Reads page value offsets.

    Raises:
      IOError: if the page value offsets cannot be read.
    """
    file_offset = self._file_object.tell()
    if self._debug:
      print(u'Seeking page value offsets at offset: 0x{0:08x}'.format(
          file_offset))

    try:
      number_of_offsets = construct.ULInt16(u'number_of_offsets').parse_stream(
          self._file_object)
    except construct.FieldError as exception:
      raise IOError((
          u'Unable to parse number of page value offsets at offset: 0x{0:08x} '
          u'with error: {1:s}').format(file_offset, exception))

    if self._debug:
      print(u'Number of offsets\t\t\t\t\t\t\t: {0:d}'.format(number_of_offsets))

    offsets_data = self._file_object.read(number_of_offsets * 2)

    if self._debug:
      print(u'Page value offsets:')
      print(hexdump.Hexdump(offsets_data))

    try:
      self._page_value_offsets = construct.Array(
          number_of_offsets, construct.ULInt16(u'offset')).parse(offsets_data)
    except construct.FieldError as exception:
      raise IOError((
          u'Unable to parse page value offsets at offset: 0x{0:08x} '
          u'with error: {1:s}').format(file_offset, exception))

    if self._debug:
      for index in range(number_of_offsets):
        print(u'Page value: {0:d} offset\t\t\t\t\t\t\t: 0x{1:04x}'.format(
            index, self._page_value_offsets[index]))
      print(u'')

  def _ReadValueData(self):
    """Reads page value data.

    Raises:
      IOError: if the page value data cannot be read.
    """
    file_offset = self._file_object.tell()
    if self._debug:
      print(u'Seeking page value data at offset: 0x{0:08x}'.format(file_offset))

    try:
      data_size = construct.ULInt16(u'data_size').parse_stream(
          self._file_object)
    except construct.FieldError as exception:
      raise IOError((
          u'Unable to parse page value data size at offset: 0x{0:08x} '
          u'with error: {1:s}').format(file_offset, exception))

    if self._debug:
      print(u'Page value data size\t\t\t\t\t\t\t: {0:d} bytes'.format(
          data_size))

    data = self._file_object.read(data_size)

    if self._debug:
      print(u'Page value data:')
      print(hexdump.Hexdump(data))

    if self._debug:
      for index in range(len(self._page_value_offsets)):
        page_value_offset = self._page_value_offsets[index]
        # TODO: determine size
        page_value_size = page_value_offset + 16

        print(u'Page value: {0:d} data:'.format(index))
        print(hexdump.Hexdump(data[page_value_offset:page_value_size]))
      print(u'')

  def Close(self):
    """Closes the change.log file."""
    if self._file_object_opened_in_object:
      self._file_object.close()
    self._file_object = None

  def Open(self, filename):
    """Opens the change.log file.

    Args:
      filename: the filename.
    """
    stat_object = os.stat(filename)
    self._file_size = stat_object.st_size

    self._file_object = open(filename, 'rb')
    self._file_object_opened_in_object = True

    file_offset = 0
    while file_offset < self._file_size:
      self._ReadPageHeader(file_offset)
      file_offset += self._PAGE_SIZE


def Main():
  """The main program function.

  Returns:
    A boolean containing True if successful or False if not.
  """
  argument_parser = argparse.ArgumentParser(description=(
      u'Extracts information from WMI Common Information Model (CIM) '
      u'repository files.'))

  argument_parser.add_argument(
      u'-d', u'--debug', dest=u'debug', action=u'store_true', default=False,
      help=u'enable debug output.')

  argument_parser.add_argument(
      u'source', nargs=u'?', action=u'store', metavar=u'PATH',
      default=None, help=(
          u'path of the directory containing the WMI Common Information '
          u'Model (CIM) repository files.'))

  options = argument_parser.parse_args()

  if not options.source:
    print(u'Source file missing.')
    print(u'')
    argument_parser.print_help()
    print(u'')
    return False

  logging.basicConfig(
      level=logging.INFO, format=u'[%(levelname)s] %(message)s')

  index_file_path = os.path.join(options.source, u'INDEX.BTR')
  # TODO: make case insensitive
  index_file = IndexBinaryTreeFile(debug=options.debug)
  index_file.Open(index_file_path)

  index_file.Close()

  return True


if __name__ == '__main__':
  if not Main():
    sys.exit(1)
  else:
    sys.exit(0)
