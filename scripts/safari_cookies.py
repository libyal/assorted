#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Script to parse Safari Cookies (Cookies.binarycookies) files."""

from __future__ import print_function
import argparse
import logging
import os
import sys

import construct

import hexdump


class BinaryCookiesFile(object):
  """Class that contains a Cookies.binarycookies file."""

  _FILE_HEADER = construct.Struct(
      u'file_header',
      construct.Bytes(u'signature', 4),
      construct.UBInt32(u'number_of_pages'))

  _PAGE_HEADER = construct.Struct(
      u'page_header',
      construct.ULInt32(u'signature'),
      construct.ULInt32(u'number_of_records'),
      construct.Array(
          lambda ctx: ctx.number_of_records, 
          construct.ULInt32(u'offsets')))

  _RECORD_HEADER = construct.Struct(
      u'record_header',
      construct.ULInt32(u'size'),
      construct.ULInt32(u'unknown1'),
      construct.ULInt32(u'flags'),
      construct.ULInt32(u'unknown2'),
      construct.ULInt32(u'url_offset'),
      construct.ULInt32(u'name_offset'),
      construct.ULInt32(u'path_offset'),
      construct.ULInt32(u'value_offset'),
      construct.ULInt64(u'unknown3'),
      construct.LFloat64(u'expiration_date'),
      construct.LFloat64(u'creation_date'))

  _FILE_FOOTER = construct.Struct(
      u'file_footer',
      construct.Bytes(u'unknown1', 8))

  def __init__(self, debug=False):
    """Initializes a file.

    Args:
      debug (Optional[bool]): True if debug information should be printed.
    """
    super(BinaryCookiesFile, self).__init__()
    self._debug = debug
    self._file_object = None
    self._file_object_opened_in_object = False
    self._file_size = 0
    self._page_sizes = []

  def _ReadFileFooter(self):
    """Reads the file footer.

    Raises:
      IOError: if the file footer cannot be read.
    """
    file_footer_data = self._file_object.read(self._FILE_FOOTER.sizeof())

    if self._debug:
      print(u'File footer data:')
      print(hexdump.Hexdump(file_footer_data))

  def _ReadFileHeader(self):
    """Reads the file header.

    Raises:
      IOError: if the file header cannot be read.
    """
    if self._debug:
      print(u'Seeking file header offset: 0x{0:08x}'.format(0))

    self._file_object.seek(0, os.SEEK_SET)

    file_header_data = self._file_object.read(self._FILE_HEADER.sizeof())

    if self._debug:
      print(u'File header data:')
      print(hexdump.Hexdump(file_header_data))

    try:
      file_header_struct = self._FILE_HEADER.parse(file_header_data)
    except construct.FieldError as exception:
      raise IOError(
          u'Unable to parse file header with error: {0:s}'.format(exception))

    if self._debug:
      print(u'Signature\t\t\t\t\t\t\t: {0!s}'.format(
          file_header_struct.signature))
      print(u'Number of pages\t\t\t\t\t\t\t: {0:d}'.format(
          file_header_struct.number_of_pages))

      print(u'')

    page_sizes_data_size = file_header_struct.number_of_pages * 4

    page_sizes_data = self._file_object.read(page_sizes_data_size)

    if self._debug:
      print(u'Page sizes data:')
      print(hexdump.Hexdump(page_sizes_data))

    try:
      page_sizes_array = construct.Array(
             file_header_struct.number_of_pages,
             construct.UBInt32(u'page_sizes')).parse(page_sizes_data)

    except construct.FieldError as exception:
      raise IOError(
          u'Unable to parse page sizes array with error: {0:s}'.format(
              exception))

    self._page_sizes = []
    for page_index in range(file_header_struct.number_of_pages):
      self._page_sizes.append(page_sizes_array[page_index])

      if self._debug:
        print(u'Page: {0:d} size\t\t\t\t\t\t\t: {1:d}'.format(
            page_index, page_sizes_array[page_index]))

    if self._debug:
      print(u'')

  def _ReadPages(self):
    """Reads the pages."""
    for page_size in iter(self._page_sizes):
      self._ReadPage(page_size)

  def _ReadPage(self, page_size):
    """Reads the page.

    Args:
      page_size (int): page size.
    """
    page_data = self._file_object.read(page_size)

    try:
      page_header_struct = self._PAGE_HEADER.parse(page_data)
    except construct.FieldError as exception:
      raise IOError(
          u'Unable to parse file header with error: {0:s}'.format(exception))

    page_header_data_size = 8 + (4 * page_header_struct.number_of_records)

    if self._debug:
      print(u'Page header data:')
      print(hexdump.Hexdump(page_data[:page_header_data_size]))

    if self._debug:
      print(u'Signature\t\t\t\t\t\t\t: 0x{0:08x}'.format(
          page_header_struct.signature))
      print(u'Number of records\t\t\t\t\t\t: {0:d}'.format(
          page_header_struct.number_of_records))

    record_offsets = []
    for record_index in range(page_header_struct.number_of_records):
      record_offsets.append(page_header_struct.offsets[record_index])

      if self._debug:
        print(u'Record: {0:d} offset\t\t\t\t\t\t: {1:d}'.format(
            record_index, page_header_struct.offsets[record_index]))

    if self._debug:
      print(u'')

    for record_offset in iter(record_offsets):
      self._ParseRecord(page_data, record_offset)

  def _ParseRecord(self, page_data, record_offset):
    """Reads a record from the page data.

    Args:
      page_data (bytes): page data.
      record_offset (int): record offset.
    """
    try:
      record_header_struct = self._RECORD_HEADER.parse(
          page_data[record_offset:])
    except construct.FieldError as exception:
      raise IOError(
          u'Unable to parse record header with error: {0:s}'.format(exception))

    record_data_size = record_offset + record_header_struct.size

    if self._debug:
      print(u'Record data:')
      print(hexdump.Hexdump(page_data[record_offset:record_data_size]))

    if self._debug:
      print(u'Size\t\t\t\t\t\t\t\t: {0:d}'.format(record_header_struct.size))
      print(u'Unknown1\t\t\t\t\t\t\t: 0x{0:08x}'.format(
          record_header_struct.unknown1))
      print(u'Flags\t\t\t\t\t\t\t\t: 0x{0:08x}'.format(
          record_header_struct.flags))
      print(u'Unknown2\t\t\t\t\t\t\t: 0x{0:08x}'.format(
          record_header_struct.unknown2))
      print(u'URL offset\t\t\t\t\t\t\t: {0:d}'.format(
          record_header_struct.url_offset))
      print(u'name offset\t\t\t\t\t\t\t: {0:d}'.format(
          record_header_struct.name_offset))
      print(u'path offset\t\t\t\t\t\t\t: {0:d}'.format(
          record_header_struct.path_offset))
      print(u'value offset\t\t\t\t\t\t\t: {0:d}'.format(
          record_header_struct.value_offset))
      print(u'Unknown3\t\t\t\t\t\t\t: 0x{0:08x}'.format(
          record_header_struct.unknown3))
      print(u'expiration date\t\t\t\t\t\t\t: {0:f}'.format(
          record_header_struct.expiration_date))
      print(u'creation date\t\t\t\t\t\t\t: {0:f}'.format(
          record_header_struct.creation_date))
      print(u'')

      if record_header_struct.url_offset:
        data_offset = record_offset + record_header_struct.url_offset
        string = construct.CString(u'string').parse(
            page_data[data_offset:record_data_size])
      else:
        sting = u''

      print(u'URL\t\t\t\t\t\t\t\t: {0:s}'.format(string))

      if record_header_struct.name_offset:
        data_offset = record_offset + record_header_struct.name_offset
        string = construct.CString(u'string').parse(
            page_data[data_offset:record_data_size])
      else:
        sting = u''

      print(u'Name\t\t\t\t\t\t\t\t: {0:s}'.format(string))

      if record_header_struct.path_offset:
        data_offset = record_offset + record_header_struct.path_offset
        string = construct.CString(u'string').parse(
            page_data[data_offset:record_data_size])
      else:
        sting = u''

      print(u'Path\t\t\t\t\t\t\t\t: {0:s}'.format(string))

      if record_header_struct.value_offset:
        data_offset = record_offset + record_header_struct.value_offset
        string = construct.CString(u'string').parse(
            page_data[data_offset:record_data_size])
      else:
        sting = u''

      print(u'Value\t\t\t\t\t\t\t\t: {0:s}'.format(string))

      print(u'')

  def Close(self):
    """Closes a file."""
    if self._file_object_opened_in_object:
      self._file_object.close()
    self._file_object = None

  def Open(self, filename):
    """Opens a file.

    Args:
      filename (str): filename.
    """
    stat_object = os.stat(filename)
    self._file_size = stat_object.st_size

    self._file_object = open(filename, 'rb')
    self._file_object_opened_in_object = True

    self._ReadFileHeader()
    self._ReadPages()
    self._ReadFileFooter()


class StdoutWriter(object):
  """Class that defines a stdout output writer."""

  def Close(self):
    """Closes the output writer object."""
    return

  def Open(self):
    """Opens the output writer object.

    Returns:
      bool: True if successful or False if not.
    """
    return True

  def WriteText(self, text):
    """Writes text to stdout.

    Args:
      text (str): text to write.
    """
    print(text)


def Main():
  """The main program function.

  Returns:
    bool: True if successful or False if not.
  """
  argument_parser = argparse.ArgumentParser(description=(
      u'Extracts information from Safari Cookies files.'))

  argument_parser.add_argument(
      u'-d', u'--debug', dest=u'debug', action=u'store_true', default=False,
      help=u'enable debug output.')

  argument_parser.add_argument(
      u'source', nargs=u'?', action=u'store', metavar=u'PATH',
      default=None, help=u'path of the Cookies.binarycookies file.')

  options = argument_parser.parse_args()

  if not options.source:
    print(u'Source file missing.')
    print(u'')
    argument_parser.print_help()
    print(u'')
    return False

  output_writer = StdoutWriter()

  if not output_writer.Open():
    print(u'Unable to open output writer.')
    print(u'')
    return False

  logging.basicConfig(
      level=logging.INFO, format=u'[%(levelname)s] %(message)s')

  binary_cookies_file = BinaryCookiesFile(debug=options.debug)
  binary_cookies_file.Open(options.source)

  output_writer.WriteText(u'Safari Cookies information:')
  # TODO: print cookies information.

  binary_cookies_file.Close()

  output_writer.Close()

  return True


if __name__ == '__main__':
  if not Main():
    sys.exit(1)
  else:
    sys.exit(0)
