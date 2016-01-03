#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Script to parse WMI repository objects.data files."""

from __future__ import print_function
import argparse
import datetime
import logging
import os
import sys

import construct

import hexdump


# pylint: disable=logging-format-interpolation

def FromFiletime(filetime):
  """Converts a FILETIME timestamp into a Python datetime object.

    The FILETIME is mainly used in Windows file formats and NTFS.

    The FILETIME is a 64-bit value containing:
      100th nano seconds since 1601-01-01 00:00:00

    Technically FILETIME consists of 2 x 32-bit parts and is presumed
    to be unsigned.

    Args:
      filetime: The 64-bit FILETIME timestamp.

  Returns:
    A datetime object containing the date and time or None.
  """
  if filetime < 0:
    return None
  timestamp, _ = divmod(filetime, 10)

  return datetime.datetime(1601, 1, 1) + datetime.timedelta(
      microseconds=timestamp)


class UnknownTableEntry(object):
  """Class that contains an unknown table entry."""

  def __init__(self):
    """Initializes the unknown table entry object."""
    super(UnknownTableEntry, self).__init__()
    self.unknown_record_offset = 0
    self.unknown_record_size = 0


class WMIRepositoryObjectsDataFile(object):
  """Class that contains a WMI repository objects.data file."""

  _UNKNOWN_TABLE_ENTRY = construct.Struct(
      u'unknown_table_entry',
      construct.ULInt32(u'unknown1'),
      construct.ULInt32(u'unknown_record_offset'),
      construct.ULInt32(u'unknown_record_size'),
      construct.ULInt32(u'unknown2'))

  _UNKNOWN_RECORD_HEADER = construct.Struct(
      u'unknown_record_header',
      construct.ULInt32(u'number_of_characters'),
      construct.String(
          u'utf16_stream', lambda ctx: ctx.number_of_characters * 2),
      construct.ULInt64(u'filetime'))

  def __init__(self, debug=False):
    """Initializes the objects.data file object.

    Args:
      debug: optional boolean value to indicate if debug information should
             be printed.
    """
    super(WMIRepositoryObjectsDataFile, self).__init__()
    self._debug = debug
    self._file_object = None
    self._file_object_opened_in_object = False
    self._file_size = 0

    self._unknown_table = []

  def _ReadUnknownRecord(self, offset, size):
    """Reads an unknown record.

    Args:
      offset: the offset.
      size: the size.

    Raises:
      IOError: if the unknown record cannot be read.
    """
    if self._debug:
      print(u'Seeking unknown record offset: 0x{0:08x}'.format(offset))

    self._file_object.seek(offset, os.SEEK_SET)

    unknown_record_data = self._file_object.read(size)

    if self._debug:
      print(u'Unknown record data:')
      print(hexdump.Hexdump(unknown_record_data))

    if unknown_record_data[2:4] != b'\x00\x00':
      return

    try:
      unknown_record_header = self._UNKNOWN_RECORD_HEADER.parse(
          unknown_record_data)
    except construct.FieldError as exception:
      raise IOError(
          u'Unable to parse unknown table entry with error: {0:s}'.format(
              exception))

    utf16_stream = unknown_record_header.get(u'utf16_stream')
    filetime = unknown_record_header.get(u'filetime')

    try:
      value_string = b''.join(utf16_stream).decode(u'utf16')
    except UnicodeDecodeError as exception:
      value_string = u''

    if self._debug:
      print(u'Number of characters\t\t\t\t\t\t\t: {0:d}'.format(
          unknown_record_header.get(u'number_of_characters')))
      print(u'String\t\t\t\t\t\t\t\t\t: {0:s}'.format(value_string))
      print(u'Date and time\t\t\t\t\t\t\t\t: {0!s}'.format(
          FromFiletime(filetime)))
      print(u'')

  def _ReadUnknownRecords(self):
    """Reads the unknown records.

    Raises:
      IOError: if the unknown records cannot be read.
    """
    for unknown_table_entry in self._unknown_table:
      self._ReadUnknownRecord(
          unknown_table_entry.unknown_record_offset,
          unknown_table_entry.unknown_record_size)

  def _ReadUnknownTable(self, offset):
    """Reads the unknown table.

    Args:
      offset: the offset.

    Raises:
      IOError: if the unknown table cannot be read.
    """
    if self._debug:
      print(u'Seeking unknown table offset: 0x{0:08x}'.format(offset))

    self._file_object.seek(offset, os.SEEK_SET)

    terminator = False
    while not terminator:
      unknown_table_entry_data = self._file_object.read(
          self._UNKNOWN_TABLE_ENTRY.sizeof())

      if self._debug:
        print(u'Unknown table entry data:')
        print(hexdump.Hexdump(unknown_table_entry_data))

      try:
        unknown_table_entry_struct = self._UNKNOWN_TABLE_ENTRY.parse(
            unknown_table_entry_data)
      except construct.FieldError as exception:
        raise IOError(
            u'Unable to parse unknown table entry with error: {0:s}'.format(
                exception))

      unknown1 = unknown_table_entry_struct.get(u'unknown1')
      unknown_record_offset = unknown_table_entry_struct.get(
          u'unknown_record_offset')
      unknown_record_size = unknown_table_entry_struct.get(
          u'unknown_record_size')
      unknown2 = unknown_table_entry_struct.get(u'unknown2')

      if self._debug:
        print(u'Unknown1\t\t\t\t\t\t\t\t: 0x{0:08x}'.format(unknown1))
        print((
            u'Unknown record offset\t\t\t\t\t\t\t: 0x{0:08x} '
            u'(0x{1:08x})').format(
                unknown_record_offset, offset + unknown_record_offset))
        print(u'Unknown record size\t\t\t\t\t\t\t: {0:d}'.format(
            unknown_record_size))
        print(u'Unknown2\t\t\t\t\t\t\t\t: 0x{0:08x}'.format(unknown2))
        print(u'')

      if (unknown1 == 0 and unknown_record_offset == 0 and
          unknown_record_size == 0 and unknown2 == 0):
        terminator = True
      else:
        unknown_table_entry = UnknownTableEntry()
        unknown_table_entry.unknown_record_offset = (
            offset + unknown_record_offset)
        unknown_table_entry.unknown_record_size = unknown_record_size
        self._unknown_table.append(unknown_table_entry)

  def Close(self):
    """Closes the objects.data file."""
    if self._file_object_opened_in_object:
      self._file_object.close()
    self._file_object = None

  def Open(self, filename):
    """Opens the objects.data file.

    Args:
      filename: the filename.
    """
    stat_object = os.stat(filename)
    self._file_size = stat_object.st_size

    self._file_object = open(filename, 'rb')
    self._file_object_opened_in_object = True

    offset = 0
    while offset < self._file_size:
      self._ReadUnknownTable(offset)
      self._ReadUnknownRecords()

      offset += 0x00002000
      self._unknown_table = []


def Main():
  """The main program function.

  Returns:
    A boolean containing True if successful or False if not.
  """
  argument_parser = argparse.ArgumentParser(description=(
      u'Extracts information from WMI repository objects.data files.'))

  argument_parser.add_argument(
      u'-d', u'--debug', dest=u'debug', action=u'store_true', default=False,
      help=u'enable debug output.')

  argument_parser.add_argument(
      u'source', nargs=u'?', action=u'store', metavar=u'PATH',
      default=None, help=u'path of the WMI repository objects.data file.')

  options = argument_parser.parse_args()

  if not options.source:
    print(u'Source file missing.')
    print(u'')
    argument_parser.print_help()
    print(u'')
    return False

  logging.basicConfig(
      level=logging.INFO, format=u'[%(levelname)s] %(message)s')

  objects_data_file = WMIRepositoryObjectsDataFile(debug=options.debug)
  objects_data_file.Open(options.source)

  print(u'WMI repository objects.data information:')
  print(u'')

  objects_data_file.Close()

  return True


if __name__ == '__main__':
  if not Main():
    sys.exit(1)
  else:
    sys.exit(0)
