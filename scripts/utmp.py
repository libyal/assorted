#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Script to parse utmp files."""

from __future__ import print_function
import argparse
import datetime
import logging
import os
import sys

import construct

import hexdump


class UTMPFile(object):
  """Class that defines an UTMP file."""

  _UTMP_ENTRY = construct.Struct(
      u'utmp_linux',
      construct.ULInt32(u'type'),
      construct.ULInt32(u'pid'),
      construct.String(u'terminal', 32),
      construct.ULInt32(u'terminal_id'),
      construct.String(u'username', 32),
      construct.String(u'hostname', 256),
      construct.ULInt16(u'termination'),
      construct.ULInt16(u'exit'),
      construct.ULInt32(u'session'),
      construct.ULInt32(u'timestamp'),
      construct.ULInt32(u'micro_seconds'),
      construct.ULInt32(u'address_a'),
      construct.ULInt32(u'address_b'),
      construct.ULInt32(u'address_c'),
      construct.ULInt32(u'address_d'),
      construct.Padding(20))

  def __init__(self, debug=False):
    """Initializes an UTMP file.

    Args:
      debug (Optional[bool]): True if debug information should be printed.
    """
    super(UTMPFile, self).__init__()
    self._debug = debug
    self._file_object = None
    self._file_object_opened_in_object = False
    self._file_size = 0

    self.file_format = None
    self.size = None

  def _ReadEntry(self, file_offset):
    """Reads an entry.

    Args:
      file_offset (int): entry offset relative to the start of the file.

    Returns:
      int: size of the entry.

    Raises:
      IOError: if the entry cannot be read.
    """
    if self._debug:
      print(u'Seeking entry at offset: 0x{0:08x}'.format(file_offset))

    self._file_object.seek(file_offset, os.SEEK_SET)

    entry_struct_size = self._UTMP_ENTRY.sizeof()
    entry_data = self._file_object.read(entry_struct_size)
    file_offset += entry_struct_size

    if self._debug:
      print(u'Entry data:')
      print(hexdump.Hexdump(entry_data))

    try:
      entry_struct = self._UTMP_ENTRY.parse(entry_data)
    except construct.FieldError as exception:
      raise IOError((
          u'Unable to parse entry data section with error: '
          u'{0:s}').file_format(exception))

    if self._debug:
      print(u'Type\t\t\t\t\t\t\t\t: 0x{0:08x}'.format(entry_struct.type))
      print(u'PID\t\t\t\t\t\t\t\t: {0:d}'.format(entry_struct.pid))

      terminal = entry_struct.terminal.replace(u'\0', '')
      print(u'Terminal\t\t\t\t\t\t\t: {0:s}'.format(terminal))
      print(u'Terminal ID\t\t\t\t\t\t\t: {0:d}'.format(entry_struct.terminal_id))

      username = entry_struct.username.replace(u'\0', '')
      print(u'Username\t\t\t\t\t\t\t: {0:s}'.format(username))

      hostname = entry_struct.hostname.replace(u'\0', '')
      print(u'Hostname\t\t\t\t\t\t\t: {0:s}'.format(hostname))
      print(u'Termination\t\t\t\t\t\t\t: 0x{0:04x}'.format(entry_struct.termination))
      print(u'Exit\t\t\t\t\t\t\t\t: 0x{0:04x}'.format(entry_struct.exit))
      print(u'Session\t\t\t\t\t\t\t\t: {0:d}'.format(entry_struct.session))

      date_time = (datetime.datetime(1970, 1, 1) + datetime.timedelta(
          seconds=int(entry_struct.timestamp)))
      print(u'Timestamp\t\t\t\t\t\t\t: {0!s} ({1:d})'.format(
          date_time, entry_struct.timestamp))

      print(u'Micro seconds\t\t\t\t\t\t\t: {0:d}'.format(entry_struct.micro_seconds))
      print(u'Address A\t\t\t\t\t\t\t: 0x{0:08x}'.format(entry_struct.address_a))
      print(u'Address B\t\t\t\t\t\t\t: 0x{0:08x}'.format(entry_struct.address_b))
      print(u'Address C\t\t\t\t\t\t\t: 0x{0:08x}'.format(entry_struct.address_c))
      print(u'Address D\t\t\t\t\t\t\t: 0x{0:08x}'.format(entry_struct.address_d))
      print(u'')

    return entry_struct_size

  def _ReadEntries(self):
    """Reads the entries from the utmp file."""
    file_offset = 0
    while file_offset < self._file_size:
      file_offset += self._ReadEntry(file_offset)

  def Close(self):
    """Closes an UTMP file."""
    if not self._file_object:
      return

    if self._file_object_opened_in_object:
      self._file_object.close()
      self._file_object_opened_in_object = False
    self._file_object = None

  def Open(self, filename):
    """Opens an UTMP file.

    Args:
      filename (str): filename.

    Raises:
      IOError: if the file format signature is not supported.
    """
    stat_object = os.stat(filename)

    file_object = open(filename, 'rb')

    self._file_size = stat_object.st_size

    self.OpenFileObject(file_object)

    self._file_object_opened_in_object = True

  def OpenFileObject(self, file_object):
    """Opens an UTMP file.

    Args:
      file_object (file): file-like object.

    Raises:
      IOError: if the file is alread opened or the format signature is
               not supported.
    """
    if self._file_object:
      raise IOError(u'Already open')

    self._file_object = file_object

    self._ReadEntries()

    # TODO: print trailing data


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
      u'Extracts information from UTMP files.'))

  argument_parser.add_argument(
      u'-d', u'--debug', dest=u'debug', action=u'store_true', default=False,
      help=u'enable debug output.')

  argument_parser.add_argument(
      u'source', nargs=u'?', action=u'store', metavar=u'PATH',
      default=None, help=u'path of the UTMP file.')

  options = argument_parser.parse_args()

  if not options.source:
    print(u'Source file missing.')
    print(u'')
    argument_parser.print_help()
    print(u'')
    return False

  logging.basicConfig(
      level=logging.INFO, format=u'[%(levelname)s] %(message)s')

  output_writer = StdoutWriter()

  if not output_writer.Open():
    print(u'Unable to open output writer.')
    print(u'')
    return False

  utmp_file = UTMPFile(debug=options.debug)
  utmp_file.Open(options.source)

  output_writer.WriteText(u'UTMP information:')

  utmp_file.Close()

  output_writer.WriteText(u'')
  output_writer.Close()

  return True


if __name__ == '__main__':
  if not Main():
    sys.exit(1)
  else:
    sys.exit(0)
