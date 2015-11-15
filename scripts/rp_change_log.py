#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Script to parse Windows Restore Point change.log files."""

from __future__ import print_function
import argparse
import logging
import os
import sys

import construct

import hexdump


# pylint: disable=logging-format-interpolation

class ChangeLogEntry(object):
  """Class that contains a Windows Restore Point change log entry."""

  def __init__(self):
    """Initializes the change log entry object."""
    super(ChangeLogEntry, self).__init__()
    self.entry_type = 0
    self.entry_flags = 0
    self.file_attribute_flags = 0
    self.process_name = u''
    self.sequence_number = 0


class RestorePointChangeLogFile(object):
  """Class that contains a Windows Restore Point change.log file."""

  SIGNATURE = 0xabcdef12

  _CHANGE_LOG_ENTRY = construct.Struct(
      u'restore_point_change_log_entry',
      construct.ULInt32(u'record_size'),
      construct.ULInt32(u'record_type'),
      construct.ULInt32(u'signature'),
      construct.ULInt32(u'entry_type'),
      construct.ULInt32(u'entry_flags'),
      construct.ULInt32(u'file_attribute_flags'),
      construct.ULInt64(u'sequence_number'),
      construct.Padding(32),
      construct.ULInt32(u'process_name_data_size'),
      construct.ULInt32(u'unknown1'),
      construct.RepeatUntil(
          lambda obj, ctx: obj == b'\x00\x00',
          construct.Field(u'process_name', 2)),
      construct.Anchor(u'sub_record_data'))

  _FILE_HEADER = construct.Struct(
      u'restore_point_change_log_file_header',
      construct.ULInt32(u'record_size'),
      construct.ULInt32(u'record_type'),
      construct.ULInt32(u'signature'),
      construct.ULInt32(u'format_version'))

  _RECORD_HEADER = construct.Struct(
      u'restore_point_change_log_record_header',
      construct.ULInt32(u'record_size'),
      construct.ULInt32(u'record_type'))

  _UTF16_STREAM = construct.RepeatUntil(
      lambda obj, ctx: obj == b'\x00\x00',
      construct.Field(u'stream', 2))

  _VOLUME_PATH = construct.Struct(
      u'restore_point_change_log_volume_path',
      construct.ULInt32(u'record_size'),
      construct.ULInt32(u'record_type'),
      construct.RepeatUntil(
          lambda obj, ctx: obj == b'\x00\x00',
          construct.Field(u'volume_path', 2)))

  LOG_ENTRY_FLAGS = {
      0x00000001: u'CHANGE_LOG_ENTRYFLAGS_TEMPPATH',
      0x00000002: u'CHANGE_LOG_ENTRYFLAGS_SECONDPATH',
      0x00000004: u'CHANGE_LOG_ENTRYFLAGS_ACLINFO',
      0x00000008: u'CHANGE_LOG_ENTRYFLAGS_DEBUGINFO',
      0x00000010: u'CHANGE_LOG_ENTRYFLAGS_SHORTNAME',
  }

  LOG_ENTRY_TYPES = {
      0x00000001: u'CHANGE_LOG_ENTRYTYPES_STREAMCHANGE',
      0x00000002: u'CHANGE_LOG_ENTRYTYPES_ACLCHANGE',
      0x00000004: u'CHANGE_LOG_ENTRYTYPES_ATTRCHANGE',
      0x00000008: u'CHANGE_LOG_ENTRYTYPES_STREAMOVERWRITE',
      0x00000010: u'CHANGE_LOG_ENTRYTYPES_FILEDELETE',
      0x00000020: u'CHANGE_LOG_ENTRYTYPES_FILECREATE',
      0x00000040: u'CHANGE_LOG_ENTRYTYPES_FILERENAME',
      0x00000080: u'CHANGE_LOG_ENTRYTYPES_DIRCREATE',
      0x00000100: u'CHANGE_LOG_ENTRYTYPES_DIRRENAME',
      0x00000200: u'CHANGE_LOG_ENTRYTYPES_DIRDELETE',
      0x00000400: u'CHANGE_LOG_ENTRYTYPES_MOUNTCREATE',
      0x00000800: u'CHANGE_LOG_ENTRYTYPES_MOUNTDELETE',
      0x00001000: u'CHANGE_LOG_ENTRYTYPES_VOLUMEERROR',
      0x00002000: u'CHANGE_LOG_ENTRYTYPES_STREAMCREATE',
      0x00010000: u'CHANGE_LOG_ENTRYTYPES_NOOPTIMIZE',
      0x00020000: u'CHANGE_LOG_ENTRYTYPES_ISDIR',
      0x00040000: u'CHANGE_LOG_ENTRYTYPES_ISNOTDIR',
      0x00080000: u'CHANGE_LOG_ENTRYTYPES_SIMULATEDELETE',
      0x00100000: u'CHANGE_LOG_ENTRYTYPES_INPRECREATE',
      0x00200000: u'CHANGE_LOG_ENTRYTYPES_OPENBYID',
  }

  _RECORD_TYPES = {
      0: u'RecordTypeLogHeader',
      1: u'RecordTypeLogEntry',
      2: u'RecordTypeVolumePath',
      3: u'RecordTypeFirstPath',
      4: u'RecordTypeSecondPath',
      5: u'RecordTypeTempPath',
      6: u'RecordTypeAclInline',
      7: u'RecordTypeAclFile',
      8: u'RecordTypeDebugInfo',
      9: u'RecordTypeShortName',
  }

  def __init__(self, debug=False):
    """Initializes the change.log file object.

    Args:
      debug: optional boolean value to indicate if debug information should
             be printed. The default is false.
    """
    super(RestorePointChangeLogFile, self).__init__()
    self._debug = debug
    self._file_object = None
    self._file_object_opened_in_object = False
    self._file_size = 0

    self.entries = []
    self.volume_path = None

  def _ReadChangeLogEntries(self):
    """Reads the change log entries.

    Raises:
      IOError: if the change log entries cannot be read.
    """
    while self._file_object.tell() < self._file_size:
      change_log_entry = self._ReadChangeLogEntry()
      self.entries.append(change_log_entry)

  def _ReadChangeLogEntry(self):
    """Reads a change log entry.

    Returns:
      A change log entry (instance of ChangeLogEntry).

    Raises:
      IOError: if the change log entry cannot be read.
    """
    file_offset = self._file_object.tell()

    try:
      change_log_entry_struct = self._CHANGE_LOG_ENTRY.parse_stream(
          self._file_object)
    except construct.FieldError as exception:
      raise IOError(
          u'Unable to parse change log entry with error: {0:s}'.format(
              exception))

    record_size = change_log_entry_struct.get(u'record_size')

    record_type = change_log_entry_struct.get(u'record_type')
    if record_type != 1:
      raise IOError(u'Unsupported record type: {0:d}'.format(record_type))

    signature = change_log_entry_struct.get(u'signature')
    if signature != self.SIGNATURE:
      raise IOError(u'Unsupported change.log file signature')

    change_log_entry = ChangeLogEntry()
    change_log_entry.entry_type = change_log_entry_struct.get(u'entry_type')
    change_log_entry.entry_flags = change_log_entry_struct.get(u'entry_flags')
    change_log_entry.file_attribute_flags = change_log_entry_struct.get(
        u'file_attribute_flags')
    change_log_entry.sequence_number = change_log_entry_struct.get(
        u'sequence_number')

    try:
      # The struct includes the end-of-string character that we need
      # to strip off.
      process_name = change_log_entry_struct.get(u'process_name')
      process_name = b''.join(process_name).decode(u'utf16')[:-1]
    except UnicodeDecodeError as exception:
      process_name = u''

    change_log_entry.process_name = process_name

    self._file_object.seek(file_offset, os.SEEK_SET)

    change_log_entry_record_data = self._file_object.read(record_size)

    if self._debug:
      print(u'Change log entry record data:')
      print(hexdump.Hexdump(change_log_entry_record_data))

    if self._debug:
      print(u'Record size\t\t\t\t\t\t\t\t: {0:d}'.format(record_size))
      print(u'Record type\t\t\t\t\t\t\t\t: {0:d} ({1:s})'.format(
          record_type, self._RECORD_TYPES.get(record_type, u'Unknown')))
      print(u'Signature\t\t\t\t\t\t\t\t: 0x{0:08x}'.format(signature))
      print(u'Entry type\t\t\t\t\t\t\t\t: 0x{0:08x}'.format(
          change_log_entry.entry_type))
      for flag, description in self.LOG_ENTRY_TYPES.items():
        if change_log_entry.entry_type & flag:
          print(u'\t{0:s}'.format(description))
      print(u'')

      print(u'Entry flags\t\t\t\t\t\t\t\t: 0x{0:08x}'.format(
          change_log_entry.entry_flags))
      for flag, description in self.LOG_ENTRY_FLAGS.items():
        if change_log_entry.entry_flags & flag:
          print(u'\t{0:s}'.format(description))
      print(u'')

      print(u'File attribute flags\t\t\t\t\t\t\t: 0x{0:08x}'.format(
          change_log_entry.file_attribute_flags))
      # TODO: print flags.

      print(u'Sequence number\t\t\t\t\t\t\t\t: {0:d}'.format(
          change_log_entry.sequence_number))
      print(u'Process name data size\t\t\t\t\t\t\t: 0x{0:08x}'.format(
          change_log_entry_struct.get(u'process_name_data_size')))
      print(u'Unknown1\t\t\t\t\t\t\t\t: 0x{0:08x}'.format(
          change_log_entry_struct.get(u'unknown1')))
      print(u'Process name\t\t\t\t\t\t\t\t: {0:s}'.format(
          change_log_entry.process_name))

    sub_record_data_offset = (
        change_log_entry_struct.sub_record_data - file_offset)
    sub_record_data_size = record_size - 4
    if self._debug:
      print(u'Sub record data offset\t\t\t\t\t\t\t: {0:d}'.format(
          sub_record_data_offset))
      print(u'Sub record data size\t\t\t\t\t\t\t: {0:d}'.format(
          sub_record_data_size - sub_record_data_offset))
      if sub_record_data_offset < sub_record_data_size:
        print(u'')

    while sub_record_data_offset < sub_record_data_size:
      read_size = self._ReadRecord(
          change_log_entry_record_data, sub_record_data_offset)
      if read_size == 0:
        break
      sub_record_data_offset += read_size

    copy_of_record_size = construct.ULInt32(u'record_size').parse(
        change_log_entry_record_data[-4:])
    if record_size != copy_of_record_size:
      raise IOError(u'Record size mismatch ({0:d} != {1:d})'.format(
          record_size, copy_of_record_size))

    if self._debug:
      print(u'Copy of record size\t\t\t\t\t\t\t: {0:d}'.format(
          copy_of_record_size))
      print(u'')

    return change_log_entry

  def _ReadFileHeader(self):
    """Reads the file header.

    Raises:
      IOError: if the file header cannot be read.
    """
    if self._debug:
      print(u'Seeking file header offset: 0x{0:08x}'.format(0))

    self._file_object.seek(0, os.SEEK_SET)

    try:
      file_header_struct = self._FILE_HEADER.parse_stream(self._file_object)
    except construct.FieldError as exception:
      raise IOError(u'Unable to parse file header with error: {0:s}'.format(
          exception))

    signature = file_header_struct.get(u'signature')
    if signature != self.SIGNATURE:
      raise IOError(u'Unsupported change.log file signature')

    record_size = file_header_struct.get(u'record_size')

    record_type = file_header_struct.get(u'record_type')
    if record_type != 0:
      raise IOError(u'Unsupported record type: {0:d}'.format(record_type))

    format_version = file_header_struct.get(u'format_version')
    if format_version != 2:
      raise IOError(u'Unsupported change.log format version: {0:d}'.format(
          format_version))

    self._file_object.seek(0, os.SEEK_SET)

    file_header_data = self._file_object.read(record_size)

    if self._debug:
      print(u'File header data:')
      print(hexdump.Hexdump(file_header_data))

    if self._debug:
      print(u'Record size\t\t\t\t\t\t\t\t: {0:d}'.format(record_size))
      print(u'Record type\t\t\t\t\t\t\t\t: {0:d} ({1:s})'.format(
          record_type, self._RECORD_TYPES.get(record_type, u'Unknown')))
      print(u'Signature\t\t\t\t\t\t\t\t: 0x{0:08x}'.format(signature))
      print(u'Format version\t\t\t\t\t\t\t\t: {0:d}'.format(format_version))

    self._ReadVolumePath(file_header_data[16:-4])

    copy_of_record_size = construct.ULInt32(u'record_size').parse(
        file_header_data[-4:])
    if record_size != copy_of_record_size:
      raise IOError(u'Record size mismatch ({0:d} != {1:d})'.format(
          record_size, copy_of_record_size))

    if self._debug:
      print(u'Copy of record size\t\t\t\t\t\t\t: {0:d}'.format(
          copy_of_record_size))
      print(u'')

  def _ReadRecord(self, record_data, record_data_offset):
    """Reads a record.

    Args:
      record_data: the record data.
      record_data_offset: the record data offset.

    Returns:
      The record size.

    Raises:
      IOError: if the record cannot be read.
    """
    try:
      record_header_struct = self._RECORD_HEADER.parse(
          record_data[record_data_offset:])
    except construct.FieldError as exception:
      raise IOError(
          u'Unable to parse record header with error: {0:s}'.format(
              exception))

    record_size = record_header_struct.get(u'record_size')
    record_type = record_header_struct.get(u'record_type')

    if self._debug:
      print(u'Record data:')
      print(hexdump.Hexdump(
          record_data[record_data_offset:record_data_offset + record_size]))

    if self._debug:
      print(u'Record size\t\t\t\t\t\t\t\t: {0:d}'.format(record_size))
      print(u'Record type\t\t\t\t\t\t\t\t: {0:d} ({1:s})'.format(
          record_type, self._RECORD_TYPES.get(record_type, u'Unknown')))

    record_data_offset += self._RECORD_HEADER.sizeof()

    if record_type in [4, 5, 9]:
      try:
        utf16_stream = self._UTF16_STREAM.parse(
            record_data[record_data_offset:])
      except construct.FieldError as exception:
        raise IOError(u'Unable to parse UTF-16 stream with error: {0:s}'.format(
            exception))

      try:
        # The UTF-16 stream includes the end-of-string character that we need
        # to strip off.
        value_string = b''.join(utf16_stream).decode(u'utf16')[:-1]
      except UnicodeDecodeError as exception:
        value_string = u''

    # TODO: add support for other record types.
    # TODO: store record values in runtime objects.

    if self._debug:
      if record_type == 4:
        print(u'Secondary path\t\t\t\t\t\t\t\t: {0:s}'.format(value_string))
      elif record_type == 5:
        print(u'Backup filename\t\t\t\t\t\t\t\t: {0:s}'.format(value_string))
      elif record_type == 9:
        print(u'Short filename\t\t\t\t\t\t\t\t: {0:s}'.format(value_string))

      print(u'')

    return record_size

  def _ReadVolumePath(self, volume_path_record_data):
    """Reads the volume path.

    Args:
      volume_path_record_data: the volume path record data.

    Raises:
      IOError: if the volume path cannot be read.
    """
    try:
      volume_path_struct = self._VOLUME_PATH.parse(volume_path_record_data)
    except construct.FieldError as exception:
      raise IOError(u'Unable to parse volume path with error: {0:s}'.format(
          exception))

    record_size = volume_path_struct.get(u'record_size')

    record_type = volume_path_struct.get(u'record_type')
    if record_type != 2:
      raise IOError(u'Unsupported record type: {0:d}'.format(record_type))

    if self._debug:
      print(u'Volume path record data:')
      print(hexdump.Hexdump(volume_path_record_data))

    try:
      # The struct includes the end-of-string character that we need
      # to strip off.
      self.volume_path = volume_path_struct.get(u'volume_path')
      self.volume_path = b''.join(self.volume_path).decode(u'utf16')[:-1]
    except UnicodeDecodeError as exception:
      self.volume_path = u''

    if self._debug:
      print(u'Record size\t\t\t\t\t\t\t\t: {0:d}'.format(record_size))
      print(u'Record type\t\t\t\t\t\t\t\t: {0:d} ({1:s})'.format(
          record_type, self._RECORD_TYPES.get(record_type, u'Unknown')))
      print(u'Volume path\t\t\t\t\t\t\t\t: {0:s}'.format(self.volume_path))
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
    self._ReadFileHeader()
    self._ReadChangeLogEntries()


def Main():
  """The main program function.

  Returns:
    A boolean containing True if successful or False if not.
  """
  argument_parser = argparse.ArgumentParser(description=(
      u'Extracts information from Windows Restore Point change.log files.'))

  argument_parser.add_argument(
      u'-d', u'--debug', dest=u'debug', action=u'store_true', default=False,
      help=u'enable debug output.')

  argument_parser.add_argument(
      u'source', nargs=u'?', action=u'store', metavar=u'PATH',
      default=None, help=u'path of the Windows Restore Point change.log file.')

  options = argument_parser.parse_args()

  if not options.source:
    print(u'Source file missing.')
    print(u'')
    argument_parser.print_help()
    print(u'')
    return False

  logging.basicConfig(
      level=logging.INFO, format=u'[%(levelname)s] %(message)s')

  change_log_file = RestorePointChangeLogFile(debug=options.debug)
  change_log_file.Open(options.source)

  print(u'Windows Restore Point change.log information:')
  print(u'Volume path:\t{0:s}'.format(change_log_file.volume_path))
  print(u'')

  for change_log_entry in change_log_file.entries:
    flags = []
    for flag, description in change_log_file.LOG_ENTRY_TYPES.items():
      if change_log_entry.entry_type & flag:
        flags.append(description)

    print(u'Entry type:\t\t{0:s}'.format(u', '.join(flags)))

    flags = []
    for flag, description in change_log_file.LOG_ENTRY_FLAGS.items():
      if change_log_entry.entry_flags & flag:
        flags.append(description)

    print(u'Entry flags:\t\t{0:s}'.format(u', '.join(flags)))

    print(u'Sequence number:\t{0:d}'.format(change_log_entry.sequence_number))
    print(u'Process name:\t\t{0:s}'.format(change_log_entry.process_name))

    print(u'')

  change_log_file.Close()

  return True


if __name__ == '__main__':
  if not Main():
    sys.exit(1)
  else:
    sys.exit(0)
