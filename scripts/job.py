#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Script to parse Windows job (Task Scheduler) files."""

from __future__ import print_function
import argparse
import logging
import os
import sys
import uuid

import construct

import hexdump


class JobFile(object):
  """Class that contains a .job file."""

  _JOB_FIXED_SIZE_DATA_STRUCT = construct.Struct(
      u'job_fixed_size_data',
      construct.ULInt16(u'product_version'),
      construct.ULInt16(u'format_version'),
      construct.Bytes(u'job_identifier', 16),
      construct.ULInt16(u'application_name_size_offset'),
      construct.ULInt16(u'trigger_offset'),
      construct.ULInt16(u'error_retry_count'),
      construct.ULInt16(u'error_retry_interval'),
      construct.ULInt16(u'idle_deadline'),
      construct.ULInt16(u'idle_wait'),
      construct.ULInt32(u'priority'),
      construct.ULInt32(u'maximum_run_time'),
      construct.ULInt32(u'exit_code'),
      construct.ULInt32(u'status'),
      construct.ULInt32(u'flags'),
      construct.ULInt16(u'year'),
      construct.ULInt16(u'month'),
      construct.ULInt16(u'weekday'),
      construct.ULInt16(u'day'),
      construct.ULInt16(u'hours'),
      construct.ULInt16(u'minutes'),
      construct.ULInt16(u'seconds'),
      construct.ULInt16(u'milliseconds'))

  _JOB_VARIABLE_SIZE_DATA_STRUCT = construct.Struct(
      u'job_variable_size_data',
      construct.Bytes(u'data', 1))

  def __init__(self, debug=False):
    """Initializes the .job file object.

    Args:
      debug: optional boolean value to indicate if debug information should
             be printed.
    """
    super(JobFile, self).__init__()
    self._debug = debug
    self._file_object = None
    self._file_object_opened_in_object = False
    self._file_size = 0

  def _ReadFixedSizeDataSection(self):
    """Reads the fixed size data section.

    Raises:
      IOError: if the file header cannot be read.
    """
    if self._debug:
      print(u'Seeking fixed size data offset: 0x{0:08x}'.format(0))

    self._file_object.seek(0, os.SEEK_SET)

    fixed_size_data = self._file_object.read(
        self._JOB_FIXED_SIZE_DATA_STRUCT.sizeof())

    if self._debug:
      print(u'Fixed size data:')
      print(hexdump.Hexdump(fixed_size_data))

    try:
      job_fixed_size_data_struct = self._JOB_FIXED_SIZE_DATA_STRUCT.parse(
          fixed_size_data)
    except construct.FieldError as exception:
      raise IOError((
          u'Unable to parse fixed size data section with error: '
          u'{0:s}').format(exception))

    if self._debug:
      print(u'Product version\t\t\t\t\t\t\t: 0x{0:04x}'.format(
          job_fixed_size_data_struct.product_version))
      print(u'Format version\t\t\t\t\t\t\t: 0x{0:04x}'.format(
          job_fixed_size_data_struct.format_version))

      uuid_object = uuid.UUID(
          bytes_le=job_fixed_size_data_struct.job_identifier)
      print(u'Job identifier\t\t\t\t\t\t\t: {0!s}'.format(uuid_object))

      print(u'Application name size offset\t\t\t\t\t: 0x{0:04x}'.format(
          job_fixed_size_data_struct.application_name_size_offset))
      print(u'Trigger offset\t\t\t\t\t\t\t: 0x{0:04x}'.format(
          job_fixed_size_data_struct.trigger_offset))

      print(u'Error retry count\t\t\t\t\t\t: {0:d}'.format(
          job_fixed_size_data_struct.error_retry_count))
      print(u'Error retry interval\t\t\t\t\t\t: {0:d} minutes'.format(
          job_fixed_size_data_struct.error_retry_interval))
      print(u'Idle deadline\t\t\t\t\t\t\t: {0:d} minutes'.format(
          job_fixed_size_data_struct.idle_deadline))
      print(u'Idle wait\t\t\t\t\t\t\t: {0:d} minutes'.format(
          job_fixed_size_data_struct.idle_wait))
      print(u'Priority\t\t\t\t\t\t\t: 0x{0:08x}'.format(
          job_fixed_size_data_struct.priority))
      print(u'Maximum run time\t\t\t\t\t\t: {0:d} milliseconds'.format(
          job_fixed_size_data_struct.maximum_run_time))
      print(u'Exit code\t\t\t\t\t\t\t: 0x{0:08x}'.format(
          job_fixed_size_data_struct.exit_code))
      print(u'Status\t\t\t\t\t\t\t\t: 0x{0:08x}'.format(
          job_fixed_size_data_struct.status))
      print(u'Flags\t\t\t\t\t\t\t\t: 0x{0:08x}'.format(
          job_fixed_size_data_struct.flags))

      print(u'Year\t\t\t\t\t\t\t\t: {0:d}'.format(
          job_fixed_size_data_struct.year))
      print(u'Month\t\t\t\t\t\t\t\t: {0:d}'.format(
          job_fixed_size_data_struct.month))
      print(u'Weekday\t\t\t\t\t\t\t\t: {0:d}'.format(
          job_fixed_size_data_struct.weekday))
      print(u'Day\t\t\t\t\t\t\t\t: {0:d}'.format(
          job_fixed_size_data_struct.day))
      print(u'Hours\t\t\t\t\t\t\t\t: {0:d}'.format(
          job_fixed_size_data_struct.hours))
      print(u'Minutes\t\t\t\t\t\t\t\t: {0:d}'.format(
          job_fixed_size_data_struct.minutes))
      print(u'Seconds\t\t\t\t\t\t\t\t: {0:d}'.format(
          job_fixed_size_data_struct.seconds))
      print(u'Milliseconds\t\t\t\t\t\t\t: {0:d}'.format(
          job_fixed_size_data_struct.milliseconds))

      print(u'')

  def _ReadVariableSizeDataSection(self):
    """Reads the variable size data section.

    Raises:
      IOError: if the file header cannot be read.
    """
    return

  def Close(self):
    """Closes the .job file."""
    if self._file_object_opened_in_object:
      self._file_object.close()
    self._file_object = None

  def Open(self, filename):
    """Opens the .job file.

    Args:
      filename: the filename.
    """
    stat_object = os.stat(filename)
    self._file_size = stat_object.st_size

    self._file_object = open(filename, 'rb')
    self._file_object_opened_in_object = True

    self._ReadFixedSizeDataSection()
    self._ReadVariableSizeDataSection()


def Main():
  """The main program function.

  Returns:
    A boolean containing True if successful or False if not.
  """
  argument_parser = argparse.ArgumentParser(description=(
      u'Extracts information from Windows Job files.'))

  argument_parser.add_argument(
      u'-d', u'--debug', dest=u'debug', action=u'store_true', default=False,
      help=u'enable debug output.')

  argument_parser.add_argument(
      u'source', nargs=u'?', action=u'store', metavar=u'PATH',
      default=None, help=u'path of the Windows Job file.')

  options = argument_parser.parse_args()

  if not options.source:
    print(u'Source file missing.')
    print(u'')
    argument_parser.print_help()
    print(u'')
    return False

  logging.basicConfig(
      level=logging.INFO, format=u'[%(levelname)s] %(message)s')

  job_file = JobFile(debug=options.debug)
  job_file.Open(options.source)

  print(u'Windows Task Scheduler Job information:')

  job_file.Close()

  return True


if __name__ == '__main__':
  if not Main():
    sys.exit(1)
  else:
    sys.exit(0)
