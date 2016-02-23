#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Script to parse Windows Enhanced Metafile (EMF) files."""

from __future__ import print_function
import argparse
import logging
import os
import sys
import uuid

import construct

import hexdump


class EMFFile(object):
  """Class that contains a .emf file."""

  _EMF_SIGNATURE = b'FME\x20'

  _EMF_FILE_HEADER = construct.Struct(
      u'emf_file_header',
      construct.ULInt32(u'record_type'),
      construct.ULInt32(u'record_size'),
      construct.Bytes(u'bounds_rectangle', 16),
      construct.Bytes(u'frame_rectangle', 16),
      construct.ULInt32(u'signature'),
      construct.ULInt32(u'format_version'),
      construct.ULInt32(u'file_size'),
      construct.ULInt32(u'number_of_records'),
      construct.ULInt16(u'number_of_handles'),
      construct.ULInt16(u'unknown1'),
      construct.ULInt32(u'description_string_size'),
      construct.ULInt32(u'description_string_offset'),
      construct.ULInt32(u'number_of_palette_entries'),
      construct.Bytes(u'reference_device_resolution_pixels', 8),
      construct.Bytes(u'reference_device_resolution_millimeters', 8),
      construct.ULInt32(u'pixel_format_descriptor_size'),
      construct.ULInt32(u'pixel_format_descriptor_offset'),
      construct.ULInt32(u'has_opengl'),
      construct.Bytes(u'reference_device_resolution_micrometers', 8))

  def __init__(self, debug=False):
    """Initializes the .emf file object.

    Args:
      debug: optional boolean value to indicate if debug information should
             be printed.
    """
    super(EMFFile, self).__init__()
    self._debug = debug
    self._file_object = None
    self._file_object_opened_in_object = False
    self._file_size = 0

  def _ReadFileHeader(self):
    """Reads the file header.

    Raises:
      IOError: if the file header cannot be read.
    """
    if self._debug:
      print(u'Seeking file header offset: 0x{0:08x}'.format(0))

    self._file_object.seek(0, os.SEEK_SET)

    file_header_data = self._file_object.read(
        self._EMF_FILE_HEADER.sizeof())

    if self._debug:
      print(u'File header data:')
      print(hexdump.Hexdump(file_header_data))

    try:
      emf_file_header_struct = self._EMF_FILE_HEADER.parse(file_header_data)
    except construct.FieldError as exception:
      raise IOError((
          u'Unable to parse file header with error: {0:s}').format(exception))

    if self._debug:
      print(u'Record type\t\t\t\t\t\t\t: 0x{0:04x}'.format(
          emf_file_header_struct.record_type))
      print(u'Record size\t\t\t\t\t\t\t: {0:d}'.format(
          emf_file_header_struct.record_size))

      print(u'Signature\t\t\t\t\t\t\t: 0x{0:04x}'.format(
          emf_file_header_struct.signature))
      print(u'Signature\t\t\t\t\t\t\t: 0x{0:04x}'.format(
          emf_file_header_struct.format_version))
      print(u'File size\t\t\t\t\t\t\t: {0:d}'.format(
          emf_file_header_struct.file_size))
      print(u'Number of records\t\t\t\t\t\t: {0:d}'.format(
          emf_file_header_struct.number_of_records))
      print(u'Number of handles\t\t\t\t\t\t: {0:d}'.format(
          emf_file_header_struct.number_of_handles))
      print(u'Unknown (reserved)\t\t\t\t\t\t: 0x{0:04x}'.format(
          emf_file_header_struct.unknown1))
      print(u'Description string size\t\t\t\t\t\t: {0:d}'.format(
          emf_file_header_struct.description_string_size))
      print(u'Description string offset\t\t\t\t\t: 0x{0:04x}'.format(
          emf_file_header_struct.description_string_offset))

      print(u'')

    # TODO: check record type
    # TODO: check record size
    # TODO: check signature

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

    self._ReadFileHeader()

    # TODO: read records


class StdoutWriter(object):
  """Class that defines a stdout output writer."""

  def Close(self):
    """Closes the output writer object."""
    return

  def Open(self):
    """Opens the output writer object.

    Returns:
      A boolean containing True if successful or False if not.
    """
    return True

  def WriteText(self, text):
    """Writes text to stdout.

    Args:
      text: the text to write.
    """
    print(text)


def Main():
  """The main program function.

  Returns:
    A boolean containing True if successful or False if not.
  """
  argument_parser = argparse.ArgumentParser(description=(
      u'Extracts information from Windows Enhanced Metafile files.'))

  argument_parser.add_argument(
      u'-d', u'--debug', dest=u'debug', action=u'store_true', default=False,
      help=u'enable debug output.')

  argument_parser.add_argument(
      u'source', nargs=u'?', action=u'store', metavar=u'PATH',
      default=None, help=u'path of the Windows Enhanced Metafile file.')

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

  emf_file = EMFFile(debug=options.debug)
  emf_file.Open(options.source)

  output_writer.WriteText(u'Windows Enhanced Metafile information:')

  emf_file.Close()

  output_writer.Close()

  return True


if __name__ == '__main__':
  if not Main():
    sys.exit(1)
  else:
    sys.exit(0)
