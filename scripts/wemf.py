#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Script to parse Windows (Enhanced) Metafile Format (WMF and EMF) files."""

from __future__ import print_function
import argparse
import logging
import os
import sys
import uuid

import construct

import hexdump


class Record(object):
  """Class that contains a record.

  Attributes:
    data_offset: an integer containing the record data offset.
    data_size: an integer containing the record data size.
    size: an integer containing the record size.
    type: an integer containing the record type.
  """

  def __init__(self, type, size, data_offset, data_size):
    """Initializes the record object.

    Args:
      type: an integer containing the record type.
      size: an integer containing the record size.
      data_offset: an integer containing the record data offset.
      data_size: an integer containing the record data size.
    """
    super(Record, self).__init__()
    self.data_offset = data_offset
    self.data_size = data_size
    self.size = size
    self.type = type


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

  _EMF_RECORD_HEADER = construct.Struct(
      u'emf_record_header',
      construct.ULInt32(u'record_type'),
      construct.ULInt32(u'record_size'))

  _EMF_RECORD_TYPES = {
      1: u'EMR_HEADER',
      2: u'EMR_POLYBEZIER',
      3: u'EMR_POLYGON',
      4: u'EMR_POLYLINE',
      5: u'EMR_POLYBEZIERTO',
      6: u'EMR_POLYLINETO',
      7: u'EMR_POLYPOLYLINE',
      8: u'EMR_POLYPOLYGON',
      9: u'EMR_SETWINDOWEXTEX',
      10: u'EMR_SETWINDOWORGEX',
      11: u'EMR_SETVIEWPORTEXTEX',
      12: u'EMR_SETVIEWPORTORGEX',
      13: u'EMR_SETBRUSHORGEX',
      14: u'EMR_EOF',
      15: u'EMR_SETPIXELV',
      16: u'EMR_SETMAPPERFLAGS',
      17: u'EMR_SETMAPMODE',
      18: u'EMR_SETBKMODE',
      19: u'EMR_SETPOLYFILLMODE',
      20: u'EMR_SETROP2',
      21: u'EMR_SETSTRETCHBLTMODE',
      22: u'EMR_SETTEXTALIGN',
      23: u'EMR_SETCOLORADJUSTMENT',
      24: u'EMR_SETTEXTCOLOR',
      25: u'EMR_SETBKCOLOR',
      26: u'EMR_OFFSETCLIPRGN',
      27: u'EMR_MOVETOEX',
      28: u'EMR_SETMETARGN',
      29: u'EMR_EXCLUDECLIPRECT',
      30: u'EMR_INTERSECTCLIPRECT',
      31: u'EMR_SCALEVIEWPORTEXTEX',
      32: u'EMR_SCALEWINDOWEXTEX',
      33: u'EMR_SAVEDC',
      34: u'EMR_RESTOREDC',
      35: u'EMR_SETWORLDTRANSFORM',
      36: u'EMR_MODIFYWORLDTRANSFORM',
      37: u'EMR_SELECTOBJECT',
      38: u'EMR_CREATEPEN',
      39: u'EMR_CREATEBRUSHINDIRECT',
      40: u'EMR_DELETEOBJECT',
      41: u'EMR_ANGLEARC',
      42: u'EMR_ELLIPSE',
      43: u'EMR_RECTANGLE',
      44: u'EMR_ROUNDRECT',
      45: u'EMR_ARC',
      46: u'EMR_CHORD',
      47: u'EMR_PIE',
      48: u'EMR_SELECTPALETTE',
      49: u'EMR_CREATEPALETTE',
      50: u'EMR_SETPALETTEENTRIES',
      51: u'EMR_RESIZEPALETTE',
      52: u'EMR_REALIZEPALETTE',
      53: u'EMR_EXTFLOODFILL',
      54: u'EMR_LINETO',
      55: u'EMR_ARCTO',
      56: u'EMR_POLYDRAW',
      57: u'EMR_SETARCDIRECTION',
      58: u'EMR_SETMITERLIMIT',
      59: u'EMR_BEGINPATH',
      60: u'EMR_ENDPATH',
      61: u'EMR_CLOSEFIGURE',
      62: u'EMR_FILLPATH',
      63: u'EMR_STROKEANDFILLPATH',
      64: u'EMR_STROKEPATH',
      65: u'EMR_FLATTENPATH',
      66: u'EMR_WIDENPATH',
      67: u'EMR_SELECTCLIPPATH',
      68: u'EMR_ABORTPATH',
      70: u'EMR_GDICOMMENT',
      71: u'EMR_FILLRGN',
      72: u'EMR_FRAMERGN',
      73: u'EMR_INVERTRGN',
      74: u'EMR_PAINTRGN',
      75: u'EMR_EXTSELECTCLIPRGN',
      76: u'EMR_BITBLT',
      77: u'EMR_STRETCHBLT',
      78: u'EMR_MASKBLT',
      79: u'EMR_PLGBLT',
      80: u'EMR_SETDIBITSTODEVICE',
      81: u'EMR_STRETCHDIBITS',
      82: u'EMR_EXTCREATEFONTINDIRECTW',
      83: u'EMR_EXTTEXTOUTA',
      84: u'EMR_EXTTEXTOUTW',
      85: u'EMR_POLYBEZIER16',
      86: u'EMR_POLYGON16',
      87: u'EMR_POLYLINE16',
      88: u'EMR_POLYBEZIERTO16',
      89: u'EMR_POLYLINETO16',
      90: u'EMR_POLYPOLYLINE16',
      91: u'EMR_POLYPOLYGON16',
      92: u'EMR_POLYDRAW16',
      93: u'EMR_CREATEMONOBRUSH',
      94: u'EMR_CREATEDIBPATTERNBRUSHPT',
      95: u'EMR_EXTCREATEPEN',
      96: u'EMR_POLYTEXTOUTA',
      97: u'EMR_POLYTEXTOUTW',
      98: u'EMR_SETICMMODE',
      99: u'EMR_CREATECOLORSPACE',
      100: u'EMR_SETCOLORSPACE',
      101: u'EMR_DELETECOLORSPACE',
      102: u'EMR_GLSRECORD',
      103: u'EMR_GLSBOUNDEDRECORD',
      104: u'EMR_PIXELFORMAT'
  }

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

  def _ReadRecord(self, file_offset):
    """Reads a record.

    Args:
      file_offset: an integer containing the file offset of the record.

    Raises:
      IOError: if the record cannot be read.
    """
    if self._debug:
      print(u'Seeking record offset: 0x{0:08x}'.format(file_offset))

    self._file_object.seek(file_offset, os.SEEK_SET)

    record_header_data_size = self._EMF_RECORD_HEADER.sizeof()
    record_header_data = self._file_object.read(record_header_data_size)

    if self._debug:
      print(u'Record header data:')
      print(hexdump.Hexdump(record_header_data))

    try:
      emf_record_header_struct = self._EMF_RECORD_HEADER.parse(
          record_header_data)
    except construct.FieldError as exception:
      raise IOError((
          u'Unable to parse record header with error: {0:s}').format(exception))

    if self._debug:
      print(u'Record size\t\t\t\t\t\t\t: {0:d}'.format(
          emf_record_header_struct.record_size))

      record_type_string = self._EMF_RECORD_TYPES.get(
          emf_record_header_struct.record_type, u'UNKNOWN')
      print(u'Record type\t\t\t\t\t\t\t: 0x{0:04x} ({1:s})'.format(
          emf_record_header_struct.record_type, record_type_string))

      print(u'')

    data_offset = file_offset + record_header_data_size
    data_size = record_size - record_header_data_size

    return Record(
        emf_record_header_struct.record_type, 
        record_size, data_offset, data_size)

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

    file_offset = self._file_object.tell()
    while file_offset < self._file_size:
      record = self._ReadRecord(file_offset)

      file_offset += record.data_size


class WMFFile(object):
  """Class that contains a .wmf file."""

  _WMF_FILE_HEADER = construct.Struct(
      u'wmf_file_header',
      construct.ULInt16(u'file_type'),
      construct.ULInt16(u'record_size'),
      construct.ULInt16(u'format_version'),
      construct.ULInt32(u'file_size'),
      construct.ULInt16(u'maximum_number_of_objects'),
      construct.ULInt32(u'largest_record_size'),
      construct.ULInt16(u'number_of_records'))

  _WMF_RECORD_HEADER = construct.Struct(
      u'wmf_record_header',
      construct.ULInt32(u'record_size'),
      construct.ULInt16(u'record_type'))

  _WMF_RECORD_TYPES = {
      0x0000: u'META_EOF',
      0x001e: u'META_SAVEDC',
      0x0035: u'META_REALIZEPALETTE',
      0x0037: u'META_SETPALENTRIES',
      0x00f7: u'META_CREATEPALETTE',
      0x0102: u'META_SETBKMODE',
      0x0103: u'META_SETMAPMODE',
      0x0104: u'META_SETROP2',
      0x0105: u'META_SETRELABS',
      0x0106: u'META_SETPOLYFILLMODE',
      0x0107: u'META_SETSTRETCHBLTMODE',
      0x0108: u'META_SETTEXTCHAREXTRA',
      0x0127: u'META_RESTOREDC',
      0x012a: u'META_INVERTREGION',
      0x012b: u'META_PAINTREGION',
      0x012c: u'META_SELECTCLIPREGION',
      0x012d: u'META_SELECTOBJECT',
      0x012e: u'META_SETTEXTALIGN',
      0x0139: u'META_RESIZEPALETTE',
      0x0142: u'META_DIBCREATEPATTERNBRUSH',
      0x0149: u'META_SETLAYOUT',
      0x01f0: u'META_DELETEOBJECT',
      0x01f9: u'META_CREATEPATTERNBRUSH',
      0x0201: u'META_SETBKCOLOR',
      0x0209: u'META_SETTEXTCOLOR',
      0x020a: u'META_SETTEXTJUSTIFICATION',
      0x020b: u'META_SETWINDOWORG',
      0x020c: u'META_SETWINDOWEXT',
      0x020d: u'META_SETVIEWPORTORG',
      0x020e: u'META_SETVIEWPORTEXT',
      0x020f: u'META_OFFSETWINDOWORG',
      0x0211: u'META_OFFSETVIEWPORTORG',
      0x0213: u'META_LINETO',
      0x0214: u'META_MOVETO',
      0x0220: u'META_OFFSETCLIPRGN',
      0x0228: u'META_FILLREGION',
      0x0231: u'META_SETMAPPERFLAGS',
      0x0234: u'META_SELECTPALETTE',
      0x02fa: u'META_CREATEPENINDIRECT',
      0x02fb: u'META_CREATEFONTINDIRECT',
      0x02fc: u'META_CREATEBRUSHINDIRECT',
      0x0324: u'META_POLYGON',
      0x0325: u'META_POLYLINE',
      0x0410: u'META_SCALEWINDOWEXT',
      0x0412: u'META_SCALEVIEWPORTEXT',
      0x0415: u'META_EXCLUDECLIPRECT',
      0x0416: u'META_INTERSECTCLIPRECT',
      0x0418: u'META_ELLIPSE',
      0x0419: u'META_FLOODFILL',
      0x041B: u'META_RECTANGLE',
      0x041F: u'META_SETPIXEL',
      0x0429: u'META_FRAMEREGION',
      0x0436: u'META_ANIMATEPALETTE',
      0x0521: u'META_TEXTOUT',
      0x0538: u'META_POLYPOLYGON',
      0x0548: u'META_EXTFLOODFILL',
      0x061C: u'META_ROUNDRECT',
      0x061d: u'META_PATBLT',
      0x0626: u'META_ESCAPE',
      0x06ff: u'META_CREATEREGION',
      0x0817: u'META_ARC',
      0x081a: u'META_PIE',
      0x0830: u'META_CHORD',
      0x0922: u'META_BITBLT',
      0x0940: u'META_DIBBITBLT',
      0x0a32: u'META_EXTTEXTOUT',
      0x0B23: u'META_STRETCHBLT',
      0x0b41: u'META_DIBSTRETCHBLT',
      0x0d33: u'META_SETDIBTODEV',
      0x0f43: u'META_STRETCHDIB'
  }

  def __init__(self, debug=False):
    """Initializes the .wmf file object.

    Args:
      debug: optional boolean value to indicate if debug information should
             be printed.
    """
    super(WMFFile, self).__init__()
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
        self._WMF_FILE_HEADER.sizeof())

    if self._debug:
      print(u'File header data:')
      print(hexdump.Hexdump(file_header_data))

    try:
      wmf_file_header_struct = self._WMF_FILE_HEADER.parse(file_header_data)
    except construct.FieldError as exception:
      raise IOError((
          u'Unable to parse file header with error: {0:s}').format(exception))

    if self._debug:
      print(u'File type\t\t\t\t\t\t\t: 0x{0:04x}'.format(
          wmf_file_header_struct.file_type))
      print(u'Record size\t\t\t\t\t\t\t: {0:d}'.format(
          wmf_file_header_struct.record_size))

      print(u'Format version\t\t\t\t\t\t\t: {0:d}'.format(
          wmf_file_header_struct.format_version))
      print(u'File size\t\t\t\t\t\t\t: {0:d}'.format(
          wmf_file_header_struct.file_size))
      print(u'Maximum number of object\t\t\t\t\t: {0:d}'.format(
          wmf_file_header_struct.maximum_number_of_objects))
      print(u'Largest record size\t\t\t\t\t\t: {0:d}'.format(
          wmf_file_header_struct.largest_record_size))
      print(u'Number of records\t\t\t\t\t\t: {0:d}'.format(
          wmf_file_header_struct.number_of_records))

      print(u'')

    if wmf_file_header_struct.file_type not in (1, 2):
      raise IOError(u'Unsupported file type: {0:d}'.format(
          wmf_file_header_struct.file_type))

    if wmf_file_header_struct.record_size != 9:
      raise IOError(u'Unsupported record size: {0:d}'.format(
          wmf_file_header_struct.record_size))

  def _ReadRecord(self, file_offset):
    """Reads a record.

    Args:
      file_offset: an integer containing the file offset of the record.

    Raises:
      IOError: if the record cannot be read.
    """
    if self._debug:
      print(u'Seeking record offset: 0x{0:08x}'.format(file_offset))

    self._file_object.seek(file_offset, os.SEEK_SET)

    record_header_data_size = self._WMF_RECORD_HEADER.sizeof()
    record_header_data = self._file_object.read(record_header_data_size)

    if self._debug:
      print(u'Record header data:')
      print(hexdump.Hexdump(record_header_data))

    try:
      wmf_record_header_struct = self._WMF_RECORD_HEADER.parse(
          record_header_data)
    except construct.FieldError as exception:
      raise IOError((
          u'Unable to parse record header with error: {0:s}').format(exception))

    record_size = wmf_record_header_struct.record_size * 2

    if self._debug:
      print(u'Record size\t\t\t\t\t\t\t: {0:d} ({1:d})'.format(
          wmf_record_header_struct.record_size, record_size))

      record_type_string = self._WMF_RECORD_TYPES.get(
          wmf_record_header_struct.record_type, u'UNKNOWN')
      print(u'Record type\t\t\t\t\t\t\t: 0x{0:04x} ({1:s})'.format(
          wmf_record_header_struct.record_type, record_type_string))

      print(u'')

    data_offset = file_offset + record_header_data_size
    data_size = record_size - record_header_data_size

    return Record(
        wmf_record_header_struct.record_type, 
        record_size, data_offset, data_size)

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

    file_offset = self._file_object.tell()
    while file_offset < self._file_size:
      record = self._ReadRecord(file_offset)

      file_offset += record.data_size


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
      u'Extracts information from Windows (Enhanced) Metafile files.'))

  argument_parser.add_argument(
      u'-d', u'--debug', dest=u'debug', action=u'store_true', default=False,
      help=u'enable debug output.')

  argument_parser.add_argument(
      u'source', nargs=u'?', action=u'store', metavar=u'PATH',
      default=None, help=u'path of the Windows (Enhanced) Metafile file.')

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

  try:
    wmf_file = WMFFile(debug=options.debug)
    wmf_file.Open(options.source)
  except IOError:
    wmf_file = None

  if wmf_file:
    output_writer.WriteText(u'Windows Metafile information:')
    wmf_file.Close()

  else:
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
