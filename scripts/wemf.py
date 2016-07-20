#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Script to parse Windows (Enhanced) Metafile Format (WMF and EMF) files."""

from __future__ import print_function
import argparse
import logging
import os
import sys

import construct

import hexdump


class Record(object):
  """Class that contains an EMF or WMF record.

  Attributes:
    data_offset (int): record data offset.
    data_size (int): record data size.
    record_type (int): record type.
    size (int): record size.
  """

  def __init__(self, record_type, size, data_offset, data_size):
    """Initializes an EMF or WMF record.

    Args:
      record_type (int): record type.
      size (int): record size.
      data_offset (int): record data offset.
      data_size (int): record data size.
    """
    super(Record, self).__init__()
    self.data_offset = data_offset
    self.data_size = data_size
    self.record_type = record_type
    self.size = size


class EMFFile(object):
  """Class that contains an EMF (.emf) file."""

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

  _EMF_SETTEXTCOLOR = construct.Struct(
      u'emf_settextcolor',
      construct.ULInt32(u'color'))
  # https://msdn.microsoft.com/en-us/library/cc250420.aspx

  _EMF_SELECTOBJECT = construct.Struct(
      u'emf_selectobject',
      construct.ULInt32(u'object_identifier'))

  # Here None represents that the record has no additional data.
  _EMF_RECORD_DATA_STRUCT_TYPES = {
      0x0018: _EMF_SETTEXTCOLOR,
      0x0025: _EMF_SELECTOBJECT}

  # https://msdn.microsoft.com/en-us/library/cc231191.aspx
  _EMF_STOCK_OBJECTS = {
      0x80000000: u'WHITE_BRUSH',
      0x80000001: u'LTGRAY_BRUSH',
      0x80000002: u'GRAY_BRUSH',
      0x80000003: u'DKGRAY_BRUSH',
      0x80000004: u'BLACK_BRUSH',
      0x80000005: u'NULL_BRUSH',
      0x80000006: u'WHITE_PEN',
      0x80000007: u'BLACK_PEN',
      0x80000008: u'NULL_PEN',
      0x8000000A: u'OEM_FIXED_FONT',
      0x8000000B: u'ANSI_FIXED_FONT',
      0x8000000C: u'ANSI_VAR_FONT',
      0x8000000D: u'SYSTEM_FONT',
      0x8000000E: u'DEVICE_DEFAULT_FONT',
      0x8000000F: u'DEFAULT_PALETTE',
      0x80000010: u'SYSTEM_FIXED_FONT',
      0x80000011: u'DEFAULT_GUI_FONT',
      0x80000012: u'DC_BRUSH',
      0x80000013: u'DC_PEN'}

  def __init__(self, debug=False):
    """Initializes an EMF file.

    Args:
      debug (Optional[bool]): True if debug information should be printed.
    """
    super(EMFFile, self).__init__()
    self._debug = debug
    self._file_object = None
    self._file_object_opened_in_object = False
    self._file_size = 0

  def _ReadFileHeader(self):
    """Reads a file header.

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
      record_type_string = self._EMF_RECORD_TYPES.get(
          emf_file_header_struct.record_type, u'UNKNOWN')
      print(u'Record type\t\t\t\t\t\t\t: 0x{0:04x} ({1:s})'.format(
          emf_file_header_struct.record_type, record_type_string))
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
      file_offset (int): file offset of the record.

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
    data_size = emf_record_header_struct.record_size - record_header_data_size

    if self._debug:
      self._ReadRecordData(emf_record_header_struct.record_type, data_size)

    return Record(
        emf_record_header_struct.record_type,
        emf_record_header_struct.record_size, data_offset, data_size)

  def _ReadRecordData(self, record_type, data_size):
    """Reads a record.

    Args:
      record_type (int): record type.
      data_size (int): size of the record data.

    Raises:
      IOError: if the record cannot be read.
    """
    record_data = self._file_object.read(data_size)

    if self._debug and data_size > 0:
      print(u'Record data:')
      print(hexdump.Hexdump(record_data))

    # TODO: use lookup dict with callback.
    struct_type = self._EMF_RECORD_DATA_STRUCT_TYPES.get(record_type, None)
    if not struct_type:
      return

    try:
      record_data_struct = struct_type.parse(record_data)
    except construct.FieldError as exception:
      raise IOError((
          u'Unable to parse record data with error: {0:s}').format(exception))

    if self._debug:
      if record_type == 0x0018:
        print(u'Color\t\t\t\t\t\t\t\t: 0x{0:04x}'.format(
            record_data_struct.color))

      elif record_type == 0x0025:
        stock_object_string = self._EMF_STOCK_OBJECTS.get(
            record_data_struct.object_identifier, None)
        if stock_object_string:
          print(u'Object identifier\t\t\t\t\t\t: 0x{0:08x} ({1:s})'.format(
              record_data_struct.object_identifier, stock_object_string))
        else:
          print(u'Object identifier\t\t\t\t\t\t: 0x{0:08x}'.format(
              record_data_struct.object_identifier))

      print(u'')

  def Close(self):
    """Closes an EMF file."""
    if self._file_object_opened_in_object:
      self._file_object.close()
    self._file_object = None

  def Open(self, filename):
    """Opens an EMF file.

    Args:
      filename (str): filename.
    """
    stat_object = os.stat(filename)
    self._file_size = stat_object.st_size

    self._file_object = open(filename, 'rb')
    self._file_object_opened_in_object = True

    self._ReadFileHeader()

    file_offset = self._file_object.tell()
    while file_offset < self._file_size:
      record = self._ReadRecord(file_offset)

      file_offset += record.size


class WMFFile(object):
  """Class that contains a WMF (.wmf) file."""

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
      0x0b23: u'META_STRETCHBLT',
      0x0b41: u'META_DIBSTRETCHBLT',
      0x0d33: u'META_SETDIBTODEV',
      0x0f43: u'META_STRETCHDIB'
  }

  _WMF_SETMAPMODE = construct.Struct(
      u'wmf_setmapmode',
      construct.ULInt16(u'map_mode'))

  _WMF_SETSTRETCHBLTMODE = construct.Struct(
      u'wmf_setstretchbltmode',
      construct.ULInt16(u'stretch_mode'))
  # TODO: documentation indicates there should be 16-bit reserved field.

  _WMF_RESTOREDC = construct.Struct(
      u'wmf_restoredc',
      construct.ULInt16(u'number_of_saved_device_context'))

  _WMF_SETWINDOWORG = construct.Struct(
      u'wmf_setwindoworg',
      construct.ULInt16(u'x_coordinate'),
      construct.ULInt16(u'y_coordinate'))

  _WMF_SETWINDOWEXT = construct.Struct(
      u'wmf_setwindowext',
      construct.ULInt16(u'x_coordinate'),
      construct.ULInt16(u'y_coordinate'))

  _WMF_DIBSTRETCHBLT = construct.Struct(
      u'wmf_dibstretchblt',
      construct.ULInt32(u'raster_operation'),
      construct.ULInt16(u'source_height'),
      construct.ULInt16(u'source_width'),
      construct.ULInt16(u'source_x_coordinate'),
      construct.ULInt16(u'source_y_coordinate'),
      construct.ULInt16(u'destination_height'),
      construct.ULInt16(u'destination_width'),
      construct.ULInt16(u'destination_x_coordinate'),
      construct.ULInt16(u'destination_y_coordinate'),
      construct.Anchor(u'device_indepent_bitmap'))

  # record_size == ((record_type >> 8) + 3)
  # DIB: https://msdn.microsoft.com/en-us/library/cc250593.aspx

  # Here None represents that the record has no additional data.
  _WMF_RECORD_DATA_STRUCT_TYPES = {
      0x0000: None,
      0x001e: None,
      0x0103: _WMF_SETMAPMODE,
      0x0107: _WMF_SETSTRETCHBLTMODE,
      0x0127: _WMF_RESTOREDC,
      0x020b: _WMF_SETWINDOWORG,
      0x020c: _WMF_SETWINDOWEXT,
      0x0b41: _WMF_DIBSTRETCHBLT}

  _WMF_MAP_MODES = {
      0x0001: u'MM_TEXT',
      0x0002: u'MM_LOMETRIC',
      0x0003: u'MM_HIMETRIC',
      0x0004: u'MM_LOENGLISH',
      0x0005: u'MM_HIENGLISH',
      0x0006: u'MM_TWIPS',
      0x0007: u'MM_ISOTROPIC',
      0x0008: u'MM_ANISOTROPIC'}

  _WMF_RASTER_OPERATION_CODES = {
      0x00: u'BLACKNESS',
      0x01: u'DPSOON',
      0x02: u'DPSONA',
      0x03: u'PSON',
      0x04: u'SDPONA',
      0x05: u'DPON',
      0x06: u'PDSXNON',
      0x07: u'PDSAON',
      0x08: u'SDPNAA',
      0x09: u'PDSXON',
      0x0a: u'DPNA',
      0x0b: u'PSDNAON',
      0x0c: u'SPNA',
      0x0d: u'PDSNAON',
      0x0e: u'PDSONON',
      0x0f: u'PN',
      0x10: u'PDSONA',
      0x11: u'NOTSRCERASE',
      0x12: u'SDPXNON',
      0x13: u'SDPAON',
      0x14: u'DPSXNON',
      0x15: u'DPSAON',
      0x16: u'PSDPSANAXX',
      0x17: u'SSPXDSXAXN',
      0x18: u'SPXPDXA',
      0x19: u'SDPSANAXN',
      0x1a: u'PDSPAOX',
      0x1b: u'SDPSXAXN',
      0x1c: u'PSDPAOX',
      0x1d: u'DSPDXAXN',
      0x1e: u'PDSOX',
      0x1f: u'PDSOAN',
      0x20: u'DPSNAA',
      0x21: u'SDPXON',
      0x22: u'DSNA',
      0x23: u'SPDNAON',
      0x24: u'SPXDSXA',
      0x25: u'PDSPANAXN',
      0x26: u'SDPSAOX',
      0x27: u'SDPSXNOX',
      0x28: u'DPSXA',
      0x29: u'PSDPSAOXXN',
      0x2a: u'DPSANA',
      0x2b: u'SSPXPDXAXN',
      0x2c: u'SPDSOAX',
      0x2d: u'PSDNOX',
      0x2e: u'PSDPXOX',
      0x2f: u'PSDNOAN',
      0x30: u'PSNA',
      0x31: u'SDPNAON',
      0x32: u'SDPSOOX',
      0x33: u'NOTSRCCOPY',
      0x34: u'SPDSAOX',
      0x35: u'SPDSXNOX',
      0x36: u'SDPOX',
      0x37: u'SDPOAN',
      0x38: u'PSDPOAX',
      0x39: u'SPDNOX',
      0x3a: u'SPDSXOX',
      0x3b: u'SPDNOAN',
      0x3c: u'PSX',
      0x3d: u'SPDSONOX',
      0x3e: u'SPDSNAOX',
      0x3f: u'PSAN',
      0x40: u'PSDNAA',
      0x41: u'DPSXON',
      0x42: u'SDXPDXA',
      0x43: u'SPDSANAXN',
      0x44: u'SRCERASE',
      0x45: u'DPSNAON',
      0x46: u'DSPDAOX',
      0x47: u'PSDPXAXN',
      0x48: u'SDPXA',
      0x49: u'PDSPDAOXXN',
      0x4a: u'DPSDOAX',
      0x4b: u'PDSNOX',
      0x4c: u'SDPANA',
      0x4d: u'SSPXDSXOXN',
      0x4e: u'PDSPXOX',
      0x4f: u'PDSNOAN',
      0x50: u'PDNA',
      0x51: u'DSPNAON',
      0x52: u'DPSDAOX',
      0x53: u'SPDSXAXN',
      0x54: u'DPSONON',
      0x55: u'DSTINVERT',
      0x56: u'DPSOX',
      0x57: u'DPSOAN',
      0x58: u'PDSPOAX',
      0x59: u'DPSNOX',
      0x5a: u'PATINVERT',
      0x5b: u'DPSDONOX',
      0x5c: u'DPSDXOX',
      0x5d: u'DPSNOAN',
      0x5e: u'DPSDNAOX',
      0x5f: u'DPAN',
      0x60: u'PDSXA',
      0x61: u'DSPDSAOXXN',
      0x62: u'DSPDOAX',
      0x63: u'SDPNOX',
      0x64: u'SDPSOAX',
      0x65: u'DSPNOX',
      0x66: u'SRCINVERT',
      0x67: u'SDPSONOX',
      0x68: u'DSPDSONOXXN',
      0x69: u'PDSXXN',
      0x6a: u'DPSAX',
      0x6b: u'PSDPSOAXXN',
      0x6c: u'SDPAX',
      0x6d: u'PDSPDOAXXN',
      0x6e: u'SDPSNOAX',
      0x6f: u'PDXNAN',
      0x70: u'PDSANA',
      0x71: u'SSDXPDXAXN',
      0x72: u'SDPSXOX',
      0x73: u'SDPNOAN',
      0x74: u'DSPDXOX',
      0x75: u'DSPNOAN',
      0x76: u'SDPSNAOX',
      0x77: u'DSAN',
      0x78: u'PDSAX',
      0x79: u'DSPDSOAXXN',
      0x7a: u'DPSDNOAX',
      0x7b: u'SDPXNAN',
      0x7c: u'SPDSNOAX',
      0x7d: u'DPSXNAN',
      0x7e: u'SPXDSXO',
      0x7f: u'DPSAAN',
      0x80: u'DPSAA',
      0x81: u'SPXDSXON',
      0x82: u'DPSXNA',
      0x83: u'SPDSNOAXN',
      0x84: u'SDPXNA',
      0x85: u'PDSPNOAXN',
      0x86: u'DSPDSOAXX',
      0x87: u'PDSAXN',
      0x88: u'SRCAND',
      0x89: u'SDPSNAOXN',
      0x8a: u'DSPNOA',
      0x8b: u'DSPDXOXN',
      0x8c: u'SDPNOA',
      0x8d: u'SDPSXOXN',
      0x8e: u'SSDXPDXAX',
      0x8f: u'PDSANAN',
      0x90: u'PDSXNA',
      0x91: u'SDPSNOAXN',
      0x92: u'DPSDPOAXX',
      0x93: u'SPDAXN',
      0x94: u'PSDPSOAXX',
      0x95: u'DPSAXN',
      0x96: u'DPSXX',
      0x97: u'PSDPSONOXX',
      0x98: u'SDPSONOXN',
      0x99: u'DSXN',
      0x9a: u'DPSNAX',
      0x9b: u'SDPSOAXN',
      0x9c: u'SPDNAX',
      0x9d: u'DSPDOAXN',
      0x9e: u'DSPDSAOXX',
      0x9f: u'PDSXAN',
      0xa0: u'DPA',
      0xa1: u'PDSPNAOXN',
      0xa2: u'DPSNOA',
      0xa3: u'DPSDXOXN',
      0xa4: u'PDSPONOXN',
      0xa5: u'PDXN',
      0xa6: u'DSPNAX',
      0xa7: u'PDSPOAXN',
      0xa8: u'DPSOA',
      0xa9: u'DPSOXN',
      0xaa: u'D',
      0xab: u'DPSONO',
      0xac: u'SPDSXAX',
      0xad: u'DPSDAOXN',
      0xae: u'DSPNAO',
      0xaf: u'DPNO',
      0xb0: u'PDSNOA',
      0xb1: u'PDSPXOXN',
      0xb2: u'SSPXDSXOX',
      0xb3: u'SDPANAN',
      0xb4: u'PSDNAX',
      0xb5: u'DPSDOAXN',
      0xb6: u'DPSDPAOXX',
      0xb7: u'SDPXAN',
      0xb8: u'PSDPXAX',
      0xb9: u'DSPDAOXN',
      0xba: u'DPSNAO',
      0xbb: u'MERGEPAINT',
      0xbc: u'SPDSANAX',
      0xbd: u'SDXPDXAN',
      0xbe: u'DPSXO',
      0xbf: u'DPSANO',
      0xc0: u'MERGECOPY',
      0xc1: u'SPDSNAOXN',
      0xc2: u'SPDSONOXN',
      0xc3: u'PSXN',
      0xc4: u'SPDNOA',
      0xc5: u'SPDSXOXN',
      0xc6: u'SDPNAX',
      0xc7: u'PSDPOAXN',
      0xc8: u'SDPOA',
      0xc9: u'SPDOXN',
      0xca: u'DPSDXAX',
      0xcb: u'SPDSAOXN',
      0xcc: u'SRCCOPY',
      0xcd: u'SDPONO',
      0xce: u'SDPNAO',
      0xcf: u'SPNO',
      0xd0: u'PSDNOA',
      0xd1: u'PSDPXOXN',
      0xd2: u'PDSNAX',
      0xd3: u'SPDSOAXN',
      0xd4: u'SSPXPDXAX',
      0xd5: u'DPSANAN',
      0xd6: u'PSDPSAOXX',
      0xd7: u'DPSXAN',
      0xd8: u'PDSPXAX',
      0xd9: u'SDPSAOXN',
      0xda: u'DPSDANAX',
      0xdb: u'SPXDSXAN',
      0xdc: u'SPDNAO',
      0xdd: u'SDNO',
      0xde: u'SDPXO',
      0xdf: u'SDPANO',
      0xe0: u'PDSOA',
      0xe1: u'PDSOXN',
      0xe2: u'DSPDXAX',
      0xe3: u'PSDPAOXN',
      0xe4: u'SDPSXAX',
      0xe5: u'PDSPAOXN',
      0xe6: u'SDPSANAX',
      0xe7: u'SPXPDXAN',
      0xe8: u'SSPXDSXAX',
      0xe9: u'DSPDSANAXXN',
      0xea: u'DPSAO',
      0xeb: u'DPSXNO',
      0xec: u'SDPAO',
      0xed: u'SDPXNO',
      0xee: u'SRCPAINT',
      0xef: u'SDPNOO',
      0xf0: u'PATCOPY',
      0xf1: u'PDSONO',
      0xf2: u'PDSNAO',
      0xf3: u'PSNO',
      0xf4: u'PSDNAO',
      0xf5: u'PDNO',
      0xf6: u'PDSXO',
      0xf7: u'PDSANO',
      0xf8: u'PDSAO',
      0xf9: u'PDSXNO',
      0xfa: u'DPO',
      0xfb: u'PATPAINT',
      0xfc: u'PSO',
      0xfd: u'PSDNOO',
      0xfe: u'DPSOO',
      0xff: u'WHITENESS'}

  # https://msdn.microsoft.com/en-us/library/windows/desktop/
  # dd183370(v=vs.85).aspx
  _WMF_RASTER_OPERATIONS = {
      0x00000042: u'BLACKNES',
      0x00010289: u'DPSOO',
      0x00020C89: u'DPSON',
      0x000300AA: u'PSO',
      0x00040C88: u'SDPON',
      0x000500A9: u'DPO',
      0x00060865: u'PDSXNO',
      0x000702C5: u'PDSAO',
      0x00080F08: u'SDPNA',
      0x00090245: u'PDSXO',
      0x000A0329: u'DPN',
      0x000B0B2A: u'PSDNAO',
      0x000C0324: u'SPN',
      0x000D0B25: u'PDSNAO',
      0x000E08A5: u'PDSONO',
      0x000F0001: u'P',
      0x00100C85: u'PDSON',
      0x001100A6: u'NOTSRCERAS',
      0x00120868: u'SDPXNO',
      0x001302C8: u'SDPAO',
      0x00140869: u'DPSXNO',
      0x001502C9: u'DPSAO',
      0x00165CCA: u'PSDPSANAX',
      0x00171D54: u'SSPXDSXAX',
      0x00180D59: u'SPXPDX',
      0x00191CC8: u'SDPSANAX',
      0x001A06C5: u'PDSPAO',
      0x001B0768: u'SDPSXAX',
      0x001C06CA: u'PSDPAO',
      0x001D0766: u'DSPDXAX',
      0x001E01A5: u'PDSO',
      0x001F0385: u'PDSOA',
      0x00200F09: u'DPSNA',
      0x00210248: u'SDPXO',
      0x00220326: u'DSN',
      0x00230B24: u'SPDNAO',
      0x00240D55: u'SPXDSX',
      0x00251CC5: u'PDSPANAX',
      0x002606C8: u'SDPSAO',
      0x00271868: u'SDPSXNOX',
      0x00280369: u'DPSXA',
      0x002916CA: u'PSDPSAOXXN',
      0x002A0CC9: u'DPSANA',
      0x002B1D58: u'SSPXPDXAXN',
      0x002C0784: u'SPDSOAX',
      0x002D060A: u'PSDNOX',
      0x002E064A: u'PSDPXOX',
      0x002F0E2A: u'PSDNOAN',
      0x0030032A: u'PSNA',
      0x00310B28: u'SDPNAON',
      0x00320688: u'SDPSOOX',
      0x00330008: u'NOTSRCCOPY',
      0x003406C4: u'SPDSAOX',
      0x00351864: u'SPDSXNOX',
      0x003601A8: u'SDPOX',
      0x00370388: u'SDPOAN',
      0x0038078A: u'PSDPOAX',
      0x00390604: u'SPDNOX',
      0x003A0644: u'SPDSXOX',
      0x003B0E24: u'SPDNOAN',
      0x003C004A: u'PSX',
      0x003D18A4: u'SPDSONOX',
      0x003E1B24: u'SPDSNAOX',
      0x003F00EA: u'PSAN',
      0x00400F0A: u'PSDNAA',
      0x00410249: u'DPSXON',
      0x00420D5D: u'SDXPDXA',
      0x00431CC4: u'SPDSANAXN',
      0x00440328: u'SRCERASE',
      0x00450B29: u'DPSNAON',
      0x004606C6: u'DSPDAOX',
      0x0047076A: u'PSDPXAXN',
      0x00480368: u'SDPXA',
      0x004916C5: u'PDSPDAOXXN',
      0x004A0789: u'DPSDOAX',
      0x004B0605: u'PDSNOX',
      0x004C0CC8: u'SDPANA',
      0x004D1954: u'SSPXDSXOXN',
      0x004E0645: u'PDSPXOX',
      0x004F0E25: u'PDSNOAN',
      0x00500325: u'PDNA',
      0x00510B26: u'DSPNAON',
      0x005206C9: u'DPSDAOX',
      0x00530764: u'SPDSXAXN',
      0x005408A9: u'DPSONON',
      0x00550009: u'DSTINVERT',
      0x005601A9: u'DPSOX',
      0x000570389: u'DPSOAN',
      0x00580785: u'PDSPOAX',
      0x00590609: u'DPSNOX',
      0x005A0049: u'PATINVERT',
      0x005B18A9: u'DPSDONOX',
      0x005C0649: u'DPSDXOX',
      0x005D0E29: u'DPSNOAN',
      0x005E1B29: u'DPSDNAOX',
      0x005F00E9: u'DPAN',
      0x00600365: u'PDSXA',
      0x006116C6: u'DSPDSAOXXN',
      0x00620786: u'DSPDOAX',
      0x00630608: u'SDPNOX',
      0x00640788: u'SDPSOAX',
      0x00650606: u'DSPNOX',
      0x00660046: u'SRCINVERT',
      0x006718A8: u'SDPSONOX',
      0x006858A6: u'DSPDSONOXXN',
      0x00690145: u'PDSXXN',
      0x006A01E9: u'DPSAX',
      0x006B178A: u'PSDPSOAXXN',
      0x006C01E8: u'SDPAX',
      0x006D1785: u'PDSPDOAXXN',
      0x006E1E28: u'SDPSNOAX',
      0x006F0C65: u'PDXNAN',
      0x00700CC5: u'PDSANA',
      0x00711D5C: u'SSDXPDXAXN',
      0x00720648: u'SDPSXOX',
      0x00730E28: u'SDPNOAN',
      0x00740646: u'DSPDXOX',
      0x00750E26: u'DSPNOAN',
      0x00761B28: u'SDPSNAOX',
      0x007700E6: u'DSAN',
      0x007801E5: u'PDSAX',
      0x00791786: u'DSPDSOAXXN',
      0x007A1E29: u'DPSDNOAX',
      0x007B0C68: u'SDPXNAN',
      0x007C1E24: u'SPDSNOAX',
      0x007D0C69: u'DPSXNAN',
      0x007E0955: u'SPXDSXO',
      0x007F03C9: u'DPSAAN',
      0x008003E9: u'DPSAA',
      0x00810975: u'SPXDSXON',
      0x00820C49: u'DPSXNA',
      0x00831E04: u'SPDSNOAXN',
      0x00840C48: u'SDPXNA',
      0x00851E05: u'PDSPNOAXN',
      0x008617A6: u'DSPDSOAXX',
      0x008701C5: u'PDSAXN',
      0x008800C6: u'SRCAND',
      0x00891B08: u'SDPSNAOXN',
      0x008A0E06: u'DSPNOA',
      0x008B0666: u'DSPDXOXN',
      0x008C0E08: u'SDPNOA',
      0x008D0668: u'SDPSXOXN',
      0x008E1D7C: u'SSDXPDXAX',
      0x008F0CE5: u'PDSANAN',
      0x00900C45: u'PDSXNA',
      0x00911E08: u'SDPSNOAXN',
      0x009217A9: u'DPSDPOAXX',
      0x009301C4: u'SPDAXN',
      0x009417AA: u'PSDPSOAXX',
      0x009501C9: u'DPSAXN',
      0x00960169: u'DPSXX',
      0x0097588A: u'PSDPSONOXX',
      0x00981888: u'SDPSONOXN',
      0x00990066: u'DSXN',
      0x009A0709: u'DPSNAX',
      0x009B07A8: u'SDPSOAXN',
      0x009C0704: u'SPDNAX',
      0x009D07A6: u'DSPDOAXN',
      0x009E16E6: u'DSPDSAOXX',
      0x009F0345: u'PDSXAN',
      0x00A000C9: u'DPA',
      0x00A11B05: u'PDSPNAOXN',
      0x00A20E09: u'DPSNOA',
      0x00A30669: u'DPSDXOXN',
      0x00A41885: u'PDSPONOXN',
      0x00A50065: u'PDXN',
      0x00A60706: u'DSPNAX',
      0x00A707A5: u'PDSPOAXN',
      0x00A803A9: u'DPSOA',
      0x00A90189: u'DPSOXN',
      0x00AA0029: u'D',
      0x00AB0889: u'DPSONO',
      0x00AC0744: u'SPDSXAX',
      0x00AD06E9: u'DPSDAOXN',
      0x00AE0B06: u'DSPNAO',
      0x00AF0229: u'DPNO',
      0x00B00E05: u'PDSNOA',
      0x00B10665: u'PDSPXOXN',
      0x00B21974: u'SSPXDSXOX',
      0x00B30CE8: u'SDPANAN',
      0x00B4070A: u'PSDNAX',
      0x00B507A9: u'DPSDOAXN',
      0x00B616E9: u'DPSDPAOXX',
      0x00B70348: u'SDPXAN',
      0x00B8074A: u'PSDPXAX',
      0x00B906E6: u'DSPDAOXN',
      0x00BA0B09: u'DPSNAO',
      0x00BB0226: u'MERGEPAINT',
      0x00BC1CE4: u'SPDSANAX',
      0x00BD0D7D: u'SDXPDXAN',
      0x00BE0269: u'DPSXO',
      0x00BF08C9: u'DPSANO',
      0x00C000CA: u'MERGECOPY',
      0x00C11B04: u'SPDSNAOXN',
      0x00C21884: u'SPDSONOXN',
      0x00C3006A: u'PSXN',
      0x00C40E04: u'SPDNOA',
      0x00C50664: u'SPDSXOXN',
      0x00C60708: u'SDPNAX',
      0x00C707AA: u'PSDPOAXN',
      0x00C803A8: u'SDPOA',
      0x00C90184: u'SPDOXN',
      0x00CA0749: u'DPSDXAX',
      0x00CB06E4: u'SPDSAOXN',
      0x00CC0020: u'SRCCOPY',
      0x00CD0888: u'SDPONO',
      0x00CE0B08: u'SDPNAO',
      0x00CF0224: u'SPNO',
      0x00D00E0A: u'PSDNOA',
      0x00D1066A: u'PSDPXOXN',
      0x00D20705: u'PDSNAX',
      0x00D307A4: u'SPDSOAXN',
      0x00D41D78: u'SSPXPDXAX',
      0x00D50CE9: u'DPSANAN',
      0x00D616EA: u'PSDPSAOXX',
      0x00D70349: u'DPSXAN',
      0x00D80745: u'PDSPXAX',
      0x00D906E8: u'SDPSAOXN',
      0x00DA1CE9: u'DPSDANAX',
      0x00DB0D75: u'SPXDSXAN',
      0x00DC0B04: u'SPDNAO',
      0x00DD0228: u'SDNO',
      0x00DE0268: u'SDPXO',
      0x00DF08C8: u'SDPANO',
      0x00E003A5: u'PDSOA',
      0x00E10185: u'PDSOXN',
      0x00E20746: u'DSPDXAX',
      0x00E306EA: u'PSDPAOXN',
      0x00E40748: u'SDPSXAX',
      0x00E506E5: u'PDSPAOXN',
      0x00E61CE8: u'SDPSANAX',
      0x00E70D79: u'SPXPDXAN',
      0x00E81D74: u'SSPXDSXAX',
      0x00E95CE6: u'DSPDSANAXXN',
      0x00EA02E9: u'DPSAO',
      0x00EB0849: u'DPSXNO',
      0x00EC02E8: u'SDPAO',
      0x00ED0848: u'SDPXNO',
      0x00EE0086: u'SRCPAINT',
      0x00EF0A08: u'SDPNOO',
      0x00F00021: u'PATCOPY',
      0x00F10885: u'PDSONO',
      0x00F20B05: u'PDSNAO',
      0x00F3022A: u'PSNO',
      0x00F40B0A: u'PSDNAO',
      0x00F50225: u'PDNO',
      0x00F60265: u'PDSXO',
      0x00F708C5: u'PDSANO',
      0x00F802E5: u'PDSAO',
      0x00F90845: u'PDSXNO',
      0x00FA0089: u'DPO',
      0x00FB0A09: u'PATPAINT',
      0x00FC008A: u'PSO',
      0x00FD0A0A: u'PSDNOO',
      0x00FE02A9: u'DPSOO',
      0x00FF0062: u'WHITENESS'}

  _WMF_STRETCH_MODES = {
      0x0001: u'BLACKONWHITE',
      0x0002: u'WHITEONBLACK',
      0x0003: u'COLORONCOLOR',
      0x0004: u'HALFTONE'}

  def __init__(self, debug=False):
    """Initializes an WMF file.

    Args:
      debug (Optional[bool]): True if debug information should be printed.
    """
    super(WMFFile, self).__init__()
    self._debug = debug
    self._file_object = None
    self._file_object_opened_in_object = False
    self._file_size = 0

  def _ReadFileHeader(self):
    """Reads a file header.

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

    if self._debug:
      self._ReadRecordData(wmf_record_header_struct.record_type, data_size)

    return Record(
        wmf_record_header_struct.record_type,
        record_size, data_offset, data_size)

  def _ReadRecordData(self, record_type, data_size):
    """Reads a record.

    Args:
      record_type (int): record type.
      data_size (int): size of the record data.

    Raises:
      IOError: if the record cannot be read.
    """
    record_data = self._file_object.read(data_size)

    if self._debug and data_size > 0:
      print(u'Record data:')
      print(hexdump.Hexdump(record_data))

    # TODO: use lookup dict with callback.
    struct_type = self._WMF_RECORD_DATA_STRUCT_TYPES.get(record_type, None)
    if not struct_type:
      return

    try:
      record_data_struct = struct_type.parse(record_data)
    except construct.FieldError as exception:
      raise IOError((
          u'Unable to parse record data with error: {0:s}').format(exception))

    if self._debug:
      if record_type == 0x0103:
        map_mode_string = self._WMF_MAP_MODES.get(
            record_data_struct.map_mode, u'UNKNOWN')
        print(u'Map mode\t\t\t\t\t\t\t: 0x{0:04x} ({1:s})'.format(
            record_data_struct.map_mode, map_mode_string))

      elif record_type == 0x0107:
        stretch_mode_string = self._WMF_STRETCH_MODES.get(
            record_data_struct.stretch_mode, u'UNKNOWN')
        print(u'Stretch mode\t\t\t\t\t\t\t: 0x{0:04x} ({1:s})'.format(
            record_data_struct.stretch_mode, stretch_mode_string))

      elif record_type == 0x0127:
        print(u'Number of saved device context\t\t\t\t\t: {0:d}'.format(
            record_data_struct.number_of_saved_device_context))

      elif record_type in (0x020b, 0x020c):
        print(u'X coordinate\t\t\t\t\t\t\t: {0:d}'.format(
            record_data_struct.x_coordinate))
        print(u'Y coordinate\t\t\t\t\t\t\t: {0:d}'.format(
            record_data_struct.y_coordinate))

      elif record_type == 0x0b41:
        raster_operation_string = self._WMF_RASTER_OPERATIONS.get(
            record_data_struct.raster_operation, u'UNKNOWN')
        print(u'Raster operation\t\t\t\t\t\t: 0x{0:08x} ({1:s})'.format(
            record_data_struct.raster_operation, raster_operation_string))

        print(u'Source height\t\t\t\t\t\t\t: {0:d}'.format(
            record_data_struct.source_height))
        print(u'Source width\t\t\t\t\t\t\t: {0:d}'.format(
            record_data_struct.source_width))
        print(u'Source X coordinate\t\t\t\t\t\t: {0:d}'.format(
            record_data_struct.source_x_coordinate))
        print(u'Source Y coordinate\t\t\t\t\t\t: {0:d}'.format(
            record_data_struct.source_y_coordinate))

        print(u'Destination height\t\t\t\t\t\t: {0:d}'.format(
            record_data_struct.destination_height))
        print(u'Destination width\t\t\t\t\t\t: {0:d}'.format(
            record_data_struct.destination_width))
        print(u'Destination X coordinate\t\t\t\t\t: {0:d}'.format(
            record_data_struct.destination_x_coordinate))
        print(u'Destination Y coordinate\t\t\t\t\t: {0:d}'.format(
            record_data_struct.destination_y_coordinate))

      print(u'')

  def Close(self):
    """Closes an WMF file."""
    if self._file_object_opened_in_object:
      self._file_object.close()
    self._file_object = None

  def Open(self, filename):
    """Opens an WMF file.

    Args:
      filename (str): filename.
    """
    stat_object = os.stat(filename)
    self._file_size = stat_object.st_size

    self._file_object = open(filename, 'rb')
    self._file_object_opened_in_object = True

    self._ReadFileHeader()

    file_offset = self._file_object.tell()
    while file_offset < self._file_size:
      record = self._ReadRecord(file_offset)

      file_offset += record.size


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
