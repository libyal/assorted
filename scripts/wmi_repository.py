#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Script to parse WMI Common Information Model (CIM) repository files."""

from __future__ import print_function
import argparse
import datetime
import glob
import logging
import os
import sys

import construct

from dtfabric import errors as dtfabric_errors
from dtfabric import fabric as dtfabric_fabric
from dtfabric import runtime as dtfabric_runtime

import hexdump


def FromFiletime(filetime):
  """Converts a FILETIME timestamp into a Python datetime object.

  The FILETIME is mainly used in Windows file formats and NTFS.

  The FILETIME is a 64-bit value containing 100th nano seconds since
  1601-01-01 00:00:00

  Technically FILETIME consists of 2 x 32-bit parts and is presumed
  to be unsigned.

  Args:
    filetime (int): 64-bit FILETIME timestamp.

  Returns:
    datetime.datetime: date and time or None.
  """
  if filetime < 0:
    return None
  timestamp, _ = divmod(filetime, 10)

  return datetime.datetime(1601, 1, 1) + datetime.timedelta(
      microseconds=timestamp)


class ParseError(Exception):
  """Error that is raised when data cannot be parsed."""


class BinaryDataFormat(object):
  """Binary data format."""

  def __init__(self, debug=False):
    """Initializes a binary data format.

    Args:
      debug (Optional[bool]): True if debug information should be printed.
    """
    super(BinaryDataFormat, self).__init__()
    self._debug = debug

  def _DebugPrintData(self, description, data):
    """Prints data debug information.

    Args:
      description (str): description.
      data (bytes): data.
    """
    print(u'{0:s}:'.format(description))
    print(hexdump.Hexdump(data))

  def _DebugPrintValue(self, description, value):
    """Prints a value debug information.

    Args:
      description (str): description.
      value (object): value.
    """
    alignment = 8 - (len(description) / 8) + 1
    text = u'{0:s}{1:s}: {2!s}'.format(description, u'\t' * alignment, value)
    print(text)

  def _ReadStructure(
      self, file_object, file_offset, data_size, data_type_map, description):
    """Reads a structure.

    Args:
      file_object (file): a file-like object.
      file_offset (int): offset of the data relative from the start of
          the file-like object.
      data_size (int): data size of the structure.
      data_type_map (dtfabric.DataTypeMap): data type map of the structure.
      description (str): description of the structure.

    Returns:
      object: structure values object.

    Raises:
      ParseError: if the structure cannot be read.
    """
    file_object.seek(file_offset, os.SEEK_SET)

    if self._debug:
      print(u'Reading {0:s} at offset: 0x{1:08x}'.format(
          description, file_offset))

    try:
      data = file_object.read(data_size)
    except IOError as exception:
      raise ParseError((
          u'Unable to read {0:s} data at offset: 0x{1:08x} with error: '
          u'{2:s}').format(description, file_offset, exception))

    if len(data) != data_size:
      raise ParseError((
          u'Unable to read {0:s} data at offset: 0x{1:08x} with error: '
          u'missing data').format(description, file_offset))

    if self._debug:
      data_description = u'{0:s} data'.format(description.title())
      self._DebugPrintData(data_description, data)

    try:
      return data_type_map.MapByteStream(data)
    except dtfabric_errors.MappingError as exception:
      raise ParseError((
          u'Unable to read {0:s} at offset: 0x{1:08x} with error: '
          u'{2:s}').format(description, file_offset, exception))


class IndexBinaryTreePage(BinaryDataFormat):
  """Index binary-tree page.

  Attributes:
    keys (list[str]): index binary-tree keys.
    page_type (int): page type.
    root_page_number (int): root page number.
    sub_pages (list[int]): sub page numbers.
  """

  _DATA_TYPE_FABRIC_DEFINITION = b'\n'.join([
      b'name: uint16',
      b'type: integer',
      b'attributes:',
      b'  format: unsigned',
      b'  size: 2',
      b'  units: bytes',
      b'---',
      b'name: uint32',
      b'type: integer',
      b'attributes:',
      b'  format: unsigned',
      b'  size: 4',
      b'  units: bytes',
      b'---',
      b'name: uint16le',
      b'type: integer',
      b'attributes:',
      b'  byte_order: little-endian',
      b'  format: unsigned',
      b'  size: 2',
      b'  units: bytes',
      b'---',
      b'name: uint32le',
      b'type: integer',
      b'attributes:',
      b'  byte_order: little-endian',
      b'  format: unsigned',
      b'  size: 4',
      b'  units: bytes',
      b'---',
      b'name: cim_page_header',
      b'type: structure',
      b'attributes:',
      b'  byte_order: little-endian',
      b'members:',
      b'- name: page_type',
      b'  data_type: uint32',
      b'- name: mapped_page_number',
      b'  data_type: uint32',
      b'- name: unknown1',
      b'  data_type: uint32',
      b'- name: root_page_number',
      b'  data_type: uint32',
      b'- name: number_of_keys',
      b'  data_type: uint32',
      b'---',
      b'name: cim_page_offsets',
      b'type: sequence',
      b'element_data_type: uint16le',
      b'number_of_elements: cim_page_header.number_of_keys',
      b'---',
      b'name: cim_page_subpages',
      b'type: sequence',
      b'element_data_type: uint32le',
      b'number_of_elements: cim_page_header.number_of_keys + 1',
      b'---',
      b'name: cim_page_key',
      b'type: structure',
      b'attributes:',
      b'  byte_order: little-endian',
      b'members:',
      b'- name: number_of_segments',
      b'  data_type: uint16',
      b'- name: segments',
      b'  type: sequence',
      b'  element_data_type: uint16',
      b'  number_of_elements: cim_page_key.number_of_segments',
      b'---',
      b'name: cim_offsets',
      b'type: sequence',
      b'element_data_type: uint16le',
      b'number_of_elements: number_of_offsets',
  ])

  _DATA_TYPE_FABRIC = dtfabric_fabric.DataTypeFabric(
      yaml_definition=_DATA_TYPE_FABRIC_DEFINITION)

  _UINT16LE = _DATA_TYPE_FABRIC.CreateDataTypeMap(u'uint16le')

  _UINT16LE_SIZE = _UINT16LE.GetByteSize()

  _PAGE_HEADER = _DATA_TYPE_FABRIC.CreateDataTypeMap(u'cim_page_header')

  _PAGE_HEADER_SIZE = _PAGE_HEADER.GetByteSize()

  _PAGE_KEY_OFFSETS = _DATA_TYPE_FABRIC.CreateDataTypeMap(u'cim_page_offsets')

  _PAGE_SUBPAGES = _DATA_TYPE_FABRIC.CreateDataTypeMap(u'cim_page_subpages')

  _PAGE_KEY = _DATA_TYPE_FABRIC.CreateDataTypeMap(u'cim_page_key')

  _OFFSETS = _DATA_TYPE_FABRIC.CreateDataTypeMap(u'cim_offsets')

  _PAGE_TYPES = {
      0xaccc: u'Is active',
      0xaddd: u'Is administrative',
      0xbadd: u'Is deleted',
  }

  _KEY_SEGMENT_SEPARATOR = u'\\'

  PAGE_SIZE = 8192

  def __init__(self, debug=False):
    """Initializes an index binary-tree page.

    Args:
      debug (Optional[bool]): True if debug information should be printed.
    """
    super(IndexBinaryTreePage, self).__init__(debug=debug)
    self._key_offsets = None
    self._number_of_keys = None
    self._page_key_segments = []
    self._page_values = []
    self._page_value_offsets = None

    self.keys = []
    self.page_type = None
    self.root_page_number = None
    self.sub_pages = []

  def _DebugPrintHeader(self, page_header):
    """Prints page header debug information.

    Args:
      page_header (cim_page_header): page header.
    """
    page_type_string = self._PAGE_TYPES.get(page_header.page_type, u'Unknown')
    value_string = u'0x{0:04x} ({1:s})'.format(
        page_header.page_type, page_type_string)
    self._DebugPrintValue(u'Page type', value_string)

    value_string = u'{0:d}'.format(page_header.mapped_page_number)
    self._DebugPrintValue(u'Mapped page number', value_string)

    value_string = u'0x{0:08x}'.format(page_header.unknown1)
    self._DebugPrintValue(u'Unknown1', value_string)

    value_string = u'{0:d}'.format(page_header.root_page_number)
    self._DebugPrintValue(u'Root page number', value_string)

    value_string = u'{0:d}'.format(page_header.number_of_keys)
    self._DebugPrintValue(u'Number of keys', value_string)

    print(u'')

  def _DebugPrintKeyOffsets(self, key_offsets):
    """Prints key offsets debug information.

    Args:
      key_offsets (list[int]): key offsets.
    """
    for index, key_offset in enumerate(key_offsets):
      description = u'Page key: {0:d} offset'.format(index)
      value_string = u'0x{0:04x}'.format(key_offset)
      self._DebugPrintValue(description, value_string)

    print(u'')

  def _DebugPrintPageNumber(
      self, description, page_number, unavailable_page_numbers=None):
    """Prints a page number debug information.

    Args:
      description (str): description.
      page_number (int): page number.
      unavailable_page_numbers (Optional[set[int]]): unavailable page numbers.
    """
    if not unavailable_page_numbers:
      unavailable_page_numbers = set()

    if page_number in unavailable_page_numbers:
      value_string = u'0x{0:08x} (unavailable)'.format(page_number)
    else:
      value_string = u'{0:d}'.format(page_number)

    self._DebugPrintValue(description, value_string)

  def _ReadHeader(self, file_object):
    """Reads a page header.

    Args:
      file_object (file): a file-like object.

    Returns:
      cim_page_header: page header.

    Raises:
      ParseError: if the page header cannot be read.
    """
    file_offset = file_object.tell()

    page_header = self._ReadStructure(
        file_object, file_offset, self._PAGE_HEADER_SIZE, self._PAGE_HEADER,
        u'page header')

    if self._debug:
      self._DebugPrintHeader(page_header)

    self.page_type = page_header.page_type
    self.root_page_number = page_header.root_page_number
    self._number_of_keys = page_header.number_of_keys

    return page_header

  def _ReadKeyOffsets(self, page_header, file_object):
    """Reads page key offsets.

    Args:
      page_header (cim_page_header): page header.
      file_object (file): a file-like object.

    Raises:
      ParseError: if the page key offsets cannot be read.
    """
    if page_header.number_of_keys == 0:
      return

    file_offset = file_object.tell()
    if self._debug:
      print(u'Reading page key offsets at offset: 0x{0:08x}'.format(
          file_offset))

    offsets_data_size = page_header.number_of_keys * 2
    offsets_data = file_object.read(offsets_data_size)

    if self._debug:
      self._DebugPrintData(u'Page key offsets data', offsets_data)

    context = dtfabric_runtime.DataTypeMapContext(values={
        u'cim_page_header': page_header})

    try:
      self._key_offsets = self._PAGE_KEY_OFFSETS.MapByteStream(
          offsets_data, context=context)
    except dtfabric_errors.MappingError as exception:
      raise ParseError((
          u'Unable to parse page key offsets at offset: 0x{0:08x} '
          u'with error: {1:s}').format(file_offset, exception))

    if self._debug:
      self._DebugPrintKeyOffsets(self._key_offsets)

  def _ReadKeyData(self, file_object):
    """Reads page key data.

    Args:
      file_object (file): a file-like object.

    Raises:
      ParseError: if the page key data cannot be read.
    """
    file_offset = file_object.tell()
    if self._debug:
      print(u'Reading page key data at offset: 0x{0:08x}'.format(file_offset))

    size_data = file_object.read(self._UINT16LE_SIZE)

    try:
      data_size = self._UINT16LE.MapByteStream(size_data)
    except dtfabric_errors.MappingError as exception:
      raise ParseError((
          u'Unable to parse page key data size at offset: 0x{0:08x} '
          u'with error: {1:s}').format(file_offset, exception))

    if self._debug:
      value_string = u'{0:d} ({1:d} bytes)'.format(data_size, data_size * 2)
      self._DebugPrintValue(u'Page key data size', value_string)

    if data_size == 0:
      if self._debug:
        self._DebugPrintData(u'Page key data', size_data)
      return

    key_data = file_object.read(data_size * 2)

    if self._debug:
      self._DebugPrintData(u'Page key data', b''.join([size_data, key_data]))

    for index, key_offset in enumerate(self._key_offsets):
      page_key_offset = key_offset * 2

      if self._debug:
        description = u'Page key: {0:d} offset'.format(index)
        value_string = u'{0:d} (0x{0:08x})'.format(page_key_offset)
        self._DebugPrintValue(description, value_string)

      try:
        page_key = self._PAGE_KEY.MapByteStream(key_data[page_key_offset:])
      except dtfabric_errors.MappingError as exception:
        raise ParseError(
            u'Unable to parse page key: {0:d} with error: {1:s}'.format(
                index, exception))

      page_key_size = page_key_offset + 2 + (page_key.number_of_segments * 2)

      if self._debug:
        description = u'Page key: {0:d} data:'.format(index)
        self._DebugPrintData(
            description, key_data[page_key_offset:page_key_size])

      self._page_key_segments.append(page_key.segments)

      if self._debug:
        description = u'Page key: {0:d} number of segments'.format(index)
        value_string = u'{0:d}'.format(page_key.number_of_segments)
        self._DebugPrintValue(description, value_string)

        description = u'Page key: {0:d} segments'.format(index)
        value_string = u', '.join([
            u'{0:d}'.format(segment_index)
            for segment_index in page_key.segments])
        self._DebugPrintValue(description, value_string)

        print(u'')

  def _ReadOffsetsTable(self, file_object, file_offset, description):
    """Reads an offsets table.

    Args:
      file_object (file): a file-like object.
      file_offset (int): offset of the data relative from the start of
          the file-like object.
      description (str): description of the offsets table.

    Returns:
      tuple[int, ...]: offsets number array.

    Raises:
      ParseError: if the offsets table cannot be read.
    """
    if self._debug:
      print(u'Reading {0:s} at offset: 0x{1:08x}'.format(
          description, file_offset))

    try:
      number_of_offsets_data = file_object.read(self._UINT16LE_SIZE)
    except IOError as exception:
      raise ParseError((
          u'Unable to read number of offsets data at offset: 0x{0:08x} '
          u'with error: {1:s}').format(file_offset, exception))

    if len(number_of_offsets_data) != self._UINT16LE_SIZE:
      raise ParseError((
          u'Unable to read number of offsets data at offset: 0x{0:08x} '
          u'with error: missing data').format(file_offset))

    try:
      number_of_offsets = self._UINT16LE.MapByteStream(number_of_offsets_data)
    except dtfabric_errors.MappingError as exception:
      raise ParseError((
          u'Unable to parse number of offsets at offset: 0x{0:08x} with error '
          u'error: {1:s}').format(file_offset, exception))

    if number_of_offsets == 0:
      offsets_data = b''
    else:
      offsets_data_size = number_of_offsets * self._UINT16LE_SIZE

      try:
        offsets_data = file_object.read(offsets_data_size)
      except IOError as exception:
        raise ParseError((
            u'Unable to read offsets data at offset: 0x{0:08x} with error: '
            u'{1:s}').format(file_offset, exception))

      if len(offsets_data) != offsets_data_size:
        raise ParseError((
            u'Unable to read offsets data at offset: 0x{0:08x} with error: '
            u'missing data').format(file_offset))

    if self._debug:
      data_description = u'{0:s} data'.format(description.title())
      self._DebugPrintData(data_description, b''.join([
          number_of_offsets_data, offsets_data]))

      value_string = u'{0:d}'.format(number_of_offsets)
      self._DebugPrintValue(u'Number of offsets', value_string)

    if not offsets_data:
      offsets = tuple()
    else:
      context = dtfabric_runtime.DataTypeMapContext(values={
          u'number_of_offsets': number_of_offsets})

      try:
        offsets = self._OFFSETS.MapByteStream(offsets_data, context=context)

      except dtfabric_errors.MappingError as exception:
        raise ParseError((
            u'Unable to parse offsets data at offset: 0x{0:08x} with error: '
            u'{1:s}').format(file_offset, exception))

    return offsets

  def _ReadValueOffsets(self, file_object):
    """Reads page value offsets.

    Args:
      file_object (file): a file-like object.

    Raises:
      ParseError: if the page value offsets cannot be read.
    """
    file_offset = file_object.tell()
    offset_array = self._ReadOffsetsTable(
        file_object, file_offset, u'page value offsets')

    if self._debug:
      for index, offset in enumerate(offset_array):
        description = u'Page value: {0:d} offset'.format(index)
        value_string = u'0x{0:04x}'.format(offset)
        self._DebugPrintValue(description, value_string)

      print(u'')

    self._page_value_offsets = offset_array

  def _ReadValueData(self, file_object):
    """Reads page value data.

    Args:
      file_object (file): a file-like object.

    Raises:
      ParseError: if the page value data cannot be read.
    """
    file_offset = file_object.tell()
    if self._debug:
      print(u'Reading page value data at offset: 0x{0:08x}'.format(file_offset))

    size_data = file_object.read(self._UINT16LE_SIZE)

    try:
      data_size = self._UINT16LE.MapByteStream(size_data)
    except dtfabric_errors.MappingError as exception:
      raise ParseError((
          u'Unable to parse page value data size at offset: 0x{0:08x} '
          u'with error: {1:s}').format(file_offset, exception))

    if self._debug:
      value_string = u'{0:d} bytes'.format(data_size)
      self._DebugPrintValue(u'Page value data size', value_string)

    if data_size == 0:
      self._DebugPrintData(u'Page value data', size_data)
      return

    value_data = file_object.read(data_size)

    if self._debug:
      self._DebugPrintData(u'Page value data', b''.join([
          size_data, value_data]))

    for index, page_value_offset in enumerate(self._page_value_offsets):
      # TODO: determine size

      value_string = construct.CString(u'string').parse(
          value_data[page_value_offset:])

      if self._debug:
        description = u'Page value: {0:d} data'.format(index)
        self._DebugPrintValue(description, value_string)

      self._page_values.append(value_string)

    if self._debug and self._page_value_offsets:
      print(u'')

  def _ReadSubPages(self, page_header, file_object):
    """Reads sub pages data.

    Args:
      page_header (cim_page_header): page header.
      file_object (file): a file-like object.

    Raises:
      ParseError: if the sub pages cannot be read.
    """
    file_offset = file_object.tell()
    if self._debug:
      print(u'Reading sub pages at offset: 0x{0:08x}'.format(file_offset))

    number_of_entries = self._number_of_keys + 1
    entries_data_size = number_of_entries * 4

    entries_data = file_object.read(entries_data_size)

    if self._debug:
      self._DebugPrintData(u'Sub pages array data', entries_data)

    context = dtfabric_runtime.DataTypeMapContext(values={
        u'cim_page_header': page_header})

    try:
      sub_pages_array = self._PAGE_SUBPAGES.MapByteStream(
          entries_data, context=context)

    except dtfabric_errors.MappingError as exception:
      raise ParseError((
          u'Unable to parse sub pages at offset: 0x{0:08x} '
          u'with error: {1:s}').format(file_offset, exception))

    for index, page_number in enumerate(sub_pages_array):
      if page_number not in (0, 0xffffffff):
        self.sub_pages.append(page_number)

      if self._debug:
        description = u'Sub page: {0:d} mapped page number'.format(index)
        self._DebugPrintPageNumber(
            description, page_number,
            unavailable_page_numbers=set([0, 0xffffffff]))

    if self._debug:
      print(u'')

  def ReadPage(self, file_object, file_offset):
    """Reads a page.

    Args:
      file_object (file): a file-like object.
      file_offset (int): offset of the page relative from the start of the file.

    Raises:
      ParseError: if the page cannot be read.
    """
    file_object.seek(file_offset, os.SEEK_SET)

    if self._debug:
      print(u'Reading index binary-tree page at offset: 0x{0:08x}'.format(
          file_offset))

    page_header = self._ReadHeader(file_object)

    if page_header.number_of_keys > 0:
      array_data_size = page_header.number_of_keys * 4
      array_data = file_object.read(array_data_size)

      if self._debug:
        self._DebugPrintData(u'Unknown array data', array_data)

    self._ReadSubPages(page_header, file_object)
    self._ReadKeyOffsets(page_header, file_object)
    self._ReadKeyData(file_object)
    self._ReadValueOffsets(file_object)
    self._ReadValueData(file_object)

    trailing_data_size = (
        (file_offset + self.PAGE_SIZE) - file_object.tell())
    trailing_data = file_object.read(trailing_data_size)

    if self._debug:
      self._DebugPrintData(u'Trailing data', trailing_data)

    self.keys = []
    for page_key_segments in self._page_key_segments:
      key_segments = []
      for segment_index in page_key_segments:
        key_segments.append(self._page_values[segment_index])

      key_path = u'{0:s}{1:s}'.format(
          self._KEY_SEGMENT_SEPARATOR,
          self._KEY_SEGMENT_SEPARATOR.join(key_segments))

      self.keys.append(key_path)


class IndexBinaryTreeFile(object):
  """An index binary-tree (Index.btr) file."""

  def __init__(self, index_mapping_file, debug=False):
    """Initializes an index binary-tree file.

    Args:
      index_mapping_file: an index mapping file (instance of MappingFile).
      debug (Optional[bool]): True if debug information should be printed.
    """
    super(IndexBinaryTreeFile, self).__init__()
    self._debug = debug
    self._file_object = None
    self._file_object_opened_in_object = False
    self._file_size = 0

    self._index_mapping_file = index_mapping_file
    self._first_mapped_page = None
    self._root_page = None

  def _GetPage(self, page_number):
    """Retrieves a specific page.

    Args:
      page_number (int): page number.

    Returns:
      IndexBinaryTreePage: an index binary-tree page or None.
    """
    file_offset = page_number * IndexBinaryTreePage.PAGE_SIZE
    if file_offset >= self._file_size:
      return

    # TODO: cache pages.
    return self._ReadPage(file_offset)

  def _ReadPage(self, file_offset):
    """Reads a page.

    Args:
      file_offset (int): offset of the page relative from the start of the file.

    Return:
      IndexBinaryTreePage: an index binary-tree page.
    """
    index_page = IndexBinaryTreePage(debug=self._debug)
    index_page.ReadPage(self._file_object, file_offset)
    return index_page

  def Close(self):
    """Closes the index binary-tree file."""
    if self._file_object_opened_in_object:
      self._file_object.close()
    self._file_object = None

  def GetFirstMappedPage(self):
    """Retrieves the first mapped page.

    Returns:
      IndexBinaryTreePage: an index binary-tree page or None.
    """
    if not self._first_mapped_page:
      page_number = self._index_mapping_file.mappings[0]

      index_page = self._GetPage(page_number)
      if not index_page:
        logging.warning((
            u'Unable to read first mapped index binary-tree page: '
            u'{0:d}.').format(page_number))
        return

      if index_page.page_type != 0xaddd:
        logging.warning(u'First mapped index binary-tree page type mismatch.')
        return

      self._first_mapped_page = index_page

    return self._first_mapped_page

  def GetMappedPage(self, page_number):
    """Retrieves a specific mapped page.

    Args:
      page_number (int): page number.

    Returns:
      IndexBinaryTreePage: an index binary-tree page or None.
    """
    mapped_page_number = self._index_mapping_file.mappings[page_number]

    index_page = self._GetPage(mapped_page_number)
    if not index_page:
      logging.warning(
          u'Unable to read index binary-tree mapped page: {0:d}.'.format(
              page_number))
      return

    return index_page

  def GetRootPage(self):
    """Retrieves the root page.

    Returns:
      IndexBinaryTreePage: an index binary-tree page or None.
    """
    if not self._root_page:
      first_mapped_page = self.GetFirstMappedPage()
      if not first_mapped_page:
        return

      page_number = self._index_mapping_file.mappings[
          first_mapped_page.root_page_number]

      index_page = self._GetPage(page_number)
      if not index_page:
        logging.warning(
            u'Unable to read index binary-tree root page: {0:d}.'.format(
                page_number))
        return

      self._root_page = index_page

    return self._root_page

  def Open(self, filename):
    """Opens the index binary-tree file.

    Args:
      filename (str): name of the file.
    """
    stat_object = os.stat(filename)
    self._file_size = stat_object.st_size

    self._file_object = open(filename, 'rb')
    self._file_object_opened_in_object = True

    if self._debug:
      file_offset = 0
      while file_offset < self._file_size:
        self._ReadPage(file_offset)
        file_offset += IndexBinaryTreePage.PAGE_SIZE


class MappingFile(BinaryDataFormat):
  """Mappings (*.map) file.

  Attributes:
    data_size (int): data size of the mappings file.
    mapping (list[int]): mappings to page numbers in the index binary-tree
        or objects data file.
  """

  _DATA_TYPE_FABRIC_DEFINITION = b'\n'.join([
      b'name: uint32',
      b'type: integer',
      b'attributes:',
      b'  format: unsigned',
      b'  size: 4',
      b'  units: bytes',
      b'---',
      b'name: uint32le',
      b'type: integer',
      b'attributes:',
      b'  byte_order: little-endian',
      b'  format: unsigned',
      b'  size: 4',
      b'  units: bytes',
      b'---',
      b'name: cim_map_footer',
      b'type: structure',
      b'attributes:',
      b'  byte_order: little-endian',
      b'members:',
      b'- name: signature',
      b'  data_type: uint32',
      b'---',
      b'name: cim_map_header',
      b'type: structure',
      b'attributes:',
      b'  byte_order: little-endian',
      b'members:',
      b'- name: signature',
      b'  data_type: uint32',
      b'- name: format_version',
      b'  data_type: uint32',
      b'- name: number_of_pages',
      b'  data_type: uint32',
      b'---',
      b'name: cim_map_page_numbers',
      b'type: sequence',
      b'element_data_type: uint32le',
      b'number_of_elements: number_of_entries',
  ])

  _DATA_TYPE_FABRIC = dtfabric_fabric.DataTypeFabric(
      yaml_definition=_DATA_TYPE_FABRIC_DEFINITION)

  _UINT32LE = _DATA_TYPE_FABRIC.CreateDataTypeMap(u'uint32le')

  _UINT32LE_SIZE = _UINT32LE.GetByteSize()

  _FOOTER_SIGNATURE = 0x0000dcba

  _FILE_FOOTER = _DATA_TYPE_FABRIC.CreateDataTypeMap(u'cim_map_footer')

  _FILE_FOOTER_SIZE = _FILE_FOOTER.GetByteSize()

  _HEADER_SIGNATURE = 0x0000abcd

  _FILE_HEADER = _DATA_TYPE_FABRIC.CreateDataTypeMap(u'cim_map_header')

  _FILE_HEADER_SIZE = _FILE_HEADER.GetByteSize()

  _PAGE_NUMBERS = _DATA_TYPE_FABRIC.CreateDataTypeMap(u'cim_map_page_numbers')

  def __init__(self, debug=False):
    """Initializes a mappings file.

    Args:
      debug (Optional[bool]): True if debug information should be printed.
    """
    super(MappingFile, self).__init__(debug=debug)
    self._file_object = None
    self._file_object_opened_in_object = False
    self._file_size = 0

    self.data_size = 0
    self.mappings = []

  def _DebugPrintFooter(self, file_footer):
    """Prints file footer debug information.

    Args:
      file_footer (cim_map_footer): file footer.
    """
    value_string = u'0x{0:08x}'.format(file_footer.signature)
    self._DebugPrintValue(u'Signature', value_string)

    print(u'')

  def _DebugPrintHeader(self, file_header):
    """Prints file header debug information.

    Args:
      file_header (cim_map_header): file header.
    """
    value_string = u'0x{0:08x}'.format(file_header.signature)
    self._DebugPrintValue(u'Signature', value_string)

    value_string = u'0x{0:08x}'.format(file_header.format_version)
    self._DebugPrintValue(u'Format version', value_string)

    value_string = u'{0:d}'.format(file_header.number_of_pages)
    self._DebugPrintValue(u'Signature', value_string)

    print(u'')

  def _DebugPrintPageNumber(
      self, description, page_number, unavailable_page_numbers=None):
    """Prints a page number debug information.

    Args:
      description (str): description.
      page_number (int): page number.
      unavailable_page_numbers (Optional[set[int]]): unavailable page numbers.
    """
    if not unavailable_page_numbers:
      unavailable_page_numbers = set()

    if page_number in unavailable_page_numbers:
      value_string = u'0x{0:08x} (unavailable)'.format(page_number)
    else:
      value_string = u'{0:d}'.format(page_number)

    self._DebugPrintValue(description, value_string)

  def _ReadFileFooter(self):
    """Reads the file footer.

    Raises:
      ParseError: if the file footer cannot be read.
    """
    file_offset = self._file_object.tell()

    file_footer = self._ReadStructure(
        self._file_object, file_offset, self._FILE_FOOTER_SIZE,
        self._FILE_FOOTER, u'file footer')

    if self._debug:
      self._DebugPrintFooter(file_footer)

    if file_footer.signature != self._FOOTER_SIGNATURE:
      raise ParseError(u'Unsupported file footer signature: 0x{0:08x}'.format(
          file_footer.signature))

  def _ReadFileHeader(self, file_offset=0):
    """Reads the file header.

    Args:
      file_offset (int): offset of the mappings file header relative from the
          start of the file.

    Raises:
      ParseError: if the file header cannot be read.
    """
    file_header = self._ReadStructure(
        self._file_object, file_offset, self._FILE_HEADER_SIZE,
        self._FILE_HEADER, u'file header')

    if self._debug:
      self._DebugPrintHeader(file_header)

    if file_header.signature != self._HEADER_SIGNATURE:
      raise ParseError(u'Unsupported file header signature: 0x{0:08x}'.format(
          file_header.signature))

  def _ReadMappings(self):
    """Reads the mappings.

    Raises:
      ParseError: if the mappings cannot be read.
    """
    file_offset = self._file_object.tell()
    mappings_array = self._ReadPageNumbersTable(
        self._file_object, file_offset, u'mappings')

    if self._debug:
      for index, page_number in enumerate(mappings_array):
        description = u'Mapping entry: {0:d} page number'.format(index)
        self._DebugPrintPageNumber(
            description, page_number,
            unavailable_page_numbers=set([0xffffffff]))

      print(u'')

    self.mappings = mappings_array

  def _ReadPageNumbersTable(self, file_object, file_offset, description):
    """Reads a page numbers table.

    Args:
      file_object (file): a file-like object.
      file_offset (int): offset of the data relative from the start of
          the file-like object.
      description (str): description of the page numbers table.

    Returns:
      tuple[int, ...]: page number array.

    Raises:
      ParseError: if the page numbers table cannot be read.
    """
    if self._debug:
      print(u'Reading {0:s} at offset: 0x{1:08x}'.format(
          description, file_offset))

    try:
      number_of_entries_data = file_object.read(self._UINT32LE_SIZE)
    except IOError as exception:
      raise ParseError((
          u'Unable to read number of entries data at offset: 0x{0:08x} '
          u'with error: {1:s}').format(file_offset, exception))

    if len(number_of_entries_data) != self._UINT32LE_SIZE:
      raise ParseError((
          u'Unable to read number of entries data at offset: 0x{0:08x} '
          u'with error: missing data').format(file_offset))

    try:
      number_of_entries = self._UINT32LE.MapByteStream(number_of_entries_data)
    except dtfabric_errors.MappingError as exception:
      raise ParseError((
          u'Unable to parse number of entries at offset: 0x{0:08x} with error '
          u'error: {1:s}').format(file_offset, exception))

    if number_of_entries == 0:
      entries_data = b''
    else:
      entries_data_size = number_of_entries * self._UINT32LE_SIZE

      try:
        entries_data = file_object.read(entries_data_size)
      except IOError as exception:
        raise ParseError((
            u'Unable to read entries data at offset: 0x{0:08x} with error: '
            u'{1:s}').format(file_offset, exception))

      if len(entries_data) != entries_data_size:
        raise ParseError((
            u'Unable to read entries data at offset: 0x{0:08x} with error: '
            u'missing data').format(file_offset))

    if self._debug:
      data_description = u'{0:s} data'.format(description.title())
      self._DebugPrintData(data_description, b''.join([
          number_of_entries_data, entries_data]))

      value_string = u'{0:d}'.format(number_of_entries)
      self._DebugPrintValue(u'Number of entries', value_string)

    if not entries_data:
      page_numbers = tuple()
    else:
      context = dtfabric_runtime.DataTypeMapContext(values={
          u'number_of_entries': number_of_entries})

      try:
        page_numbers = self._PAGE_NUMBERS.MapByteStream(
            entries_data, context=context)

      except dtfabric_errors.MappingError as exception:
        raise ParseError((
            u'Unable to parse entries data at offset: 0x{0:08x} with error: '
            u'{1:s}').format(file_offset, exception))

    return page_numbers

  def _ReadUnknownEntries(self):
    """Reads unknown entries.

    Raises:
      ParseError: if the unknown entries cannot be read.
    """
    file_offset = self._file_object.tell()
    unknown_entries_array = self._ReadPageNumbersTable(
        self._file_object, file_offset, u'unknown entries')

    if self._debug:
      for index, page_number in enumerate(unknown_entries_array):
        description = u'Unknown entry: {0:d} page number'.format(index)
        self._DebugPrintPageNumber(
            description, page_number,
            unavailable_page_numbers=set([0xffffffff]))

      print(u'')

  def Close(self):
    """Closes the mappings file."""
    if self._file_object_opened_in_object:
      self._file_object.close()
    self._file_object = None

  def Open(self, filename, file_offset=0):
    """Opens the mappings file.

    Args:
      filename (str): name of the file.
      file_offset (Optional[int]): offset of the mappings file relative from
          the start of the file.
    """
    stat_object = os.stat(filename)
    self._file_size = stat_object.st_size

    self._file_object = open(filename, 'rb')
    self._file_object_opened_in_object = True

    self._ReadFileHeader(file_offset=file_offset)
    self._ReadMappings()
    self._ReadUnknownEntries()
    self._ReadFileFooter()

    self.data_size = self._file_object.tell() - file_offset


class PropertyDescriptor(object):
  """A property descriptor.

  Attributes:
    definition_offset (int): offset of the property definition.
    name_offset (int): offset of the property name.
  """

  def __init__(self, name_offset, definition_offset):
    """Initializes a property descriptor.

    Args:
      name_offset (int): offset of the property name.
      definition_offset (int): offset of the property definition.
    """
    super(PropertyDescriptor, self).__init__()
    self.definition_offset = definition_offset
    self.name_offset = name_offset


class ObjectRecord(object):
  """An object record.

  Attributes:
    data_type (str): object record data type.
    data (bytes): object record data.
  """

  _CLASS_DEFINITION_OBJECT_RECORD = construct.Struct(
      u'class_definition_object_record',
      construct.ULInt32(u'super_class_name_string_size'),
      construct.Bytes(
          u'super_class_name_string',
          lambda ctx: ctx.super_class_name_string_size * 2),
      construct.ULInt64(u'date_time'),
      construct.ULInt32(u'data_size'),
      construct.Bytes(u'data', lambda ctx: ctx.data_size - 4))

  _CLASS_DEFINITION_HEADER = construct.Struct(
      u'class_definition_header',
      construct.Byte(u'unknown1'),
      construct.ULInt32(u'class_name_offset'),
      construct.ULInt32(u'default_value_size'),
      construct.ULInt32(u'super_class_name_block_size'),
      construct.Bytes(
          u'super_class_name_block_data',
          lambda ctx: ctx.super_class_name_block_size - 4),
      construct.ULInt32(u'qualifiers_block_size'),
      construct.Bytes(
          u'qualifiers_block_data',
          lambda ctx: ctx.qualifiers_block_size - 4),
      construct.ULInt32(u'number_of_property_descriptors'),
      construct.Array(
          lambda ctx: ctx.number_of_property_descriptors,
          construct.Struct(
              u'property_descriptors',
              construct.ULInt32(u'name_offset'),
              construct.ULInt32(u'data_offset'))),
      construct.Bytes(
          u'default_value_data',
          lambda ctx: ctx.default_value_size),
      construct.ULInt32(u'properties_block_size'),
      construct.Bytes(
          u'properties_block_data',
          lambda ctx: ctx.properties_block_size & 0x7ffffff))

  _CLASS_DEFINITION_METHODS = construct.Struct(
      u'class_definition_methods',
      construct.ULInt32(u'methods_block_size'),
      construct.Bytes(
          u'methods_block_data',
          lambda ctx: ctx.methods_block_size - 4))

  # TODO: add more values.

  _SUPER_CLASS_NAME_BLOCK = construct.Struct(
      u'super_class_name_block',
      construct.Byte(u'super_class_name_string_flags'),
      construct.CString(u'super_class_name_string'),
      construct.ULInt32(u'super_class_name_string_size'))

  _PROPERTY_NAME = construct.Struct(
      u'property_name',
      construct.Byte(u'string_flags'),
      construct.CString(u'string'))

  _PROPERTY_DEFINITION = construct.Struct(
      u'property_definition',
      construct.ULInt32(u'type'),
      construct.ULInt16(u'index'),
      construct.ULInt32(u'offset'),
      construct.ULInt32(u'level'),
      construct.ULInt32(u'qualifiers_block_size'),
      construct.Bytes(
          u'qualifiers_block_data',
          lambda ctx: ctx.qualifiers_block_size - 4))

  _PROPERTY_TYPES = {
      0x00000002: u'CIM-TYPE-SINT16',
      0x00000003: u'CIM-TYPE-SINT32',
      0x00000004: u'CIM-TYPE-REAL32',
      0x00000005: u'CIM-TYPE-REAL64',
      0x00000008: u'CIM-TYPE-STRING',
      0x0000000b: u'CIM-TYPE-BOOLEAN',
      0x0000000d: u'CIM-TYPE-OBJECT',
      0x00000010: u'CIM-TYPE-SINT8',
      0x00000011: u'CIM-TYPE-UINT8',
      0x00000012: u'CIM-TYPE-UINT16',
      0x00000013: u'CIM-TYPE-UINT32',
      0x00000014: u'CIM-TYPE-SINT64',
      0x00000015: u'CIM-TYPE-UINT64',
      0x00000065: u'CIM-TYPE-DATETIME',
      0x00000066: u'CIM-TYPE-REFERENCE',
      0x00000067: u'CIM-TYPE-CHAR16',

      0x00002002: u'CIM-ARRAY-SINT16',
      0x00002003: u'CIM-ARRAY-SINT32',
      0x00002004: u'CIM-ARRAY-REAL32',
      0x00002005: u'CIM-ARRAY-REAL64',
      0x00002008: u'CIM-ARRAY-STRING',
      0x0000200b: u'CIM-ARRAY-BOOLEAN',
      0x0000200d: u'CIM-ARRAY-OBJECT',
      0x00002010: u'CIM-ARRAY-SINT8',
      0x00002011: u'CIM-ARRAY-UINT8',
      0x00002012: u'CIM-ARRAY-UINT16',
      0x00002013: u'CIM-ARRAY-UINT32',
      0x00002014: u'CIM-ARRAY-SINT64',
      0x00002015: u'CIM-ARRAY-UINT64',
      0x00002065: u'CIM-ARRAY-DATETIME',
      0x00002066: u'CIM-ARRAY-REFERENCE',
      0x00002067: u'CIM-ARRAY-CHAR16',
  }

  # A size of 0 indicates variable of size.
  _PROPERTY_TYPE_VALUE_SIZES = {
      0x00000002: 2,
      0x00000003: 4,
      0x00000004: 4,
      0x00000005: 8,
      0x00000008: 0,
      0x0000000b: 2,
      0x0000000d: 0,
      0x00000010: 1,
      0x00000011: 1,
      0x00000012: 2,
      0x00000013: 4,
      0x00000014: 8,
      0x00000015: 8,
      0x00000065: 0,
      0x00000066: 2,
      0x00000067: 2,
  }

  _INTERFACE_OBJECT_RECORD = construct.Struct(
      u'interface_object_record',
      construct.Bytes(u'string_digest_hash', 64),
      construct.ULInt64(u'date_time1'),
      construct.ULInt64(u'date_time2'),
      construct.ULInt32(u'data_size'),
      construct.Bytes(u'data', lambda ctx: ctx.data_size - 4))

  _REGISTRATION_OBJECT_RECORD = construct.Struct(
      u'registration_object_record',
      construct.ULInt32(u'name_space_string_size'),
      construct.Bytes(
          u'name_space_string', lambda ctx: ctx.name_space_string_size * 2),
      construct.ULInt32(u'class_name_string_size'),
      construct.Bytes(
          u'class_name_string', lambda ctx: ctx.class_name_string_size * 2),
      construct.ULInt32(u'attribute_name_string_size'),
      construct.Bytes(
          u'attribute_name_string',
          lambda ctx: ctx.attribute_name_string_size * 2),
      construct.ULInt32(u'attribute_value_string_size'),
      construct.Bytes(
          u'attribute_value_string',
          lambda ctx: ctx.attribute_value_string_size * 2),
      construct.Bytes(u'unknown1', 8))

  DATA_TYPE_CLASS_DEFINITION = u'CD'

  def __init__(self, data_type, data, debug=False):
    """Initializes an object record object.

    Args:
      data_type: a string containg the object record data type.
      data: a byte string containg the object record data.
    """
    super(ObjectRecord, self).__init__()
    self._debug = debug
    self.data_type = data_type
    self.data = data

  def _ReadClassDefinition(self, object_record_data):
    """Reads a class definition object record.

    Args:
      object_record_data: a binary string containing the object record data.

    Raises:
      ParseError: if the object record cannot be read.
    """
    if self._debug:
      print(u'Reading class definition object record.')

    try:
      class_definition_struct = self._CLASS_DEFINITION_OBJECT_RECORD.parse(
          object_record_data)
    except construct.FieldError as exception:
      raise ParseError((
          u'Unable to parse class definition object record with '
          u'error: {0:s}').format(exception))

    try:
      utf16_stream = class_definition_struct.super_class_name_string
      super_class_name_string = utf16_stream.decode(u'utf-16-le')
    except UnicodeDecodeError as exception:
      super_class_name_string = u''

    super_class_name_string_size = (
        class_definition_struct.super_class_name_string_size)
    date_time = class_definition_struct.date_time
    data_size = class_definition_struct.data_size

    if self._debug:
      print(u'Super class name string size\t\t\t\t\t\t: {0:d}'.format(
          super_class_name_string_size))
      print(u'Super class name string\t\t\t\t\t\t\t: {0:s}'.format(
          super_class_name_string))
      print(u'Unknown date and time\t\t\t\t\t\t\t: {0!s}'.format(
          FromFiletime(date_time)))

      print(u'Data size\t\t\t\t\t\t\t\t: {0:d}'.format(data_size))
      print(u'Data:')
      print(hexdump.Hexdump(class_definition_struct.data))

    self._ReadClassDefinitionHeader(class_definition_struct.data)

    data_offset = 12 + (super_class_name_string_size * 2) + data_size
    if data_offset < len(object_record_data):
      if self._debug:
        print(u'Methods data:')
        print(hexdump.Hexdump(object_record_data[data_offset:]))

      self._ReadClassDefinitionMethods(object_record_data[data_offset:])

  def _ReadClassDefinitionHeader(self, class_definition_data):
    """Reads a class definition header.

    Args:
      class_definition_data (bytes): class definition data.

    Raises:
      ParseError: if the class definition cannot be read.
    """
    if self._debug:
      print(u'Reading class definition header.')

    try:
      class_definition_header_struct = self._CLASS_DEFINITION_HEADER.parse(
          class_definition_data)
    except construct.FieldError as exception:
      raise ParseError((
          u'Unable to parse class definition header with error: {0:s}').format(
              exception))

    number_of_property_descriptors = (
        class_definition_header_struct.number_of_property_descriptors)
    property_descriptors_array = (
        class_definition_header_struct.property_descriptors)

    property_descriptors = []
    for index in range(number_of_property_descriptors):
      property_name_offset = property_descriptors_array[index].name_offset
      property_data_offset = property_descriptors_array[index].data_offset

      property_descriptor = PropertyDescriptor(
          property_name_offset, property_data_offset)
      property_descriptors.append(property_descriptor)

    if self._debug:
      print(u'Unknown1\t\t\t\t\t\t\t\t: {0:d}'.format(
          class_definition_header_struct.unknown1))

      print(u'Class name offset\t\t\t\t\t\t\t: 0x{0:08x}'.format(
          class_definition_header_struct.class_name_offset))
      print(u'Default value size\t\t\t\t\t\t\t: {0:d}'.format(
          class_definition_header_struct.default_value_size))

      print(u'Super class name block size\t\t\t\t\t\t: {0:d}'.format(
          class_definition_header_struct.super_class_name_block_size))
      print(u'Super class name block data:')
      super_class_name_block_data = (
          class_definition_header_struct.super_class_name_block_data)
      print(hexdump.Hexdump(super_class_name_block_data))

      print(u'Qualifiers block size\t\t\t\t\t\t\t: {0:d}'.format(
          class_definition_header_struct.qualifiers_block_size))
      print(u'Qualifiers block data:')
      qualifiers_block_data = (
          class_definition_header_struct.qualifiers_block_data)
      print(hexdump.Hexdump(qualifiers_block_data))

      print(u'Number of property descriptors\t\t\t\t\t\t: {0:d}'.format(
          number_of_property_descriptors))

      for index, property_descriptor in enumerate(property_descriptors):
        print((u'Property descriptor: {0:d} name offset\t\t\t\t\t: '
               u'0x{1:08x}').format(index, property_descriptor.name_offset))
        print((u'Property descriptor: {0:d} definition offset\t\t\t\t: '
               u'0x{1:08x}').format(
                   index, property_descriptor.definition_offset))

      print(u'Default value data:')
      default_value_data = (
          class_definition_header_struct.default_value_data)
      print(hexdump.Hexdump(default_value_data))

      properties_block_size = (
          class_definition_header_struct.properties_block_size)
      print(u'Properties block size\t\t\t\t\t\t\t: {0:d} (0x{1:08x})'.format(
          properties_block_size & 0x7fffffff, properties_block_size))

      # if class_definition_header_struct.super_class_name_block_size > 4:
      #   super_class_name_block_struct = class_definition_header_struct.get(
      #       u'super_class_name_block')
      #   print(u'Super class name string flags\t\t\t\t\t\t: 0x{0:02x}'.format(
      #       super_class_name_block_struct.get(
      #           u'super_class_name_string_flags')))
      #   print(u'Super class name string\t\t\t\t\t\t\t: {0:s}'.format(
      #       super_class_name_block_struct.get(u'super_class_name_string')))
      #   print(u'Super class name string size\t\t\t\t\t\t: {0:d}'.format(
      #       super_class_name_block_struct.get(
      #           u'super_class_name_string_size')))

      print(u'')

    properties_block_data = (
        class_definition_header_struct.properties_block_data)
    self._ReadClassDefinitionProperties(
        properties_block_data, property_descriptors)

  def _ReadClassDefinitionMethods(self, class_definition_data):
    """Reads a class definition methods.

    Args:
      class_definition_data (bytes): class definition data.

    Raises:
      ParseError: if the class definition cannot be read.
    """
    if self._debug:
      print(u'Reading class definition methods.')

    try:
      class_definition_methods_struct = self._CLASS_DEFINITION_METHODS.parse(
          class_definition_data)
    except construct.FieldError as exception:
      raise ParseError((
          u'Unable to parse class definition methods with error: {0:s}').format(
              exception))

    methods_block_size = class_definition_methods_struct.get(
        u'methods_block_size')

    if self._debug:
      print(u'Methods block size\t\t\t\t\t\t\t: {0:d} (0x{1:08x})'.format(
          methods_block_size & 0x7fffffff, methods_block_size))
      print(u'Methods block data:')
      print(hexdump.Hexdump(class_definition_methods_struct.get(
          u'methods_block_data')))

  def _ReadClassDefinitionProperties(
      self, properties_data, property_descriptors):
    """Reads class definition properties.

    Args:
      properties_data: a binary string containing the class
                       definition properties data.
      property_descriptors: a list of property descriptors (instance of
                            PropertyDescriptor).

    Raises:
      ParseError: if the class definition properties cannot be read.
    """
    if self._debug:
      print(u'Reading class definition properties.')

    if self._debug:
      print(u'Properties data:')
      print(hexdump.Hexdump(properties_data))

    for index, property_descriptor in enumerate(property_descriptors):
      name_offset = property_descriptor.name_offset & 0x7fffffff
      property_name_data = properties_data[name_offset:]

      try:
        property_name_struct = self._PROPERTY_NAME.parse(property_name_data)
      except construct.FieldError as exception:
        raise ParseError((
            u'Unable to parse property name with error: {0:s}').format(
                exception))

      string_flags = property_name_struct.get(u'string_flags')

      # TODO: check if string flags is 0
      if self._debug:
        print((u'Property: {0:d} name string flags\t\t\t\t\t\t: '
               u'0x{1:02x}').format(index, string_flags))
        print(u'Property: {0:d} name string\t\t\t\t\t\t\t: {1:s}'.format(
            index, property_name_struct.get(u'string')))
        print(u'')

      definition_offset = property_descriptor.definition_offset & 0x7fffffff
      property_definition_data = properties_data[definition_offset:]

      try:
        property_definition_struct = self._PROPERTY_DEFINITION.parse(
            property_definition_data)
      except construct.FieldError as exception:
        raise ParseError((
            u'Unable to parse property definition with error: {0:s}').format(
                exception))

      property_type = property_definition_struct.get(u'type')

      if self._debug:
        property_type_string = self._PROPERTY_TYPES.get(
            property_type, u'UNKNOWN')
        print(u'Property: {0:d} type\t\t\t\t\t\t\t: 0x{1:08x} ({2:s})'.format(
            index, property_type, property_type_string))
        print(u'Property: {0:d} index\t\t\t\t\t\t\t: {1:d}'.format(
            index, property_definition_struct.get(u'index')))
        print(u'Property: {0:d} offset\t\t\t\t\t\t\t: 0x{1:08x}'.format(
            index, property_definition_struct.get(u'offset')))
        print(u'Property: {0:d} level\t\t\t\t\t\t\t: {1:d}'.format(
            index, property_definition_struct.get(u'level')))

        print(u'Property: {0:d} qualifiers block size\t\t\t\t\t: {1:d}'.format(
            index, property_definition_struct.get(u'qualifiers_block_size')))
        print(u'Property: {0:d} qualifiers block data:'.format(index))
        qualifiers_block_data = property_definition_struct.get(
            u'qualifiers_block_data')
        print(hexdump.Hexdump(qualifiers_block_data))

      property_value_size = self._PROPERTY_TYPE_VALUE_SIZES.get(
          property_type & 0x00001fff, None)
      # TODO: handle property value data.
      property_value_data = b''

      if property_value_size is not None:
        if self._debug:
          print(u'Property: {0:d} value size\t\t\t\t\t\t\t: {1:d}'.format(
              index, property_value_size))

          # TODO: handle variable size value data.
          # TODO: handle array.
          print(u'Property: {0:d} value data:'.format(index))
          print(hexdump.Hexdump(property_value_data[:property_value_size]))

  def _ReadInterface(self, object_record_data):
    """Reads an interface object record.

    Args:
      object_record_data: a binary string containing the object record data.

    Raises:
      ParseError: if the object record cannot be read.
    """
    if self._debug:
      print(u'Reading interface object record.')

    try:
      interface_struct = self._INTERFACE_OBJECT_RECORD.parse(object_record_data)
    except construct.FieldError as exception:
      raise ParseError(
          u'Unable to parse interace object record with error: {0:s}'.format(
              exception))

    try:
      utf16_stream = interface_struct.get(u'string_digest_hash')
      string_digest_hash = utf16_stream.decode(u'utf-16-le')
    except UnicodeDecodeError as exception:
      string_digest_hash = u''

    date_time1 = interface_struct.get(u'date_time1')
    date_time2 = interface_struct.get(u'date_time2')

    if self._debug:
      print(u'String digest hash\t\t\t\t\t\t\t: {0:s}'.format(
          string_digest_hash))
      print(u'Unknown data and time1\t\t\t\t\t\t\t: {0!s}'.format(
          FromFiletime(date_time1)))
      print(u'Unknown data and time2\t\t\t\t\t\t\t: {0!s}'.format(
          FromFiletime(date_time2)))

      print(u'Data size\t\t\t\t\t\t\t\t: {0:d}'.format(
          interface_struct.get(u'data_size')))

      print(u'')

      print(u'Data:')
      print(hexdump.Hexdump(interface_struct.data))

  def _ReadRegistration(self, object_record_data):
    """Reads a registration object record.

    Args:
      object_record_data: a binary string containing the object record data.

    Raises:
      ParseError: if the object record cannot be read.
    """
    if self._debug:
      print(u'Reading registration object record.')

    try:
      registration_struct = self._REGISTRATION_OBJECT_RECORD.parse(
          object_record_data)
    except construct.FieldError as exception:
      raise ParseError((
          u'Unable to parse registration object record with '
          u'error: {0:s}').format(exception))

    try:
      utf16_stream = registration_struct.get(u'name_space_string')
      name_space_string = utf16_stream.decode(u'utf-16-le')
    except UnicodeDecodeError as exception:
      name_space_string = u''

    try:
      utf16_stream = registration_struct.get(u'class_name_string')
      class_name_string = utf16_stream.decode(u'utf-16-le')
    except UnicodeDecodeError as exception:
      class_name_string = u''

    try:
      utf16_stream = registration_struct.get(u'attribute_name_string')
      attribute_name_string = utf16_stream.decode(u'utf-16-le')
    except UnicodeDecodeError as exception:
      attribute_name_string = u''

    try:
      utf16_stream = registration_struct.get(u'attribute_value_string')
      attribute_value_string = utf16_stream.decode(u'utf-16-le')
    except UnicodeDecodeError as exception:
      attribute_value_string = u''

    if self._debug:
      print(u'Name space string size\t\t\t\t\t\t\t: {0:d}'.format(
          registration_struct.get(u'name_space_string_size')))
      print(u'Name space string\t\t\t\t\t\t\t: {0:s}'.format(
          name_space_string))

      print(u'Class name string size\t\t\t\t\t\t\t: {0:d}'.format(
          registration_struct.get(u'class_name_string_size')))
      print(u'Class name string\t\t\t\t\t\t\t: {0:s}'.format(
          class_name_string))

      print(u'Attribute name string size\t\t\t\t\t\t: {0:d}'.format(
          registration_struct.get(u'attribute_name_string_size')))
      print(u'Attribute name string\t\t\t\t\t\t\t: {0:s}'.format(
          attribute_name_string))

      print(u'Attribute value string size\t\t\t\t\t\t: {0:d}'.format(
          registration_struct.get(u'attribute_value_string_size')))
      print(u'Attribute value string\t\t\t\t\t\t\t: {0:s}'.format(
          attribute_value_string))

      print(u'')

  def Read(self):
    """Reads an object record."""
    if self._debug:
      print(u'Object record data:')
      print(hexdump.Hexdump(self.data))

    if self._debug:
      if self.data_type == self.DATA_TYPE_CLASS_DEFINITION:
        self._ReadClassDefinition(self.data)
      elif self.data_type in (u'I', u'IL'):
        self._ReadInterface(self.data)
      elif self.data_type == u'R':
        self._ReadRegistration(self.data)


class ObjectsDataPage(BinaryDataFormat):
  """An objects data page.

  Attributes:
    page_offset (int): page offset or None.
  """

  _DATA_TYPE_FABRIC_DEFINITION = b'\n'.join([
      b'name: uint32',
      b'type: integer',
      b'attributes:',
      b'  format: unsigned',
      b'  size: 4',
      b'  units: bytes',
      b'---',
      b'name: cim_object_descriptor',
      b'type: structure',
      b'attributes:',
      b'  byte_order: little-endian',
      b'members:',
      b'- name: identifier',
      b'  data_type: uint32',
      b'- name: data_offset',
      b'  data_type: uint32',
      b'- name: data_size',
      b'  data_type: uint32',
      b'- name: data_checksum',
      b'  data_type: uint32',
  ])

  _DATA_TYPE_FABRIC = dtfabric_fabric.DataTypeFabric(
      yaml_definition=_DATA_TYPE_FABRIC_DEFINITION)

  _OBJECT_DESCRIPTOR = _DATA_TYPE_FABRIC.CreateDataTypeMap(
      u'cim_object_descriptor')

  _OBJECT_DESCRIPTOR_SIZE = _OBJECT_DESCRIPTOR.GetByteSize()

  _EMPTY_OBJECT_DESCRIPTOR = b'\x00' * _OBJECT_DESCRIPTOR_SIZE

  PAGE_SIZE = 8192

  def __init__(self, debug=False):
    """Initializes an objects data page object.

    Args:
      debug (Optional[bool]): True if debug information should be printed.
    """
    super(ObjectsDataPage, self).__init__(debug=debug)
    self._object_descriptors = []

    self.page_offset = None

  def _ReadObjectDescriptor(self, file_object):
    """Reads an object descriptor.

    Args:
      file_object (file): a file-like object.

    Returns:
      cim_object_descriptor: an object descriptor or None.

    Raises:
      ParseError: if the object descriptor cannot be read.
    """
    file_offset = file_object.tell()
    if self._debug:
      print(u'Reading object descriptor at offset: 0x{0:08x}'.format(
          file_offset))

    object_descriptor_data = file_object.read(self._OBJECT_DESCRIPTOR_SIZE)

    if self._debug:
      self._DebugPrintData(u'Object descriptor data', object_descriptor_data)

    # The last object descriptor (terminator) is filled with 0-byte values.
    if object_descriptor_data == self._EMPTY_OBJECT_DESCRIPTOR:
      return

    try:
      object_descriptor = self._OBJECT_DESCRIPTOR.MapByteStream(
          object_descriptor_data)
    except dtfabric_errors.MappingError as exception:
      raise ParseError(
          u'Unable to parse object descriptor with error: {0:s}'.format(
              exception))

    if self._debug:
      value_string = u'0x{0:08x}'.format(object_descriptor.identifier)
      self._DebugPrintValue(u'Identifier', value_string)

      value_string = u'0x{0:08x} (0x{1:08x})'.format(
          object_descriptor.data_offset,
          file_offset + object_descriptor.data_offset)
      self._DebugPrintValue(u'Data offset', value_string)

      value_string = u'{0:d}'.format(object_descriptor.data_size)
      self._DebugPrintValue(u'Data size', value_string)

      value_string = u'0x{0:08x}'.format(object_descriptor.data_checksum)
      self._DebugPrintValue(u'Checksum', value_string)

      print(u'')

    return object_descriptor

  def _ReadObjectDescriptors(self, file_object):
    """Reads object descriptors.

    Args:
      file_object (file): a file-like object.

    Raises:
      ParseError: if the object descriptor cannot be read.
    """
    while True:
      object_descriptor = self._ReadObjectDescriptor(file_object)
      if not object_descriptor:
        break

      self._object_descriptors.append(object_descriptor)

  def GetObjectDescriptor(self, record_identifier, data_size):
    """Retrieves a specific object descriptor.

    Args:
      record_identifier: an integer containing the object record identifier.
      data_size: an integer containing the object record data size.

    Returns:
      cim_object_descriptor: an object descriptor or None.
    """
    object_descriptor_match = None
    for object_descriptor in self._object_descriptors:
      if object_descriptor.identifier == record_identifier:
        object_descriptor_match = object_descriptor
        break

    if not object_descriptor_match:
      logging.warning(u'Object record data not found.')
      return

    if object_descriptor_match.data_size != data_size:
      logging.warning(u'Object record data size mismatch.')
      return

    return object_descriptor_match

  def ReadPage(self, file_object, file_offset, data_page=False):
    """Reads a page.

    Args:
      file_object (file): a file-like object.
      file_offset (int): offset of the page relative from the start of the file.
      data_page (Optional[bool]): True if the page is a data page.

    Raises:
      ParseError: if the page cannot be read.
    """
    file_object.seek(file_offset, os.SEEK_SET)

    if self._debug:
      print(u'Reading objects data page at offset: 0x{0:08x}'.format(
          file_offset))

    self.page_offset = file_offset

    if not data_page:
      self._ReadObjectDescriptors(file_object)

  def ReadObjectRecordData(self, file_object, data_offset, data_size):
    """Reads the data of an object record.

    Args:
      file_object (file): a file-like object.
      data_offset (int): offset of the object record data relative from
          the start of the page.
      data_size (int): object record data size.

    Returns:
      bytes: object record data.

    Raises:
      ParseError: if the object record cannot be read.
    """
    # Make the offset relative to the start of the file.
    file_offset = self.page_offset + data_offset

    file_object.seek(file_offset, os.SEEK_SET)

    if self._debug:
      print(u'Reading object record at offset: 0x{0:08x}'.format(file_offset))

    available_page_size = self.PAGE_SIZE - data_offset

    if data_size > available_page_size:
      read_size = available_page_size
    else:
      read_size = data_size

    return file_object.read(read_size)


class ObjectsDataFile(object):
  """An objects data (Objects.data) file."""

  _KEY_SEGMENT_SEPARATOR = u'\\'
  _KEY_VALUE_SEPARATOR = u'.'

  _KEY_VALUE_PAGE_NUMBER_INDEX = 1
  _KEY_VALUE_RECORD_IDENTIFIER_INDEX = 2
  _KEY_VALUE_DATA_SIZE_INDEX = 3

  def __init__(self, objects_mapping_file, debug=False):
    """Initializes an objects data file object.

    Args:
      objects_mapping_file: an objects mapping file (instance of MappingFile).
      debug (Optional[bool]): True if debug information should be printed.
    """
    super(ObjectsDataFile, self).__init__()
    self._debug = debug
    self._file_object = None
    self._file_object_opened_in_object = False
    self._file_size = 0

    self._objects_mapping_file = objects_mapping_file

  def _GetKeyValues(self, key):
    """Retrieves the key values from the key.

    Args:
      key (str): a CIM key.

    Returns:
      tuple[str, int, int, int]: name of the key, corresponding page number,
          record identifier and record data size or None.
    """
    _, _, key = key.rpartition(self._KEY_SEGMENT_SEPARATOR)

    if self._KEY_VALUE_SEPARATOR not in key:
      return

    key_values = key.split(self._KEY_VALUE_SEPARATOR)
    if not len(key_values) == 4:
      logging.warning(u'Unsupported number of key values.')
      return

    try:
      page_number = int(key_values[self._KEY_VALUE_PAGE_NUMBER_INDEX], 10)
    except ValueError:
      logging.warning(u'Unsupported key value page number.')
      return

    try:
      record_identifier = int(
          key_values[self._KEY_VALUE_RECORD_IDENTIFIER_INDEX], 10)
    except ValueError:
      logging.warning(u'Unsupported key value record identifier.')
      return

    try:
      data_size = int(key_values[self._KEY_VALUE_DATA_SIZE_INDEX], 10)
    except ValueError:
      logging.warning(u'Unsupported key value data size.')
      return

    return key_values[0], page_number, record_identifier, data_size

  def _GetPage(self, page_number, data_page=False):
    """Retrieves a specific page.

    Args:
      page_number (int): page number.
      data_page (Optional[bool]): True if the page is a data page.

    Returns:
      ObjectsDataPage: objects data page or None.
    """
    file_offset = page_number * ObjectsDataPage.PAGE_SIZE
    if file_offset >= self._file_size:
      return

    # TODO: cache pages.
    return self._ReadPage(file_offset, data_page=data_page)

  def _ReadPage(self, file_offset, data_page=False):
    """Reads a page.

    Args:
      file_offset (int): offset of the page relative from the start of the file.
      data_page (Optional[bool]): True if the page is a data page.

    Return:
      ObjectsDataPage: objects data page or None.

    Raises:
      ParseError: if the page cannot be read.
    """
    objects_page = ObjectsDataPage(debug=self._debug)
    objects_page.ReadPage(self._file_object, file_offset, data_page=data_page)
    return objects_page

  def Close(self):
    """Closes the objects data file."""
    if self._file_object_opened_in_object:
      self._file_object.close()
    self._file_object = None

  def GetMappedPage(self, page_number, data_page=False):
    """Retrieves a specific mapped page.

    Args:
      page_number (int): page number.
      data_page (Optional[bool]): True if the page is a data page.

    Returns:
      ObjectsDataPage: objects data page or None.
    """
    mapped_page_number = self._objects_mapping_file.mappings[page_number]

    objects_page = self._GetPage(mapped_page_number, data_page=data_page)
    if not objects_page:
      logging.warning(
          u'Unable to read objects data mapped page: {0:d}.'.format(
              page_number))
      return

    return objects_page

  def GetObjectRecordByKey(self, key):
    """Retrieves a specific object record.

    Args:
      key (str): a CIM key.

    Returns:
      ObjectRecord: an object record or None.
    """
    key, page_number, record_identifier, data_size = self._GetKeyValues(key)

    data_segments = []
    data_page = False
    data_segment_index = 0
    while data_size > 0:
      object_page = self.GetMappedPage(page_number, data_page=data_page)
      if not object_page:
        logging.warning(
            u'Unable to read objects record: {0:d} data segment: {1:d}.'.format(
                record_identifier, data_segment_index))
        return

      if not data_page:
        object_descriptor = object_page.GetObjectDescriptor(
            record_identifier, data_size)

        data_offset = object_descriptor.data_offset
        data_page = True
      else:
        data_offset = 0

      data_segment = object_page.ReadObjectRecordData(
          self._file_object, data_offset, data_size)
      if not data_segment:
        logging.warning(
            u'Unable to read objects record: {0:d} data segment: {1:d}.'.format(
                record_identifier, data_segment_index))
        return

      data_segments.append(data_segment)
      data_size -= len(data_segment)
      data_segment_index += 1
      page_number += 1

    data_type, _, _ = key.partition(u'_')
    object_record_data = b''.join(data_segments)
    return ObjectRecord(data_type, object_record_data, debug=self._debug)

  def Open(self, filename):
    """Opens the objects data file.

    Args:
      filename (str): name of the file.
    """
    stat_object = os.stat(filename)
    self._file_size = stat_object.st_size

    self._file_object = open(filename, 'rb')
    self._file_object_opened_in_object = True


class CIMRepository(object):
  """A CIM repository."""

  _MAPPING_VER = construct.ULInt32(u'active_mapping_file')

  def __init__(self, debug=False):
    """Initializes a CIM repository object.

    Args:
      debug (Optional[bool]): True if debug information should be printed.
    """
    super(CIMRepository, self).__init__()
    self._debug = debug
    self._index_binary_tree_file = None
    self._index_mapping_file = None
    self._objects_data_file = None
    self._objects_mapping_file = None

  def _GetCurrentMappingFile(self, path):
    """Retrieves the current mapping file.

    Args:
      path (str): path to the CIM repository.

    Raises:
      ParseError: if the current mapping file cannot be read.
    """
    mapping_file_glob = glob.glob(
        os.path.join(path, u'[Mm][Aa][Pp][Pp][Ii][Nn][Gg].[Vv][Ee][Rr]'))

    active_mapping_file = 0
    if mapping_file_glob:
      with open(mapping_file_glob[0], 'rb') as file_object:
        try:
          active_mapping_file = self._MAPPING_VER.parse_stream(file_object)
        except construct.FieldError as exception:
          raise ParseError(
              u'Unable to parse Mapping.ver with error: {0:s}'.format(
                  exception))

      if self._debug:
        print(u'Active mapping file: {0:d}'.format(active_mapping_file))

    if mapping_file_glob:
      mapping_file_glob = glob.glob(os.path.join(
          path, u'[Mm][Aa][Pp][Pp][Ii][Nn][Gg]{0:d}.[Mm][Aa][Pp]'.format(
              active_mapping_file)))
    else:
      mapping_file_glob = glob.glob(os.path.join(
          path, u'[Mm][Aa][Pp][Pp][Ii][Nn][Gg][1-3].[Mm][Aa][Pp]'))

    # TODO: determine active mapping file for Windows Vista and later.
    for mapping_file_path in mapping_file_glob:
      if self._debug:
        print(u'Reading: {0:s}'.format(mapping_file_path))

      objects_mapping_file = MappingFile(debug=self._debug)
      objects_mapping_file.Open(mapping_file_path)

      index_mapping_file = MappingFile(debug=self._debug)
      index_mapping_file.Open(
          mapping_file_path, file_offset=objects_mapping_file.data_size)

  def _GetKeysFromIndexPage(self, index_page):
    """Retrieves the keys from an index page.

    Yields:
      str: a CIM key.
    """
    for key in index_page.keys:
      yield key

    for sub_page_number in index_page.sub_pages:
      sub_index_page = self._index_binary_tree_file.GetMappedPage(
          sub_page_number)
      for key in self._GetKeysFromIndexPage(sub_index_page):
        yield key

  def Close(self):
    """Closes the CIM repository."""
    if self._index_binary_tree_file:
      self._index_binary_tree_file.Close()
      self._index_binary_tree_file = None

    if self._index_mapping_file:
      self._index_mapping_file.Close()
      self._index_mapping_file = None

    if self._objects_data_file:
      self._objects_data_file.Close()
      self._objects_data_file = None

    if self._objects_mapping_file:
      self._objects_mapping_file.Close()
      self._objects_mapping_file = None

  def GetKeys(self):
    """Retrieves the keys.

    Yields:
      str: a CIM key.
    """
    if not self._index_binary_tree_file:
      return

    index_page = self._index_binary_tree_file.GetRootPage()
    for key in self._GetKeysFromIndexPage(index_page):
      yield key

  def GetObjectRecordByKey(self, key):
    """Retrieves a specific object record.

    Args:
      key (str): a CIM key.

    Returns:
      ObjectRecord: an object record or None.
    """
    if not self._objects_data_file:
      return

    return self._objects_data_file.GetObjectRecordByKey(key)

  def Open(self, path):
    """Opens the CIM repository.

    Args:
      path (str): path to the CIM repository.
    """
    # TODO: self._GetCurrentMappingFile(path)

    # Index mappings file.
    index_mapping_file_path = glob.glob(
        os.path.join(path, u'[Ii][Nn][Dd][Ee][Xx].[Mm][Aa][Pp]'))[0]

    if self._debug:
      print(u'Reading: {0:s}'.format(index_mapping_file_path))

    self._index_mapping_file = MappingFile(debug=self._debug)
    self._index_mapping_file.Open(index_mapping_file_path)

    # Index binary tree file.
    index_binary_tree_file_path = glob.glob(
        os.path.join(path, u'[Ii][Nn][Dd][Ee][Xx].[Bb][Tt][Rr]'))[0]

    if self._debug:
      print(u'Reading: {0:s}'.format(index_binary_tree_file_path))

    self._index_binary_tree_file = IndexBinaryTreeFile(
        self._index_mapping_file, debug=self._debug)
    self._index_binary_tree_file.Open(index_binary_tree_file_path)

    # Objects mappings file.
    objects_mapping_file_path = glob.glob(
        os.path.join(path, u'[Oo][Bb][Jj][Ee][Cc][Tt][Ss].[Mm][Aa][Pp]'))[0]

    if self._debug:
      print(u'Reading: {0:s}'.format(objects_mapping_file_path))

    self._objects_mapping_file = MappingFile(debug=self._debug)
    self._objects_mapping_file.Open(objects_mapping_file_path)

    # Objects data file.
    objects_data_file_path = glob.glob(
        os.path.join(path, u'[Oo][Bb][Jj][Ee][Cc][Tt][Ss].[Da][Aa][Tt][Aa]'))[0]

    if self._debug:
      print(u'Reading: {0:s}'.format(objects_data_file_path))

    self._objects_data_file = ObjectsDataFile(
        self._objects_mapping_file, debug=self._debug)
    self._objects_data_file.Open(objects_data_file_path)


def Main():
  """The main program function.

  Returns:
    bool: True if successful or False if not.
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

  cim_repository = CIMRepository(debug=options.debug)

  cim_repository.Open(options.source)

  object_record_keys = {}
  for key in cim_repository.GetKeys():
    if u'.' not in key:
      continue

    _, _, key_name = key.rpartition(u'\\')
    key_name, _, _ = key_name.partition(u'.')

    if key_name not in object_record_keys:
      object_record_keys[key_name] = []

    object_record_keys[key_name].append(key)

  for key_name, keys in iter(object_record_keys.items()):
    for key in keys:
      print(key)
      object_record = cim_repository.GetObjectRecordByKey(key)
      object_record.Read()

  cim_repository.Close()

  return True


if __name__ == '__main__':
  if not Main():
    sys.exit(1)
  else:
    sys.exit(0)
