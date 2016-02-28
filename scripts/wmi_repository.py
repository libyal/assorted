#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Script to parse WMI Common Information Model (CIM) repository files."""

from __future__ import print_function
import argparse
import glob
import logging
import os
import sys

import construct

import hexdump


# pylint: disable=logging-format-interpolation

class IndexBinaryTreePage(object):
  """Class that contains a binary-tree index page.

  Attributes:
    type: an integer containing the page type.
    values: a dictionary of binary-tree index page keys and values.
  """

  PAGE_SIZE = 8192

  _PAGE_HEADER = construct.Struct(
      u'page_header',
      construct.ULInt32(u'page_type'),
      construct.ULInt32(u'mapped_page_number'),
      construct.ULInt32(u'unknown2'),
      construct.ULInt32(u'root_page_number'),
      construct.ULInt32(u'number_of_page_values'))

  _PAGE_KEY_DATA_SIZE = construct.ULInt16(u'page_key_data_size')

  _PAGE_TYPES = {
      0xaccc: u'Is active',
      0xaddd: u'Is administrative',
      0xbadd: u'Is deleted',
  }

  def __init__(self, debug=False):
    """Initializes the binary-tree index page object.

    Args:
      debug: optional boolean value to indicate if debug information should
             be printed.
    """
    super(IndexBinaryTreePage, self).__init__()
    self._debug = debug
    self._key_offsets = None
    self._number_of_page_values = None
    self._value_offsets = None

    self.root_page_number = None
    self.page_type = None
    self.values = []

  def _ReadHeader(self, file_object):
    """Reads a page header.

    Args:
      file_object: a file-like object.

    Returns:
      A contains a binary-tree index page.

    Raises:
      IOError: if the page header cannot be read.
    """
    file_offset = file_object.tell()
    if self._debug:
      print(u'Reading page header at offset: 0x{0:08x}'.format(file_offset))

    page_header_data = file_object.read(self._PAGE_HEADER.sizeof())

    try:
      page_header_struct = self._PAGE_HEADER.parse(page_header_data)
    except construct.FieldError as exception:
      raise IOError((
          u'Unable to parse page header at offset: 0x{0:08x} '
          u'with error: {1:s}').format(file_offset, exception))

    self.page_type = page_header_struct.get(u'page_type')
    self.root_page_number = page_header_struct.get(u'root_page_number')
    self._number_of_page_values = page_header_struct.get(
        u'number_of_page_values')

    if self._debug:
      print(u'Page header data:')
      print(hexdump.Hexdump(page_header_data))

    if self._debug:
      print(u'Page type\t\t\t\t\t\t\t\t: 0x{0:04x} ({1:s})'.format(
          self.page_type, self._PAGE_TYPES.get(self.page_type, u'Unknown')))
      print(u'Mapped page number\t\t\t\t\t\t\t: {0:d}'.format(
          page_header_struct.get(u'mapped_page_number')))
      print(u'Unknown2\t\t\t\t\t\t\t\t: 0x{0:08x}'.format(
          page_header_struct.get(u'unknown2')))
      print(u'Root page number\t\t\t\t\t\t\t: {0:d}'.format(
          self.root_page_number))
      print(u'Number of page values\t\t\t\t\t\t\t: {0:d}'.format(
          self._number_of_page_values))
      print(u'')

  def _ReadKeyOffsets(self, file_object):
    """Reads page key offsets.

    Args:
      file_object: a file-like object.

    Raises:
      IOError: if the page key offsets cannot be read.
    """
    if self._number_of_page_values == 0:
      return

    file_offset = file_object.tell()
    if self._debug:
      print(u'Reading page key offsets at offset: 0x{0:08x}'.format(
          file_offset))

    offsets_data_size = self._number_of_page_values * 2
    offsets_data = file_object.read(offsets_data_size)

    if self._debug:
      print(u'Page key offsets:')
      print(hexdump.Hexdump(offsets_data))

    try:
      self._key_offsets = construct.Array(
          self._number_of_page_values, construct.ULInt16(u'offset')).parse(
              offsets_data)
    except construct.FieldError as exception:
      raise IOError((
          u'Unable to parse page key offsets at offset: 0x{0:08x} '
          u'with error: {1:s}').format(file_offset, exception))

    if self._debug:
      for index in range(self._number_of_page_values):
        print(u'Page key: {0:d} offset\t\t\t\t\t\t\t: 0x{1:04x}'.format(
            index, self._key_offsets[index]))
      print(u'')

  def _ReadKeyData(self, file_object):
    """Reads page key data.

    Args:
      file_object: a file-like object.

    Raises:
      IOError: if the page key data cannot be read.
    """
    file_offset = file_object.tell()
    if self._debug:
      print(u'Reading page key data at offset: 0x{0:08x}'.format(file_offset))

    try:
      data_size = construct.ULInt16(u'data_size').parse_stream(file_object)
    except construct.FieldError as exception:
      raise IOError((
          u'Unable to parse page key data size at offset: 0x{0:08x} '
          u'with error: {1:s}').format(file_offset, exception))

    if data_size == 0:
      return

    data_size *= 2

    if self._debug:
      print(u'Page keys data size\t\t\t\t\t\t\t: {0:d} bytes'.format(
          data_size))

    data = file_object.read(data_size)

    if self._debug:
      print(u'Page key data:')
      print(hexdump.Hexdump(data))

    for index in range(len(self._key_offsets)):
      page_key_offset = self._key_offsets[index] * 2
      page_key_size = page_key_offset + 2

      try:
        page_key_data_size = self._PAGE_KEY_DATA_SIZE.parse(
            data[page_key_offset:page_key_size])
      except construct.FieldError as exception:
        raise IOError((
            u'Unable to parse page key data size: {0:d} '
            u'with error: {1:s}').format(index, exception))

      page_key_size = page_key_offset + (page_key_data_size * 2)

      if self._debug:
        print(u'Page key: {0:d} data:'.format(index))
        print(hexdump.Hexdump(data[page_key_offset:page_key_size + 2]))

      page_key_offset += 2
      page_key_size += 2
      page_key = data[page_key_offset:page_key_size].encode('hex')

      if self._debug:
        print((
            u'Page key: {0:d} data size\t\t\t\t\t\t\t: {1:d} words '
            u'({2:d} bytes)').format(
                index, page_key_data_size, page_key_data_size * 2))
        print(u'Page key: {0:d}\t\t\t\t\t\t\t\t: {1:s}'.format(
            index, page_key))
        print(u'')

  def _ReadValueOffsets(self, file_object):
    """Reads page value offsets.

    Args:
      file_object: a file-like object.

    Raises:
      IOError: if the page value offsets cannot be read.
    """
    file_offset = file_object.tell()
    if self._debug:
      print(u'Reading page value offsets at offset: 0x{0:08x}'.format(
          file_offset))

    try:
      number_of_offsets = construct.ULInt16(u'number_of_offsets').parse_stream(
          file_object)
    except construct.FieldError as exception:
      raise IOError((
          u'Unable to parse number of page value offsets at offset: 0x{0:08x} '
          u'with error: {1:s}').format(file_offset, exception))

    if self._debug:
      print(u'Number of offsets\t\t\t\t\t\t\t: {0:d}'.format(number_of_offsets))

    if number_of_offsets == 0:
      return

    offsets_data = file_object.read(number_of_offsets * 2)

    if self._debug:
      print(u'Page value offsets:')
      print(hexdump.Hexdump(offsets_data))

    try:
      self._value_offsets = construct.Array(
          number_of_offsets, construct.ULInt16(u'offset')).parse(offsets_data)
    except construct.FieldError as exception:
      raise IOError((
          u'Unable to parse page value offsets at offset: 0x{0:08x} '
          u'with error: {1:s}').format(file_offset, exception))

    if self._debug:
      for index in range(number_of_offsets):
        print(u'Page value: {0:d} offset\t\t\t\t\t\t\t: 0x{1:04x}'.format(
            index, self._value_offsets[index]))
      print(u'')

  def _ReadValueData(self, file_object):
    """Reads page value data.

    Args:
      file_object: a file-like object.

    Raises:
      IOError: if the page value data cannot be read.
    """
    file_offset = file_object.tell()
    if self._debug:
      print(u'Reading page value data at offset: 0x{0:08x}'.format(file_offset))

    try:
      data_size = construct.ULInt16(u'data_size').parse_stream(file_object)
    except construct.FieldError as exception:
      raise IOError((
          u'Unable to parse page value data size at offset: 0x{0:08x} '
          u'with error: {1:s}').format(file_offset, exception))

    if self._debug:
      print(u'Page value data size\t\t\t\t\t\t\t: {0:d} bytes'.format(
          data_size))

    if data_size == 0:
      return

    data = file_object.read(data_size)

    if self._debug:
      print(u'Page value data:')
      print(hexdump.Hexdump(data))

    for index in range(len(self._value_offsets)):
      page_value_offset = self._value_offsets[index]
      # TODO: determine size

      value_string = construct.CString(u'string').parse(data[page_value_offset:])
      if self._debug:
        print(u'Page value: {0:d} data: {1:s}'.format(index, value_string))

      self.values.append(value_string)

    if self._debug and self._value_offsets:
      print(u'')

  def _ReadSubPages(self, file_object):
    """Reads sub pages data.

    Args:
      file_object: a file-like object.

    Raises:
      IOError: if the sub pages data cannot be read.
    """
    array_data_size = (self._number_of_page_values + 1) * 4
    array_data = file_object.read(array_data_size)

    if self._debug:
      print(u'Sub pages array data:')
      print(hexdump.Hexdump(array_data))

  def ReadPage(self, file_object, file_offset):
    """Reads a page.

    Args:
      file_object: a file-like object.
      file_offset: integer containing the offset of the page relative
                   from the start of the file.

    Raises:
      IOError: if the page cannot be read.
    """
    file_object.seek(file_offset, os.SEEK_SET)

    if self._debug:
      print(u'Reading page at offset: 0x{0:08x}'.format(file_offset))

    self._ReadHeader(file_object)

    if self._number_of_page_values > 0:
      array_data_size = self._number_of_page_values * 4
      array_data = file_object.read(array_data_size)

      if self._debug:
        print(u'Unknown array data:')
        print(hexdump.Hexdump(array_data))

    self._ReadSubPages(file_object)
    self._ReadKeyOffsets(file_object)
    self._ReadKeyData(file_object)
    self._ReadValueOffsets(file_object)
    self._ReadValueData(file_object)

    trailing_data_size = (
        (file_offset + self.PAGE_SIZE) - file_object.tell())
    trailing_data = file_object.read(trailing_data_size)

    if self._debug:
      print(u'Trailing data:')
      print(hexdump.Hexdump(trailing_data))


class IndexBinaryTreeFile(object):
  """Class that contains a binary-tree index (Index.btr) file."""

  def __init__(self, debug=False):
    """Initializes the binary-tree index file object.

    Args:
      debug: optional boolean value to indicate if debug information should
             be printed.
    """
    super(IndexBinaryTreeFile, self).__init__()
    self._debug = debug
    self._file_object = None
    self._file_object_opened_in_object = False
    self._file_size = 0

    self._root_page_number = None

  def _ReadPage(self, file_offset):
    """Reads a page.

    Args:
      file_offset: integer containing the offset of the page relative
                   from the start of the file.

    Return:
      A binary-tree index page (instance of IndexBinaryTreePage).

    Raises:
      IOError: if the page cannot be read.
    """
    index_page = IndexBinaryTreePage(debug=self._debug)

    index_page.ReadPage(self._file_object, file_offset)

    if self._root_page_number is None:
      self._root_page_number = index_page.root_page_number
    elif self._root_page_number != index_page.root_page_number:
      logging.warning(u'Root page number mismatch ({0:d} != {1:d})'.format(
          self._root_page_number, index_page.root_page_number))

    return index_page

  def Close(self):
    """Closes the binary-tree index file."""
    if self._file_object_opened_in_object:
      self._file_object.close()
    self._file_object = None

  def GetPage(self, page_number):
    """Retrieves a specific page.

    Args:
      page_number: an integer containing the page number.

    Returns:
      A binary-tree index page (instance of IndexBinaryTreePage).
    """
    # TODO: cache pages.
    return self._ReadPage(page_number)

  def Open(self, filename):
    """Opens the binary-tree index file.

    Args:
      filename: a string containing the filename.
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


class MappingFile(object):
  """Class that contains mappings (*.map) file.

  Attributes:
    mapping: a list of integers containing the mappings to page
             numbers in the objects data file.
  """

  _FOOTER_SIGNATURE = 0x0000dcba
  _HEADER_SIGNATURE = 0x0000abcd

  _FILE_FOOTER = construct.Struct(
      u'file_footer',
      construct.ULInt32(u'signature'))

  _FILE_HEADER = construct.Struct(
      u'file_header',
      construct.ULInt32(u'signature'),
      construct.ULInt32(u'format_version'),
      construct.ULInt32(u'number_of_pages'))

  def __init__(self, debug=False):
    """Initializes the objects data file object.

    Args:
      debug: optional boolean value to indicate if debug information should
             be printed.
    """
    super(MappingFile, self).__init__()
    self._debug = debug
    self._file_object = None
    self._file_object_opened_in_object = False
    self._file_size = 0

    self.mappings = {}

  def _ReadFileFooter(self):
    """Reads the file footer.

    Raises:
      IOError: if the file footer cannot be read.
    """
    file_footer_data = self._file_object.read(self._FILE_FOOTER.sizeof())

    if self._debug:
      print(u'File footer data:')
      print(hexdump.Hexdump(file_footer_data))

    try:
      file_footer_struct = self._FILE_FOOTER.parse(file_footer_data)
    except construct.FieldError as exception:
      file_offset = self._file_object.tell()
      raise IOError((
          u'Unable to parse file footer at offset: 0x{0:08x} '
          u'with error: {1:s}').format(file_offset, exception))

    signature = file_footer_struct.get(u'signature')

    if self._debug:
      print(u'Signature\t\t\t\t\t\t\t\t: 0x{0:08x}'.format(signature))

    if signature != self._FOOTER_SIGNATURE:
      raise IOError(
          u'Unsupported file footer signature: 0x{0:08x}'.format(signature))

    if self._debug:
      print(u'')

  def _ReadFileHeader(self):
    """Reads the file header.

    Raises:
      IOError: if the file header cannot be read.
    """
    self._file_object.seek(0, os.SEEK_SET)

    file_header_data = self._file_object.read(self._FILE_HEADER.sizeof())

    if self._debug:
      print(u'File header data:')
      print(hexdump.Hexdump(file_header_data))

    try:
      file_header_struct = self._FILE_HEADER.parse(file_header_data)
    except construct.FieldError as exception:
      raise IOError((
          u'Unable to parse file header at offset: 0x{0:08x} '
          u'with error: {1:s}').format(0, exception))

    signature = file_header_struct.get(u'signature')
    format_version = file_header_struct.get(u'format_version')
    number_of_pages = file_header_struct.get(u'number_of_pages')

    if self._debug:
      print(u'Signature\t\t\t\t\t\t\t\t: 0x{0:08x}'.format(signature))
      print(u'Format version\t\t\t\t\t\t\t\t: 0x{0:08x}'.format(format_version))
      print(u'Number of pages\t\t\t\t\t\t\t\t: {0:d}'.format(number_of_pages))

    if signature != self._HEADER_SIGNATURE:
      raise IOError(
          u'Unsupported file header signature: 0x{0:08x}'.format(signature))

    if self._debug:
      print(u'')

  def _ReadMappings(self, mappings_reference=u'mappings'):
    """Reads the mappings.

    Args:
      mappings_reference: a string containing the mappings reference.

    Raises:
      IOError: if the mappings cannot be read.
    """
    file_offset = self._file_object.tell()
    if self._debug:
      print(u'Reading mappings at offset: 0x{0:08x}'.format(file_offset))

    try:
      number_of_entries = construct.ULInt32(u'number_of_entries').parse_stream(
          self._file_object)
    except construct.FieldError as exception:
      raise IOError((
          u'Unable to parse number of mapping entries at offset: 0x{0:08x} '
          u'with error: {1:s}').format(file_offset, exception))

    if self._debug:
      print(u'Number of entries\t\t\t\t\t\t\t: {0:d}'.format(number_of_entries))

    entries_data = self._file_object.read(number_of_entries * 4)

    if self._debug:
      print(u'Entries data:')
      print(hexdump.Hexdump(entries_data))

    try:
      mappings = construct.Array(
          number_of_entries, construct.ULInt32(u'page_number')).parse(
              entries_data)
    except construct.FieldError as exception:
      raise IOError((
          u'Unable to parse mapping entries at offset: 0x{0:08x} '
          u'with error: {1:s}').format(file_offset, exception))

    if self._debug:
      for index in range(number_of_entries):
        page_number = mappings[index]
        if page_number == 0xffffffff:
          print((
              u'Mapping entry: {0:d} page number\t\t\t\t\t\t: 0x{1:08x} '
              u'(unavailable)').format(index, page_number))
        else:
          print(u'Mapping entry: {0:d} page number\t\t\t\t\t\t: {1:d}'.format(
              index, page_number))
      print(u'')

    self.mappings[mappings_reference] = mappings

  def _ReadUnknownEntries(self):
    """Reads unknown entries.

    Raises:
      IOError: if the unknown entries cannot be read.
    """
    file_offset = self._file_object.tell()
    if self._debug:
      print(u'Reading unknown entries at offset: 0x{0:08x}'.format(file_offset))

    try:
      number_of_entries = construct.ULInt32(u'number_of_entries').parse_stream(
          self._file_object)
    except construct.FieldError as exception:
      raise IOError((
          u'Unable to parse number of unknown entries at offset: 0x{0:08x} '
          u'with error: {1:s}').format(file_offset, exception))

    if self._debug:
      print(u'Number of entries\t\t\t\t\t\t\t: {0:d}'.format(number_of_entries))

    entries_data = self._file_object.read(number_of_entries * 4)

    if self._debug:
      print(u'Entries data:')
      print(hexdump.Hexdump(entries_data))

    try:
      unknown_entries = construct.Array(
          number_of_entries, construct.ULInt32(u'page_number')).parse(
              entries_data)
    except construct.FieldError as exception:
      raise IOError((
          u'Unable to parse unknown entries at offset: 0x{0:08x} '
          u'with error: {1:s}').format(file_offset, exception))

    if self._debug:
      for index in range(number_of_entries):
        page_number = unknown_entries[index]
        if page_number == 0xffffffff:
          print((
              u'Unknown entry: {0:d} page number\t\t\t\t\t\t: 0x{1:08x} '
              u'(unavailable)').format(index, page_number))
        else:
          print(u'Unknown entry: {0:d} page number\t\t\t\t\t\t: {1:d}'.format(
              index, page_number))
      print(u'')

  def Close(self):
    """Closes the mappings file."""
    if self._file_object_opened_in_object:
      self._file_object.close()
    self._file_object = None

  def Open(self, filename):
    """Opens the mappings file.

    Args:
      filename: a string containing the filename.
    """
    stat_object = os.stat(filename)
    self._file_size = stat_object.st_size

    self._file_object = open(filename, 'rb')
    self._file_object_opened_in_object = True

    self._ReadFileHeader()
    self._ReadMappings(mappings_reference=u'data')
    self._ReadUnknownEntries()
    self._ReadFileFooter()

    self._ReadFileHeader()
    self._ReadMappings(mappings_reference=u'index')
    self._ReadUnknownEntries()
    self._ReadFileFooter()


class ObjectsDataFile(object):
  """Class that contains an objects data (Objects.data) file."""

  _PAGE_SIZE = 8192

  _OBJECT_DESCRIPTOR = construct.Struct(
      u'object_descriptor',
      construct.ULInt32(u'identifier'),
      construct.ULInt32(u'object_record_data_offset'),
      construct.ULInt32(u'object_record_data_size'),
      construct.ULInt32(u'object_record_data_checksum'))

  _EMPTY_OBJECT_DESCRIPTOR = b'\x00' * _OBJECT_DESCRIPTOR.sizeof()

  def __init__(self, debug=False):
    """Initializes the objects data file object.

    Args:
      debug: optional boolean value to indicate if debug information should
             be printed.
    """
    super(ObjectsDataFile, self).__init__()
    self._debug = debug
    self._file_object = None
    self._file_object_opened_in_object = False
    self._file_size = 0

    self._object_descriptors = []

  def _ReadPage(self, file_offset):
    """Reads a page.

    Args:
      file_offset: integer containing the offset of the page relative
                   from the start of the file.

    Raises:
      IOError: if the page cannot be read.
    """
    # TODO: implement

  def _ReadObjectDescriptors(self, file_offset):
    """Reads an object descriptor.

    Args:
      file_offset: integer containing the offset of the page relative
                   from the start of the file.

    Raises:
      IOError: if the object descriptors cannot be read.
    """
    page_offset = 0

    while page_offset < self._PAGE_SIZE:
      object_descriptor_data = self._file_object.read(
          self._OBJECT_DESCRIPTOR.sizeof())

      if self._debug:
        print(u'Object descriptor data:')
        print(hexdump.Hexdump(object_descriptor_data))

      page_offset += self._OBJECT_DESCRIPTOR.sizeof()

      if object_descriptor_data == self._EMPTY_OBJECT_DESCRIPTOR:
        break

      try:
        object_descriptor_struct = self._OBJECT_DESCRIPTOR.parse(
            object_descriptor_data)
      except construct.FieldError as exception:
        raise IOError((
            u'Unable to parse object descriptor at offset: 0x{0:08x} '
            u'with error: {1:s}').format(file_offset, exception))

      # TODO: add debug print

    # TODO: implement
    _ = object_descriptor_struct

  def Close(self):
    """Closes the objects data file."""
    if self._file_object_opened_in_object:
      self._file_object.close()
    self._file_object = None

  def Open(self, filename):
    """Opens the objects data file.

    Args:
      filename: a string containing the filename.
    """
    stat_object = os.stat(filename)
    self._file_size = stat_object.st_size

    self._file_object = open(filename, 'rb')
    self._file_object_opened_in_object = True

    if self._debug:
      file_offset = 0
      while file_offset < self._file_size:
        self._ReadPage(file_offset)
        file_offset += self._PAGE_SIZE


class CIMRepository(object):
  """Class that contains a CIM repository."""

  _MAPPING_VER = construct.ULInt32(u'active_mapping_file')

  def __init__(self, debug=False):
    """Initializes the CIM repository object.

    Args:
      debug: optional boolean value to indicate if debug information should
             be printed.
    """
    super(CIMRepository, self).__init__()
    self._debug = debug
    self._index_binary_tree_file = None
    self._index_mapping_file = None
    self._objects_mapping_file = None

  def _GetCurrentMappingFile(self, path):
    """Retrieves the current mapping file.

    Args:
      path: a string containing the path to the CIM repository.
    """
    mapping_file_glob = glob.glob(
        os.path.join(path, u'[Mm][Aa][Pp][Pp][Ii][Nn][Gg].[Vv][Ee][Rr]'))

    active_mapping_file = 0
    if mapping_file_glob:
      with open(mapping_file_glob[0], 'rb') as file_object:
        try:
          active_mapping_file = self._MAPPING_VER.parse_stream(file_object)
        except construct.FieldError as exception:
          raise IOError(
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

      mapping_file = MappingFile(debug=self._debug)
      mapping_file.Open(mapping_file_path)

    self._mapping_file = mapping_file

    # TODO: use index and objects map instead?
    index_mapping_file_path = glob.glob(
        os.path.join(path, u'[Ii][Nn][Dd][Ee][Xx].[Mm][Aa][Pp]'))[0]

    if self._debug:
      print(u'Reading: {0:s}'.format(index_mapping_file_path))

    self._index_mapping_file = MappingFile(debug=self._debug)
    self._index_mapping_file.Open(index_mapping_file_path)

    objects_mapping_file_path = glob.glob(
        os.path.join(path, u'[Oo][Bb][Jj][Ee][Cc][Tt][Ss].[Mm][Aa][Pp]'))[0]

    if self._debug:
      print(u'Reading: {0:s}'.format(objects_mapping_file_path))

    self._index_mapping_file = MappingFile(debug=self._debug)
    self._index_mapping_file.Open(objects_mapping_file_path)

  def Close(self):
    """Closes the CIM repository."""
    self._index_mapping_file.Close()
    self._index_mapping_file = None

    self._index_binary_tree_file.Close()
    self._index_binary_tree_file = None

    self._objects_mapping_file.Close()
    self._objects_mapping_file = None

    self._objects_data_file.Close()
    self._objects_data_file = None

    self._mapping_file.Close()
    self._mapping_file = None

  def GetKeys(self):
    """Retrieves the keys.

    Yields:
      A string containing the CIM key.
    """
    if not self._index_binary_tree_file or not self._mapping_file:
      return

    page_number = self._mapping_file.mappings[u'index'][0]
    index_page = self._index_binary_tree_file.GetPage(page_number)

  def Open(self, path):
    """Opens the CIM repository.

    Args:
      path: a string containing the path to the CIM repository.
    """
    self._GetCurrentMappingFile(path)

    index_binary_tree_file_path = glob.glob(
        os.path.join(path, u'[Ii][Nn][Dd][Ee][Xx].[Bb][Tt][Rr]'))[0]
    objects_data_file_path = glob.glob(
        os.path.join(path, u'[Oo][Bb][Jj][Ee][Cc][Tt][Ss].[Da][Aa][Tt][Aa]'))[0]

    if self._debug:
      print(u'Reading: {0:s}'.format(index_binary_tree_file_path))

    self._index_binary_tree_file = IndexBinaryTreeFile(debug=self._debug)
    self._index_binary_tree_file.Open(index_binary_tree_file_path)

    if self._debug:
      print(u'Reading: {0:s}'.format(objects_data_file_path))

    self._objects_data_file = ObjectsDataFile(debug=self._debug)
    self._objects_data_file.Open(objects_data_file_path)


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

  cim_repository = CIMRepository(debug=options.debug)

  cim_repository.Open(options.source)
  cim_repository.GetKeys()
  cim_repository.Close()

  return True


if __name__ == '__main__':
  if not Main():
    sys.exit(1)
  else:
    sys.exit(0)
