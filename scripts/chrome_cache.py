#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Script to parse Chrome Cache files."""

from __future__ import print_function
import argparse
import datetime
import logging
import os
import sys

from dtfabric import errors as dtfabric_errors
from dtfabric import fabric as dtfabric_fabric

import hexdump


class ParseError(Exception):
  """Error that is raised when data cannot be parsed."""


def SuperFastHash(key):
  """Function to calculate the super fast hash.

  Args:
    key (bytes): key for which to calculate the hash.

  Returns:
    int: hash of the key.
  """
  if not key:
    return 0

  key_length = len(key)
  hash_value = key_length & 0xffffffff
  remainder = key_length & 0x00000003
  key_length -= remainder

  for key_index in xrange(0, key_length, 4):
    hash_value = (
        (hash_value + ord(key[key_index]) + (ord(key[key_index + 1]) << 8)) &
        0xffffffff)

    temp_value = ord(key[key_index + 2]) + (ord(key[key_index + 3]) << 8)

    temp_value = ((temp_value << 11) & 0xffffffff) ^ hash_value
    hash_value = ((hash_value << 16) & 0xffffffff) ^ temp_value

    hash_value = (hash_value + (hash_value >> 11)) & 0xffffffff

  key_index = key_length

  if remainder == 3:
    hash_value = (
        (hash_value + ord(key[key_index]) + (ord(key[key_index + 1]) << 8)) &
        0xffffffff)
    hash_value ^= (hash_value << 16) & 0xffffffff
    hash_value ^= (ord(key[key_index + 2]) << 18) & 0xffffffff
    hash_value = (hash_value + (hash_value >> 11)) & 0xffffffff

  elif remainder == 2:
    hash_value = (
        (hash_value + ord(key[key_index]) + (ord(key[key_index + 1]) << 8)) &
        0xffffffff)
    hash_value ^= (hash_value << 11) & 0xffffffff
    hash_value = (hash_value + (hash_value >> 17)) & 0xffffffff

  elif remainder == 1:
    hash_value = (hash_value + ord(key[key_index])) & 0xffffffff
    hash_value ^= (hash_value << 10) & 0xffffffff
    hash_value = (hash_value + (hash_value >> 1)) & 0xffffffff

  # Force "avalanching" of final 127 bits.
  hash_value ^= (hash_value << 3) & 0xffffffff
  hash_value = (hash_value + (hash_value >> 5)) & 0xffffffff
  hash_value ^= (hash_value << 4) & 0xffffffff
  hash_value = (hash_value + (hash_value >> 17)) & 0xffffffff
  hash_value ^= (hash_value << 25) & 0xffffffff
  hash_value = (hash_value + (hash_value >> 6)) & 0xffffffff

  return hash_value


class CacheAddress(object):
  """Class that contains a cache address.

  Attributes:
    block_number (int): block data file number.
    block_offset (int): offset within the block data file.
    block_size (int): block size.
    filename (str): name of the block data file.
    value (int): cache address.
  """
  FILE_TYPE_SEPARATE = 0
  FILE_TYPE_BLOCK_RANKINGS = 1
  FILE_TYPE_BLOCK_256 = 2
  FILE_TYPE_BLOCK_1024 = 3
  FILE_TYPE_BLOCK_4096 = 4

  _BLOCK_DATA_FILE_TYPES = [
      FILE_TYPE_BLOCK_RANKINGS,
      FILE_TYPE_BLOCK_256,
      FILE_TYPE_BLOCK_1024,
      FILE_TYPE_BLOCK_4096]

  _FILE_TYPE_DESCRIPTIONS = [
      u'Separate file',
      u'Rankings block file',
      u'256 byte block file',
      u'1024 byte block file',
      u'4096 byte block file']

  _FILE_TYPE_BLOCK_SIZES = [0, 36, 256, 1024, 4096]

  def __init__(self, cache_address):
    """Initializes a cache address object.

    Args:
      cache_address (int): cache address.
    """
    super(CacheAddress, self).__init__()
    self.block_number = None
    self.block_offset = None
    self.block_size = None
    self.filename = None
    self.value = cache_address

    if cache_address & 0x80000000:
      self.is_initialized = u'True'
    else:
      self.is_initialized = u'False'

    self.file_type = (cache_address & 0x70000000) >> 28
    if not cache_address == 0x00000000:
      if self.file_type == self.FILE_TYPE_SEPARATE:
        file_selector = cache_address & 0x0fffffff
        self.filename = u'f_{0:06x}'.format(file_selector)

      elif self.file_type in self._BLOCK_DATA_FILE_TYPES:
        file_selector = (cache_address & 0x00ff0000) >> 16
        self.filename = u'data_{0:d}'.format(file_selector)

        file_block_size = self._FILE_TYPE_BLOCK_SIZES[self.file_type]
        self.block_number = cache_address & 0x0000ffff
        self.block_size = (cache_address & 0x03000000) >> 24
        self.block_size *= file_block_size
        self.block_offset = 8192 + (self.block_number * file_block_size)

  def GetDebugString(self):
    """Retrieves a debug string of the cache address object.

    Return:
      str: debug string of the cache address object.
    """
    if self.file_type <= 4:
      file_type_description = self._FILE_TYPE_DESCRIPTIONS[self.file_type]
    else:
      file_type_description = u'Unknown'

    if self.value == 0x00000000:
      return u'0x{0:08x} (uninitialized)'.format(self.value)

    if self.file_type == 0:
      return (
          u'0x{0:08x} (initialized: {1:s}, file type: {2:s}, '
          u'filename: {3:s})').format(
              self.value, self.is_initialized, file_type_description,
              self.filename)

    # TODO: print reserved bits.
    return (
        u'0x{0:08x} (initialized: {1:s}, file type: {2:s}, '
        u'filename: {3:s}, block number: {4:d}, block offset: 0x{5:08x}, '
        u'block size: {6:d})').format(
            self.value, self.is_initialized, file_type_description,
            self.filename, self.block_number, self.block_offset,
            self.block_size)


class CacheEntry(object):
  """Class that contains a cache entry.

  Attributes:
    creation_time (int): creation time, in number of micro seconds since
        January 1, 1970, 00:00:00 UTC.
    hash (int): super fast hash of the key.
    key (byte): data of the key.
    next (int): cache address of the next cache entry.
    rankings_node (int): cache address of the rankings node.
  """

  def __init__(self):
    """Initializes a cache entry object."""
    super(CacheEntry, self).__init__()
    self.creation_time = None
    self.hash = None
    self.key = None
    self.next = None
    self.rankings_node = None


class IndexFile(object):
  """Class that contains an index file."""

  SIGNATURE = 0xc103cac3

  _DATA_TYPE_FABRIC_DEFINITION = b'\n'.join([
      b'name: byte',
      b'type: integer',
      b'attributes:',
      b'  format: unsigned',
      b'  size: 1',
      b'  units: bytes',
      b'---',
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
      b'name: uint64',
      b'type: integer',
      b'attributes:',
      b'  format: unsigned',
      b'  size: 8',
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
      b'name: chrome_cache_index_file_header',
      b'type: structure',
      b'attributes:',
      b'  byte_order: little-endian',
      b'members:',
      b'- name: signature',
      b'  data_type: uint32',
      b'- name: minor_version',
      b'  data_type: uint16',
      b'- name: major_version',
      b'  data_type: uint16',
      b'- name: number_of_entries',
      b'  data_type: uint32',
      b'- name: stored_data_size',
      b'  data_type: uint32',
      b'- name: last_created_file_number',
      b'  data_type: uint32',
      b'- name: unknown1',
      b'  data_type: uint32',
      b'- name: unknown2',
      b'  data_type: uint32',
      b'- name: table_size',
      b'  data_type: uint32',
      b'- name: unknown3',
      b'  data_type: uint32',
      b'- name: unknown4',
      b'  data_type: uint32',
      b'- name: creation_time',
      b'  data_type: uint64',
      b'- name: unknown5',
      b'  type: sequence',
      b'  element_data_type: byte',
      b'  number_of_elements: 208',
      b'---',
      b'name: chrome_cache_index_file_lru_data',
      b'type: structure',
      b'attributes:',
      b'  byte_order: little-endian',
      b'members:',
      b'- name: unknown1',
      b'  type: sequence',
      b'  element_data_type: byte',
      b'  number_of_elements: 8',
      b'- name: filled_flag',
      b'  data_type: uint32',
      b'- name: sizes',
      b'  type: sequence',
      b'  element_data_type: uint32',
      b'  number_of_elements: 5',
      b'- name: head_addresses',
      b'  type: sequence',
      b'  element_data_type: uint32',
      b'  number_of_elements: 5',
      b'- name: tail_addresses',
      b'  type: sequence',
      b'  element_data_type: uint32',
      b'  number_of_elements: 5',
      b'- name: transaction_address',
      b'  data_type: uint32',
      b'- name: operation',
      b'  data_type: uint32',
      b'- name: operation_list',
      b'  data_type: uint32',
      b'- name: unknown2',
      b'  type: sequence',
      b'  element_data_type: byte',
      b'  number_of_elements: 28',
  ])

  _DATA_TYPE_FABRIC = dtfabric_fabric.DataTypeFabric(
      yaml_definition=_DATA_TYPE_FABRIC_DEFINITION)

  _UINT32LE = _DATA_TYPE_FABRIC.CreateDataTypeMap(u'uint32le')

  _FILE_HEADER = _DATA_TYPE_FABRIC.CreateDataTypeMap(
      u'chrome_cache_index_file_header')

  _FILE_HEADER_SIZE = _FILE_HEADER.GetByteSize()

  _LRU_DATA = _DATA_TYPE_FABRIC.CreateDataTypeMap(
      u'chrome_cache_index_file_lru_data')

  _LRU_DATA_SIZE = _LRU_DATA.GetByteSize()

  def __init__(self, debug=False):
    """Initializes the index file object.

    Args:
      debug (Optional[bool]): True if debug information should be printed.
    """
    super(IndexFile, self).__init__()
    self._debug = debug
    self._file_object = None
    self._file_object_opened_in_object = False

    self.creation_time = None
    self.version = None
    self.index_table = {}

  def _DebugPrintData(self, description, data):
    """Prints data debug information.

    Args:
      description (str): description.
      data (bytes): data.
    """
    print(u'{0:s}:'.format(description))
    print(hexdump.Hexdump(data))

  def _DebugPrintHeader(self, file_header):
    """Prints header debug information.

    Args:
      file_header (chrome_cache_index_file_header): file header.
    """
    value_string = u'0x{0:08x}'.format(file_header.signature)
    self._DebugPrintValue(u'Signature', value_string)

    value_string = u'{0:d}'.format(file_header.major_version)
    self._DebugPrintValue(u'Major version', value_string)

    value_string = u'{0:d}'.format(file_header.minor_version)
    self._DebugPrintValue(u'Minor version', value_string)

    value_string = u'{0:d}'.format(file_header.number_of_entries)
    self._DebugPrintValue(u'Number of entries', value_string)

    value_string = u'{0:d}'.format(file_header.stored_data_size)
    self._DebugPrintValue(u'Stored data size', value_string)

    value_string = u'f_{0:06x}'.format(file_header.last_created_file_number)
    self._DebugPrintValue(u'Last created file number', value_string)

    value_string = u'0x{0:08x}'.format(file_header.unknown1)
    self._DebugPrintValue(u'Unknown1', value_string)

    value_string = u'0x{0:08x}'.format(file_header.unknown2)
    self._DebugPrintValue(u'Unknown2', value_string)

    value_string = u'{0:d}'.format(file_header.table_size)
    self._DebugPrintValue(u'Table size', value_string)

    value_string = u'0x{0:08x}'.format(file_header.unknown3)
    self._DebugPrintValue(u'Unknown3', value_string)

    value_string = u'0x{0:08x}'.format(file_header.unknown4)
    self._DebugPrintValue(u'Unknown4', value_string)

    date_string = (
        datetime.datetime(1601, 1, 1) +
        datetime.timedelta(microseconds=file_header.creation_time))

    value_string = u'{0!s} (0x{1:08x})'.format(
        date_string, file_header.creation_time)
    self._DebugPrintValue(u'Creation time', value_string)

    print(u'')

  def _DebugPrintValue(self, description, value):
    """Prints a value debug information.

    Args:
      description (str): description.
      value (object): value.
    """
    alignment = 8 - (len(description) / 8) + 1
    text = u'{0:s}{1:s}: {2!s}'.format(description, u'\t' * alignment, value)
    print(text)

  def _ReadFileHeader(self):
    """Reads the file header.

    Raises:
      ParseError: if the file header cannot be read.
    """
    if self._debug:
      print(u'Seeking file header offset: 0x{0:08x}'.format(0))

    self._file_object.seek(0, os.SEEK_SET)

    file_header_data = self._file_object.read(self._FILE_HEADER_SIZE)

    if self._debug:
      self._DebugPrintData(u'Index file header data', file_header_data)

    try:
      file_header = self._FILE_HEADER.MapByteStream(file_header_data)
    except dtfabric_errors.MappingError as exception:
      raise ParseError(u'Unable to parse file header with error: {0!s}'.format(
          exception))

    if file_header.signature != self.SIGNATURE:
      raise ParseError(u'Unsupported index file signature: 0x{0:08x}'.format(
          file_header.signature))

    self.version = u'{0:d}.{1:d}'.format(
        file_header.major_version, file_header.minor_version)

    if self.version not in (u'2.0', u'2.1'):
      raise ParseError(u'Unsupported index file version: {0:s}'.format(
          self.version))

    self.creation_time = file_header.creation_time

    if self._debug:
      self._DebugPrintHeader(file_header)

  def _ReadLRUData(self):
    """Reads the LRU data.

    Raises:
      ParseError: if the LRU data cannot be read.
    """
    lru_data = self._file_object.read(self._LRU_DATA_SIZE)

    if self._debug:
      self._DebugPrintData(u'Index file LRU data', lru_data)

    try:
      index_file_lru = self._LRU_DATA.MapByteStream(lru_data)
    except dtfabric_errors.MappingError as exception:
      raise ParseError(u'Unable to parse LRU data with error: {0!s}'.format(
          exception))

    if self._debug:
      print(u'Filled flag\t\t\t\t\t\t\t\t: 0x{0:08x}'.format(
          index_file_lru.filled_flag))

      for value in index_file_lru.sizes:
        print(u'Size\t\t\t\t\t\t\t\t\t: {0:d}'.format(value))

      cache_address_index = 0
      for value in index_file_lru.head_addresses:
        cache_address = CacheAddress(value)
        print(u'Head address: {0:d}\t\t\t\t\t\t\t\t: {1:s}'.format(
            cache_address_index, cache_address.GetDebugString()))
        cache_address_index += 1

      cache_address_index = 0
      for value in index_file_lru.tail_addresses:
        cache_address = CacheAddress(value)
        print(u'Tail address: {0:d}\t\t\t\t\t\t\t\t: {1:s}'.format(
            cache_address_index, cache_address.GetDebugString()))
        cache_address_index += 1

      cache_address = CacheAddress(index_file_lru.transaction_address)
      print(u'Transaction address\t\t\t\t\t\t\t: {0:s}'.format(
          cache_address.GetDebugString()))

      value_string = u'0x{0:08x}'.format(index_file_lru.operation)
      print(u'Operation\t\t\t\t\t\t\t\t: {0:s}'.format(value_string))

      value_string = u'0x{0:08x}'.format(index_file_lru.operation_list)
      print(u'Operation list\t\t\t\t\t\t\t\t: {0:s}'.format(value_string))

      print(u'')

  def _ReadIndexTable(self):
    """Reads the index table.

    Raises:
      ParseError: if the index table cannot be read.
    """
    cache_address_index = 0
    cache_address_data = self._file_object.read(4)

    while len(cache_address_data) == 4:
      try:
        value = self._UINT32LE.MapByteStream(cache_address_data)
      except dtfabric_errors.MappingError as exception:
        raise ParseError((
            u'Unable to parse index table entry: {0:d} with error: '
            u'{1:s}').format(cache_address_index, exception))

      if value:
        cache_address = CacheAddress(value)

        if self._debug:
          print(u'Cache address: {0:d}\t\t\t\t\t\t\t: {1:s}'.format(
              cache_address_index, cache_address.GetDebugString()))

        self.index_table[cache_address_index] = cache_address

      cache_address_index += 1
      cache_address_data = self._file_object.read(4)

    if self._debug:
      print(u'')

  def Close(self):
    """Closes the index file."""
    if self._file_object_opened_in_object:
      self._file_object.close()
    self._file_object = None

  def Open(self, filename):
    """Opens the index file.

    Args:
      filename (str): path of the file.
    """
    self._file_object = open(filename, 'rb')
    self._file_object_opened_in_object = True
    self._ReadFileHeader()
    self._ReadLRUData()
    self._ReadIndexTable()

  def OpenFileObject(self, file_object):
    """Opens the index file-like object.

    Args:
      file_object (file): file-like object.
    """
    self._file_object = file_object
    self._file_object_opened_in_object = False
    self._ReadFileHeader()
    self._ReadLRUData()
    self._ReadIndexTable()


class DataBlockFile(object):
  """Class that contains a data block file."""

  SIGNATURE = 0xc104cac3

  _DATA_TYPE_FABRIC_DEFINITION = b'\n'.join([
      b'name: byte',
      b'type: integer',
      b'attributes:',
      b'  format: unsigned',
      b'  size: 1',
      b'  units: bytes',
      b'---',
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
      b'name: uint64',
      b'type: integer',
      b'attributes:',
      b'  format: unsigned',
      b'  size: 8',
      b'  units: bytes',
      b'---',
      b'name: chrome_cache_data_file_header',
      b'type: structure',
      b'attributes:',
      b'  byte_order: little-endian',
      b'members:',
      b'- name: signature',
      b'  data_type: uint32',
      b'- name: minor_version',
      b'  data_type: uint16',
      b'- name: major_version',
      b'  data_type: uint16',
      b'- name: file_number',
      b'  data_type: uint16',
      b'- name: next_file_number',
      b'  data_type: uint16',
      b'- name: block_size',
      b'  data_type: uint32',
      b'- name: number_of_entries',
      b'  data_type: uint32',
      b'- name: maximum_number_of_entries',
      b'  data_type: uint32',
      b'- name: emtpy',
      b'  type: sequence',
      b'  element_data_type: uint32',
      b'  number_of_elements: 4',
      b'- name: hints',
      b'  type: sequence',
      b'  element_data_type: uint32',
      b'  number_of_elements: 4',
      b'- name: updating',
      b'  data_type: uint32',
      b'- name: user',
      b'  type: sequence',
      b'  element_data_type: uint32',
      b'  number_of_elements: 5',
      b'- name: allocation_bitmap',
      b'  type: sequence',
      b'  element_data_type: uint32',
      b'  number_of_elements: 2028',
      b'---',
      b'name: chrome_cache_entry',
      b'type: structure',
      b'attributes:',
      b'  byte_order: little-endian',
      b'members:',
      b'- name: hash',
      b'  data_type: uint32',
      b'- name: next_address',
      b'  data_type: uint32',
      b'- name: rankings_node_address',
      b'  data_type: uint32',
      b'- name: reuse_count',
      b'  data_type: uint32',
      b'- name: refetch_count',
      b'  data_type: uint32',
      b'- name: state',
      b'  data_type: uint32',
      b'- name: creation_time',
      b'  data_type: uint64',
      b'- name: key_size',
      b'  data_type: uint32',
      b'- name: long_key_address',
      b'  data_type: uint32',
      b'- name: data_stream_sizes',
      b'  type: sequence',
      b'  element_data_type: uint32',
      b'  number_of_elements: 4',
      b'- name: data_stream_addresses',
      b'  type: sequence',
      b'  element_data_type: uint32',
      b'  number_of_elements: 4',
      b'- name: flags',
      b'  data_type: uint32',
      b'- name: unknown1',
      b'  type: sequence',
      b'  element_data_type: byte',
      b'  number_of_elements: 16',
      b'- name: self_hash',
      b'  data_type: uint32',
      b'- name: key',
      b'  type: sequence',
      b'  element_data_type: byte',
      b'  number_of_elements: 160',
  ])

  _DATA_TYPE_FABRIC = dtfabric_fabric.DataTypeFabric(
      yaml_definition=_DATA_TYPE_FABRIC_DEFINITION)

  # TODO: update emtpy, hints, updating and user.

  _FILE_HEADER = _DATA_TYPE_FABRIC.CreateDataTypeMap(
      u'chrome_cache_data_file_header')

  _FILE_HEADER_SIZE = _FILE_HEADER.GetByteSize()

  _CACHE_ENTRY = _DATA_TYPE_FABRIC.CreateDataTypeMap(
      u'chrome_cache_entry')

  _CACHE_ENTRY_SIZE = _CACHE_ENTRY.GetByteSize()

  def __init__(self, debug=False):
    """Initializes the data block file object.

    Args:
      debug (Optional[bool]): True if debug information should be printed.
    """
    super(DataBlockFile, self).__init__()
    self._debug = debug
    self._file_object = None
    self._file_object_opened_in_object = False

    self.creation_time = None
    self.block_size = None
    self.number_of_entries = None
    self.version = None

  def _DebugPrintData(self, description, data):
    """Prints data debug information.

    Args:
      description (str): description.
      data (bytes): data.
    """
    print(u'{0:s}:'.format(description))
    print(hexdump.Hexdump(data))

  def _DebugPrintHeader(self, file_header):
    """Prints header debug information.

    Args:
      file_header (chrome_cache_data_file_header): file header.
    """
    value_string = u'0x{0:08x}'.format(file_header.signature)
    print(u'Signature\t\t\t\t\t\t\t\t: {0:s}'.format(value_string))

    value_string = u'{0:d}'.format(file_header.major_version)
    print(u'Major version\t\t\t\t\t\t\t\t: {0:s}'.format(value_string))

    value_string = u'{0:d}'.format(file_header.minor_version)
    print(u'Minor version\t\t\t\t\t\t\t\t: {0:s}'.format(value_string))

    value_string = u'{0:d}'.format(file_header.file_number)
    print(u'File number\t\t\t\t\t\t\t\t: {0:s}'.format(value_string))

    value_string = u'{0:d}'.format(file_header.next_file_number)
    print(u'Next file number\t\t\t\t\t\t\t: {0:s}'.format(value_string))

    value_string = u'{0:d}'.format(file_header.block_size)
    print(u'Block size\t\t\t\t\t\t\t\t: {0:s}'.format(value_string))

    value_string = u'{0:d}'.format(file_header.number_of_entries)
    print(u'Number of entries\t\t\t\t\t\t\t: {0:s}'.format(value_string))

    value_string = u'{0:d}'.format(file_header.maximum_number_of_entries)
    print(u'Maximum number of entries\t\t\t\t\t\t: {0:s}'.format(value_string))

  def _ReadFileHeader(self):
    """Reads the file header.

    Raises:
      ParseError: if the file header cannot be read.
    """
    if self._debug:
      print(u'Seeking file header offset: 0x{0:08x}'.format(0))

    self._file_object.seek(0, os.SEEK_SET)

    file_header_data = self._file_object.read(self._FILE_HEADER_SIZE)

    if self._debug:
      self._DebugPrintData(u'Data block file header data', file_header_data)

    try:
      file_header = self._FILE_HEADER.MapByteStream(file_header_data)
    except dtfabric_errors.MappingError as exception:
      raise ParseError(u'Unable to parse file header with error: {0!s}'.format(
          exception))

    if file_header.signature != self.SIGNATURE:
      raise ParseError(
          u'Unsupported data block file signature: 0x{0:08x}'.format(
              file_header.signature))

    self.version = u'{0:d}.{1:d}'.format(
        file_header.major_version, file_header.minor_version)

    if self.version not in (u'2.0', u'2.1'):
      raise ParseError(u'Unsupported data block file version: {0:s}'.format(
          self.version))

    self.block_size = file_header.block_size
    self.number_of_entries = file_header.number_of_entries

    if self._debug:
      self._DebugPrintHeader(file_header)

      # TODO: print empty, hints, updating and user.

      block_number = 0
      block_range_start = 0
      block_range_end = 0
      in_block_range = False
      for value_32bit in file_header.get(u'allocation_bitmap'):
        for unused_bit in range(0, 32):
          if value_32bit & 0x00000001:
            if not in_block_range:
              block_range_start = block_number
              block_range_end = block_number
              in_block_range = True

            block_range_end += 1

          elif in_block_range:
            in_block_range = False

            if self._debug:
              print(u'Block range\t: {0:d} - {1:d} ({2:d})'.format(
                  block_range_start, block_range_end,
                  block_range_end - block_range_start))

          value_32bit >>= 1
          block_number += 1

      print(u'')

  def ReadCacheEntry(self, block_offset):
    """Reads a cache entry.

    Args:
      block_offset (int): offset of the block that contains the cache entry.

    Raises:
      ParseError: if the cache entry cannot be read.
    """
    if self._debug:
      print(u'Seeking cache entry offset: 0x{0:08x}'.format(block_offset))

    self._file_object.seek(block_offset, os.SEEK_SET)

    cache_entry_data = self._file_object.read(self._CACHE_ENTRY_SIZE)

    if self._debug:
      self._DebugPrintData(
          u'Data block file cache entry data', cache_entry_data)

    try:
      cache_entry_tuple = self._CACHE_ENTRY.MapByteStream(cache_entry_data)
    except dtfabric_errors.MappingError as exception:
      raise ParseError(u'Unable to parse cache entry with error: {0!s}'.format(
          exception))

    cache_entry = CacheEntry()

    cache_entry.hash = cache_entry_tuple.hash

    cache_entry.next = CacheAddress(cache_entry_tuple.next_address)
    cache_entry.rankings_node = CacheAddress(
        cache_entry_tuple.rankings_node_address)

    cache_entry.creation_time = cache_entry_tuple.creation_time

    byte_array = cache_entry_tuple.key
    byte_string = b''.join(map(chr, byte_array))
    cache_entry.key, _, _ = byte_string.partition(b'\x00')

    if self._debug:
      value_string = u'0x{0:08x}'.format(cache_entry.hash)
      print(u'Hash\t\t\t\t\t\t\t\t\t: {0:s}'.format(value_string))

      print(u'Next address\t\t\t\t\t\t\t\t: {0:s}'.format(
          cache_entry.next.GetDebugString()))

      print(u'Rankings node address\t\t\t\t\t\t\t: {0:s}'.format(
          cache_entry.rankings_node.GetDebugString()))

      value_string = u'{0:d}'.format(cache_entry_tuple.reuse_count)
      print(u'Reuse count\t\t\t\t\t\t\t\t: {0:s}'.format(value_string))

      value_string = u'{0:d}'.format(cache_entry_tuple.refetch_count)
      print(u'Refetch count\t\t\t\t\t\t\t\t: {0:s}'.format(value_string))

      value_string = u'0x{0:08x}'.format(cache_entry_tuple.state)
      print(u'State\t\t\t\t\t\t\t\t\t: {0:s}'.format(value_string))

      date_string = (datetime.datetime(1601, 1, 1) +
                     datetime.timedelta(microseconds=cache_entry.creation_time))

      value_string = u'{0!s} (0x{1:08x})'.format(
          date_string, cache_entry.creation_time)
      print(u'Creation time\t\t\t\t\t\t\t\t: {0:s}'.format(value_string))

      for value in cache_entry_tuple.data_stream_sizes:
        value_string = u'{0:d}'.format(value)
        print(u'Data stream size\t\t\t\t\t\t\t: {0:s}'.format(value_string))

      cache_address_index = 0
      for value in cache_entry_tuple.data_stream_addresses:
        cache_address = CacheAddress(value)
        print(u'Data stream address: {0:d}\t\t\t\t\t\t\t: {1:s}'.format(
            cache_address_index, cache_address.GetDebugString()))
        cache_address_index += 1

      print(u'Flags\t\t\t\t\t\t\t\t\t: 0x{0:08x}'.format(
          cache_entry_tuple.flags))

      print(u'Self hash\t\t\t\t\t\t\t\t: 0x{0:08x}'.format(
          cache_entry_tuple.self_hash))

      try:
        cache_entry_key = cache_entry.key.decode(u'ascii')
      except UnicodeDecodeError:
        logging.warning((
            u'Unable to decode cache entry key at cache address: '
            u'0x{0:08x}. Characters that cannot be decoded will be '
            u'replaced with "?" or "\\ufffd".').format(cache_address.value))
        cache_entry_key = cache_entry.key.decode(u'ascii', errors=u'replace')

      print(u'Key\t\t\t\t\t\t\t\t\t: {0:s}'.format(cache_entry_key))

      # TODO: calculate and verify hash.

      print(u'')

    return cache_entry

  def Close(self):
    """Closes the data block file."""
    if self._file_object_opened_in_object:
      self._file_object.close()
    self._file_object = None

  def Open(self, filename):
    """Opens the data block file.

    Args:
      filename (str): path of the file.
    """
    self._file_object = open(filename, 'rb')
    self._file_object_opened_in_object = True
    self._ReadFileHeader()

  def OpenFileObject(self, file_object):
    """Opens the data block file.

    Args:
      file_object (file): file-like object.
    """
    self._file_object = file_object
    self._file_object_opened_in_object = False
    self._ReadFileHeader()


class ChromeCacheParser(object):
  """Chrome Cache parser."""

  _DATA_TYPE_FABRIC_DEFINITION = b'\n'.join([
      b'name: uint32le',
      b'type: integer',
      b'attributes:',
      b'  byte_order: little-endian',
      b'  format: unsigned',
      b'  size: 4',
      b'  units: bytes'])

  _DATA_TYPE_FABRIC = dtfabric_fabric.DataTypeFabric(
      yaml_definition=_DATA_TYPE_FABRIC_DEFINITION)

  _UINT32LE = _DATA_TYPE_FABRIC.CreateDataTypeMap(u'uint32le')

  _UINT32LE_SIZE = _UINT32LE.GetByteSize()

  def __init__(self, debug=False):
    """Initializes a Chrome Cache parser.

    Args:
      debug (Optional[bool]): True if debug information should be printed.
    """
    super(ChromeCacheParser, self).__init__()
    self._debug = debug

  def ParseDirectory(self, path):
    """Parses a Chrome Cache directory.

    Args:
      path (str): path of the directory.

    Raises:
      ParseError: if the directory cannot be read.
    """
    index_file_path = os.path.join(path, u'index')
    if not os.path.exists(index_file_path):
      raise ParseError(u'Missing index file: {0:s}'.format(index_file_path))

    index_file = IndexFile(debug=self._debug)
    index_file.Open(index_file_path)

    data_block_files = {}
    have_all_data_block_files = True
    for cache_address in iter(index_file.index_table.values()):
      if cache_address.filename not in data_block_files:
        data_block_file_path = os.path.join(path, cache_address.filename)

        if not os.path.exists(data_block_file_path):
          logging.error(u'Missing data block file: {0:s}'.format(
              data_block_file_path))
          have_all_data_block_files = False

        else:
          data_block_file = DataBlockFile(debug=self._debug)
          data_block_file.Open(data_block_file_path)

          data_block_files[cache_address.filename] = data_block_file

    if have_all_data_block_files:
      # TODO: read the cache entries from the data block files
      for cache_address in iter(index_file.index_table.values()):
        cache_address_chain_length = 0
        while cache_address.value != 0x00000000:
          if cache_address_chain_length >= 64:
            logging.error(
                u'Maximum allowed cache address chain length reached.')
            break

          data_file = data_block_files.get(cache_address.filename, None)
          if not data_file:
            logging.warning(
                u'Cache address: 0x{0:08x} missing filename.'.format(
                    cache_address.value))
            break

          # print(u'Cache address\t: {0:s}'.format(
          #     cache_address.GetDebugString()))
          cache_entry = data_file.ReadCacheEntry(cache_address.block_offset)

          try:
            cache_entry_key = cache_entry.key.decode(u'ascii')
          except UnicodeDecodeError:
            logging.warning((
                u'Unable to decode cache entry key at cache address: '
                u'0x{0:08x}. Characters that cannot be decoded will be '
                u'replaced with "?" or "\\ufffd".').format(cache_address.value))
            cache_entry_key = cache_entry.key.decode(
                u'ascii', errors=u'replace')

          # TODO: print(u'Url\t\t: {0:s}'.format(cache_entry_key))
          _ = cache_entry_key

          date_string = (datetime.datetime(1601, 1, 1) + datetime.timedelta(
              microseconds=cache_entry.creation_time))

          # print(u'Creation time\t: {0!s}'.format(date_string))

          # print(u'')

          print(u'{0!s}\t{1:s}'.format(date_string, cache_entry.key))

          cache_address = cache_entry.next
          cache_address_chain_length += 1

    for data_block_file in iter(data_block_files.values()):
      data_block_file.Close()

    index_file.Close()

    if not have_all_data_block_files:
      raise ParseError(u'Missing data block files.')

  def ParseFile(self, path):
    """Parses a Chrome Cache file.

    Args:
      path (str): path of the file.

    Raises:
      ParseError: if the file cannot be read.
    """
    with open(path, 'rb') as file_object:
      signature_data = file_object.read(self._UINT32LE_SIZE)

      try:
        signature = self._UINT32LE.MapByteStream(signature_data)
      except dtfabric_errors.MappingError as exception:
        raise ParseError(u'Unable to signature with error: {0!s}'.format(
            exception))

      if signature == IndexFile.SIGNATURE:
        index_file = IndexFile(debug=self._debug)
        index_file.OpenFileObject(file_object)
        index_file.Close()

      elif signature == DataBlockFile.SIGNATURE:
        data_block_file = DataBlockFile(debug=self._debug)
        data_block_file.OpenFileObject(file_object)
        data_block_file.Close()


def Main():
  """The main program function.

  Returns:
    bool: True if successful or False if not.
  """
  argument_parser = argparse.ArgumentParser(description=(
      u'Extracts information from Chrome Cache files.'))

  argument_parser.add_argument(
      u'-d', u'--debug', dest=u'debug', action=u'store_true', default=False,
      help=u'enable debug output.')

  argument_parser.add_argument(
      u'source', nargs=u'?', action=u'store', metavar=u'PATH',
      default=None, help=u'path of the Chrome Cache file(s).')

  options = argument_parser.parse_args()

  if not options.source:
    print(u'Source file missing.')
    print(u'')
    argument_parser.print_help()
    print(u'')
    return False

  logging.basicConfig(
      level=logging.INFO, format=u'[%(levelname)s] %(message)s')

  parser = ChromeCacheParser(debug=options.debug)

  if os.path.isdir(options.source):
    parser.ParseDirectory(options.source)

  else:
    parser.ParseFile(options.source)

  return True


if __name__ == '__main__':
  if not Main():
    sys.exit(1)
  else:
    sys.exit(0)
