#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Script to parse Windows Jump List files.

Supports:
* .customDestinations-ms

TODO:
* .automaticDestinations-ms
"""

from __future__ import print_function
import argparse
import datetime
import logging
import os
import sys
import uuid

import construct
import pyfwsi
import pylnk
import pyolecf

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


class DataRange(object):
  """Class that implements an in-file data range file-like object."""

  def __init__(self, file_object):
    """Initializes the file-like object.

    Args:
      file_object: the parent file-like object.
    """
    super(DataRange, self).__init__()
    self._current_offset = 0
    self._file_object = file_object
    self._range_offset = 0
    self._range_size = 0

  def SetRange(self, range_offset, range_size):
    """Sets the data range (offset and size).

    The data range is used to map a range of data within one file
    (e.g. a single partition within a full disk image) as a file-like object.

    Args:
      range_offset: the start offset of the data range.
      range_size: the size of the data range.

    Raises:
      ValueError: if the range offset or range size is invalid.
    """
    if range_offset < 0:
      raise ValueError(
          u'Invalid range offset: {0:d} value out of bounds.'.format(
              range_offset))

    if range_size < 0:
      raise ValueError(
          u'Invalid range size: {0:d} value out of bounds.'.format(
              range_size))

    self._range_offset = range_offset
    self._range_size = range_size
    self._current_offset = 0

  # Note: that the following functions do not follow the style guide
  # because they are part of the file-like object interface.

  def read(self, size=None):
    """Reads a byte string from the file-like object at the current offset.

       The function will read a byte string of the specified size or
       all of the remaining data if no size was specified.

    Args:
      size: optional integer value containing the number of bytes to read.
            Default is all remaining data (None).

    Returns:
      A byte string containing the data read.

    Raises:
      IOError: if the read failed.
    """
    if self._range_offset < 0 or self._range_size < 0:
      raise IOError(u'Invalid data range.')

    if self._current_offset < 0:
      raise IOError(
          u'Invalid current offset: {0:d} value less than zero.'.format(
              self._current_offset))

    if self._current_offset >= self._range_size:
      return ''

    if size is None:
      size = self._range_size
    if self._current_offset + size > self._range_size:
      size = self._range_size - self._current_offset

    self._file_object.seek(
        self._range_offset + self._current_offset, os.SEEK_SET)

    data = self._file_object.read(size)

    self._current_offset += len(data)

    return data

  def seek(self, offset, whence=os.SEEK_SET):
    """Seeks an offset within the file-like object.

    Args:
      offset: the offset to seek.
      whence: optional value that indicates whether offset is an absolute
              or relative position within the file. Default is SEEK_SET.

    Raises:
      IOError: if the seek failed.
    """
    if self._current_offset < 0:
      raise IOError(
          u'Invalid current offset: {0:d} value less than zero.'.format(
              self._current_offset))

    if whence == os.SEEK_CUR:
      offset += self._current_offset
    elif whence == os.SEEK_END:
      offset += self._range_size
    elif whence != os.SEEK_SET:
      raise IOError(u'Unsupported whence.')
    if offset < 0:
      raise IOError(u'Invalid offset value less than zero.')
    self._current_offset = offset

  def get_offset(self):
    """Returns the current offset into the file-like object."""
    return self._current_offset

  # Pythonesque alias for get_offset().
  def tell(self):
    """Returns the current offset into the file-like object."""
    return self.get_offset()

  def get_size(self):
    """Returns the size of the file-like object."""
    return self._range_size


class LNKFileEntry(object):
  """Class that contains a LNK file entry.

  Attributes:
    data_size: the size of the LNK file entry data.
    identifier: the LNK file entry identifier.
  """

  def __init__(self, identifier):
    """Initializes the LNK file entry object.

    Args:
      identifier: the LNK file entry identifier.
    """
    super(LNKFileEntry, self).__init__()
    self._lnk_file = pylnk.file()
    self.identifier = identifier
    self.data_size = 0

  def Close(self):
    """Closes the LNK file entry."""
    self._lnk_file.close()

  def GetShellItems(self):
    """Retrieves the shell items.

    Yields:
      A shell item (instance of pyfswi.item).
    """
    if self._lnk_file.link_target_identifier_data:
      shell_item_list = pyfwsi.item_list()
      shell_item_list.copy_from_byte_stream(
          self._lnk_file.link_target_identifier_data)

      for shell_item in shell_item_list.items:
        yield shell_item

  def Open(self, file_object):
    """Opens the LNK file entry.

    Args:
      file_object: the file-like object that contains the LNK file entry data.
    """
    self._lnk_file.open_file_object(file_object)

    # We cannot trust the file size in the LNK data so we get the last offset
    # that was read instead. Because of DataRange the offset will be relative
    # to the start of the LNK data.
    self.data_size = file_object.get_offset()


class AutomaticDestinationsFile(object):
  """Class that contains an .automaticDestinations-ms file.

  Attributes:
    entries: list of the LNK file entries.
    recovered_entries: list of the recovered LNK file entries.
  """

  _DEST_LIST_STREAM_HEADER = construct.Struct(
      u'dest_list_stream_header',
      construct.ULInt32(u'format_version'),
      construct.ULInt32(u'number_of_entries'),
      construct.ULInt32(u'number_of_pinned_entries'),
      construct.LFloat32(u'unknown1'),
      construct.ULInt32(u'last_entry_number'),
      construct.ULInt32(u'unknown2'),
      construct.ULInt32(u'last_revision_number'),
      construct.ULInt32(u'unknown3'))

  _DEST_LIST_STREAM_ENTRY_V1 = construct.Struct(
      u'dest_list_stream_entry_v1',
      construct.ULInt64(u'unknown1'),
      construct.Bytes(u'droid_volume_identifier', 16),
      construct.Bytes(u'droid_file_identifier', 16),
      construct.Bytes(u'birth_droid_volume_identifier', 16),
      construct.Bytes(u'birth_droid_file_identifier', 16),
      construct.String(u'hostname', 16),
      construct.ULInt32(u'entry_number'),
      construct.ULInt32(u'unknown2'),
      construct.LFloat32(u'unknown3'),
      construct.ULInt64(u'last_modification_time'),
      construct.ULInt32(u'pin_status'),
      construct.ULInt16(u'path_size'))

  _DEST_LIST_STREAM_ENTRY_V3 = construct.Struct(
      u'dest_list_stream_entry_v3',
      construct.ULInt64(u'unknown1'),
      construct.Bytes(u'droid_volume_identifier', 16),
      construct.Bytes(u'droid_file_identifier', 16),
      construct.Bytes(u'birth_droid_volume_identifier', 16),
      construct.Bytes(u'birth_droid_file_identifier', 16),
      construct.String(u'hostname', 16),
      construct.ULInt32(u'entry_number'),
      construct.ULInt32(u'unknown2'),
      construct.LFloat32(u'unknown3'),
      construct.ULInt64(u'last_modification_time'),
      construct.ULInt32(u'pin_status'),
      construct.ULInt32(u'unknown4'),
      construct.ULInt32(u'unknown5'),
      construct.ULInt64(u'unknown6'),
      construct.ULInt16(u'path_size'))

  def __init__(self, debug=False):
    """Initializes the .automaticDestinations-ms file object.

    Args:
      debug: optional boolean value to indicate if debug information should
             be printed.
    """
    super(AutomaticDestinationsFile, self).__init__()
    self._debug = debug
    self._format_version = None
    self._file_object = None
    self._file_object_opened_in_object = False
    self._file_size = 0
    self._olecf_file = pyolecf.file()

    self.entries = []
    self.recovered_entries = []

  def _ReadDestList(self):
    """Reads the DestList stream.

    Raises:
      IOError: if the DestList stream cannot be read.
    """
    olecf_item = self._olecf_file.root_item.get_sub_item_by_name(u'DestList')

    self._ReadDestListHeader(olecf_item)

    stream_offset = olecf_item.get_offset()
    while stream_offset < olecf_item.get_size():
      entry_size = self._ReadDestListEntry(
          olecf_item, stream_offset, )
      stream_offset += entry_size

  def _ReadDestListEntry(self, olecf_item, stream_offset):
    """Reads a DestList stream entry.

    Args:
      olecf_item: the OLECF item (instance of pyolecf.item).
      stream_offset: an integer containing the stream offset of the entry.

    Returns:
      An integer containing the entry data size.

    Raises:
      IOError: if the DestList stream entry cannot be read.
    """
    if self._format_version == 1:
      dest_list_entry = self._DEST_LIST_STREAM_ENTRY_V1
    elif self._format_version >= 3:
      dest_list_entry = self._DEST_LIST_STREAM_ENTRY_V3

    if self._debug:
      print(u'Reading entry at offset: 0x{0:08x}'.format(stream_offset))

    entry_data = olecf_item.read(dest_list_entry.sizeof())

    if self._debug:
      print(u'Entry data:')
      print(hexdump.Hexdump(entry_data))

    try:
      dest_list_entry_struct = dest_list_entry.parse(entry_data)
    except construct.FieldError as exception:
      raise IOError((
          u'Unable to parse entry with error: {0:s}').format(exception))

    entry_path_size = dest_list_entry_struct.path_size * 2

    if self._debug:
      print(u'Unknown1\t\t\t\t\t\t\t\t: 0x{0:08x}'.format(
          dest_list_entry_struct.unknown1))

      try:
        uuid_object = uuid.UUID(
            bytes_le=dest_list_entry_struct.droid_volume_identifier)
        print(u'Droid volume identifier\t\t\t\t\t\t\t: {0:s}'.format(
            uuid_object))
      except (TypeError, ValueError):
        pass

      try:
        uuid_object = uuid.UUID(
            bytes_le=dest_list_entry_struct.droid_file_identifier)
        print(u'Droid file identifier\t\t\t\t\t\t\t: {0:s}'.format(
            uuid_object))
      except (TypeError, ValueError):
        pass

      try:
        uuid_object = uuid.UUID(
            bytes_le=dest_list_entry_struct.birth_droid_volume_identifier)
        print(u'Birth droid volume identifier\t\t\t\t\t\t: {0:s}'.format(
            uuid_object))
      except (TypeError, ValueError):
        pass

      try:
        uuid_object = uuid.UUID(
            bytes_le=dest_list_entry_struct.birth_droid_file_identifier)
        print(u'Birth droid file identifier\t\t\t\t\t\t: {0:s}'.format(
            uuid_object))
      except (TypeError, ValueError):
        pass

      hostname = dest_list_entry_struct.hostname
      hostname, _, _ = hostname.partition(u'\x00')
      print(u'Hostname\t\t\t\t\t\t\t\t: {0:s}'.format(hostname))

      print(u'Entry number\t\t\t\t\t\t\t\t: {0:d}'.format(
          dest_list_entry_struct.entry_number))
      print(u'Unknown2\t\t\t\t\t\t\t\t: 0x{0:08x}'.format(
          dest_list_entry_struct.unknown2))
      print(u'Unknown3\t\t\t\t\t\t\t\t: {0:f}'.format(
          dest_list_entry_struct.unknown3))
      print(u'Last modification time\t\t\t\t\t\t\t: {0!s}'.format(
          FromFiletime(dest_list_entry_struct.last_modification_time)))

      # TODO: debug print pin status.
      print(u'Pin status\t\t\t\t\t\t\t\t: 0x{0:08x}'.format(
          dest_list_entry_struct.pin_status))

      if self._format_version >= 3:
        print(u'Unknown4\t\t\t\t\t\t\t\t: 0x{0:08x}'.format(
            dest_list_entry_struct.unknown4))
        print(u'Unknown5\t\t\t\t\t\t\t\t: 0x{0:08x}'.format(
            dest_list_entry_struct.unknown5))
        print(u'Unknown6\t\t\t\t\t\t\t\t: 0x{0:08x}'.format(
            dest_list_entry_struct.unknown6))

      print(u'Path size\t\t\t\t\t\t\t\t: {0:d} ({1:d})'.format(
          dest_list_entry_struct.path_size, entry_path_size))

      print(u'')

    entry_path_data = olecf_item.read(entry_path_size)

    if self._debug:
      print(u'Entry path data:')
      print(hexdump.Hexdump(entry_path_data))

    try:
      path_string = entry_path_data.decode(u'utf16')
    except UnicodeDecodeError as exception:
      path_string = u''

    if self._debug:
      print(u'Path string\t\t\t\t\t\t\t\t: {0:s}'.format(path_string))
      print(u'')

    entry_footer_data = b''
    if self._format_version >= 3:
      entry_footer_data = olecf_item.read(4)

      if self._debug:
        print(u'Entry footer data:')
        print(hexdump.Hexdump(entry_footer_data))

    return len(entry_data) + len(entry_path_data) + len(entry_footer_data)

  def _ReadDestListHeader(self, olecf_item):
    """Reads the DestList stream header.

    Args:
      olecf_item: the OLECF item (instance of pyolecf.item).

    Raises:
      IOError: if the DestList stream header cannot be read.
    """
    olecf_item.seek(0, os.SEEK_SET)

    if self._debug:
      print(u'Reading header at offset: 0x{0:08x}'.format(0))

    header_data = olecf_item.read(self._DEST_LIST_STREAM_HEADER.sizeof())

    if self._debug:
      print(u'Header data:')
      print(hexdump.Hexdump(header_data))

    try:
      dest_list_header_struct = self._DEST_LIST_STREAM_HEADER.parse(header_data)
    except construct.FieldError as exception:
      raise IOError((
          u'Unable to parse header with error: {0:s}').format(exception))

    if self._debug:
      print(u'Format version\t\t\t\t\t\t\t\t: {0:d}'.format(
          dest_list_header_struct.format_version))
      print(u'Number of entries\t\t\t\t\t\t\t: {0:d}'.format(
          dest_list_header_struct.number_of_entries))
      print(u'Number of pinned entries\t\t\t\t\t\t: {0:d}'.format(
          dest_list_header_struct.number_of_pinned_entries))
      print(u'Unknown1\t\t\t\t\t\t\t\t: {0:f}'.format(
          dest_list_header_struct.unknown1))
      print(u'Last entry number\t\t\t\t\t\t\t: {0:d}'.format(
          dest_list_header_struct.last_entry_number))
      print(u'Unknown2\t\t\t\t\t\t\t\t: 0x{0:08x}'.format(
          dest_list_header_struct.unknown2))
      print(u'Last revision number\t\t\t\t\t\t\t: {0:d}'.format(
          dest_list_header_struct.last_revision_number))
      print(u'Unknown3\t\t\t\t\t\t\t\t: 0x{0:08x}'.format(
          dest_list_header_struct.unknown3))

      print(u'')

    if dest_list_header_struct.format_version not in (1, 3, 4):
      raise IOError(
          u'Unsupported format version: {0:d}'.format(
              dest_list_header_struct.format_version))

    self._format_version = dest_list_header_struct.format_version

  def _ReadLNKFile(self, olecf_item):
    """Reads a LNK file.

    Args:
      olecf_item: the OLECF item (instance of pyolecf.item).

    Returns:
      A LNK file entry (instance of LNKFileEntry).

    Raises:
      IOError: if the LNK file cannot be read.
    """
    if self._debug:
      print(u'Reading LNK file from stream: {0:s}'.format(olecf_item.name))

    lnk_file_entry = LNKFileEntry(olecf_item.name)

    try:
      lnk_file_entry.Open(olecf_item)
    except IOError as exception:
      raise IOError((
          u'Unable to parse LNK file from stream: {0:s} '
          u'with error: {1:s}').format(olecf_item.name, exception))

    if self._debug:
      print(u'')

    return lnk_file_entry

  def _ReadLNKFiles(self):
    """Reads the LNK files.

    Raises:
      IOError: if the LNK files cannot be read.
    """
    for olecf_item in self._olecf_file.root_item.sub_items:
      if olecf_item.name == u'DestList':
        continue

      lnk_file_entry = self._ReadLNKFile(olecf_item)
      if lnk_file_entry:
        self.entries.append(lnk_file_entry)

  def Close(self):
    """Closes the .customDestinations-ms file."""
    if self._olecf_file:
      self._olecf_file.close()

    if self._file_object_opened_in_object:
      self._file_object.close()
    self._file_object = None

  def Open(self, filename):
    """Opens the .customDestinations-ms file.

    Args:
      filename: the filename.
    """
    stat_object = os.stat(filename)
    self._file_size = stat_object.st_size

    self._file_object = open(filename, 'rb')
    self._file_object_opened_in_object = True

    self._olecf_file.open_file_object(self._file_object)

    self._ReadDestList()
    self._ReadLNKFiles()


class CustomDestinationsFile(object):
  """Class that contains a .customDestinations-ms file.

  Attributes:
    entries: list of the LNK file entries.
    recovered_entries: list of the recovered LNK file entries.
  """

  _LNK_GUID = (
      b'\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46')

  _FILE_HEADER = construct.Struct(
      u'file_header',
      construct.ULInt32(u'unknown1'),
      construct.ULInt32(u'unknown2'),
      construct.ULInt32(u'unknown3'),
      construct.ULInt32(u'header_values_type'))

  _HEADER_VALUE_TYPE_0 = construct.Struct(
      u'header_value_type_0',
      construct.ULInt32(u'number_of_characters'),
      construct.String(u'string', lambda ctx: ctx.number_of_characters * 2),
      construct.ULInt32(u'unknown1'))

  _HEADER_VALUE_TYPE_1_OR_2 = construct.Struct(
      u'header_value_type_1_or_2',
      construct.ULInt32(u'unknown1'))

  _ENTRY_HEADER = construct.Struct(
      u'entry_header',
      construct.String(u'guid', 16))

  _FOOTER_SIGNATURE = 0xbabffbab

  _FILE_FOOTER = construct.Struct(
      u'file_footer',
      construct.ULInt32(u'signature'))

  def __init__(self, debug=False):
    """Initializes the .customDestinations-ms file object.

    Args:
      debug: optional boolean value to indicate if debug information should
             be printed.
    """
    super(CustomDestinationsFile, self).__init__()
    self._debug = debug
    self._file_object = None
    self._file_object_opened_in_object = False
    self._file_size = 0

    self.entries = []
    self.recovered_entries = []

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
    except (IOError, construct.FieldError) as exception:
      raise IOError(u'Unable to parse file header with error: {0:s}'.format(
          exception))

    if self._debug:
      print(u'Unknown1\t\t\t\t\t\t\t\t: 0x{0:08x}'.format(
          file_header_struct.unknown1))
      print(u'Unknown2\t\t\t\t\t\t\t\t: 0x{0:08x}'.format(
          file_header_struct.unknown2))
      print(u'Unknown3\t\t\t\t\t\t\t\t: 0x{0:08x}'.format(
          file_header_struct.unknown3))
      print(u'Header value type\t\t\t\t\t\t\t: {0:d}'.format(
          file_header_struct.header_values_type))
      print(u'')

    if file_header_struct.unknown1 != 2:
      raise IOError(u'Invalid unknown1: {0:d}.'.format(
          file_header_struct.unknown1))

    if file_header_struct.header_values_type > 2:
      raise IOError(u'Invalid header value type: {0:d}.'.format(
          file_header_struct.header_values_type))

    if file_header_struct.header_values_type == 0:
      data_structure = self._HEADER_VALUE_TYPE_0
    else:
      data_structure = self._HEADER_VALUE_TYPE_1_OR_2

    try:
      data_structure_struct = data_structure.parse_stream(self._file_object)
    except (IOError, construct.FieldError) as exception:
      raise IOError(
          u'Unable to parse file header value with error: {0:s}'.format(
              exception))

    if self._debug:
      if file_header_struct.header_values_type == 0:
        print(u'Number of characters\t\t\t\t\t\t: {0:d}'.format(
            data_structure_struct.number_of_characters))

      print(u'Unknown1\t\t\t\t\t\t\t\t: 0x{0:08x}'.format(
          data_structure_struct.unknown1))
      print(u'')

  def _ReadLNKFile(self, file_object):
    """Reads a LNK file.

    Args:
      file_object: the file-like object.

    Returns:
      A LNK file entry (instance of LNKFileEntry).

    Raises:
      IOError: if the LNK file cannot be read.
    """
    file_offset = self._file_object.tell()
    if self._debug:
      print(u'Reading LNK file at offset: 0x{0:08x}'.format(file_offset))

    identifier = u'0x{0:08x}'.format(file_offset)
    lnk_file_entry = LNKFileEntry(identifier)

    try:
      lnk_file_entry.Open(file_object)
    except IOError as exception:
      raise IOError((
          u'Unable to parse LNK file at offset: 0x{0:08x} '
          u'with error: {1:s}').format(file_offset, exception))

    if self._debug:
      print(u'')

    return lnk_file_entry

  def _ReadLNKFiles(self):
    """Reads the LNK files.

    Raises:
      IOError: if the LNK files cannot be read.
    """
    file_offset = self._file_object.tell()
    remaining_file_size = self._file_size - file_offset

    # The Custom Destination file does not have a unique signature in
    # the file header that is why we use the first LNK class identifier (GUID)
    # as a signature.
    first_guid_checked = False
    while remaining_file_size > 4:
      try:
        entry_header = self._ENTRY_HEADER.parse_stream(self._file_object)
      except (IOError, construct.FieldError) as exception:
        error_message = (
            u'Unable to parse file entry header at offset: 0x{0:08x} '
            u'with error: {1:s}').format(file_offset, exception)

        if not first_guid_checked:
          raise IOError(error_message)

        logging.warning(error_message)
        break

      if entry_header.guid != self._LNK_GUID:
        error_message = u'Invalid entry header at offset: 0x{0:08x}.'.format(
            file_offset)

        if not first_guid_checked:
          raise IOError(error_message)

        self._file_object.seek(-16, os.SEEK_CUR)
        try:
          file_footer = self._FILE_FOOTER.parse_stream(self._file_object)
        except (IOError, construct.FieldError) as exception:
          raise IOError((
              u'Unable to parse file footer at offset: 0x{0:08x} '
              u'with error: {1:s}').format(file_offset, exception))

        if file_footer.signature != self._FOOTER_SIGNATURE:
          logging.warning(error_message)

        self._file_object.seek(-4, os.SEEK_CUR)
        break

      first_guid_checked = True
      file_offset += 16
      remaining_file_size -= 16

      lnk_file_object = DataRange(self._file_object)
      lnk_file_object.SetRange(file_offset, remaining_file_size)
      lnk_file_entry = self._ReadLNKFile(lnk_file_object)
      if lnk_file_entry:
        self.entries.append(lnk_file_entry)

      file_offset += lnk_file_entry.data_size
      remaining_file_size -= lnk_file_entry.data_size

      self._file_object.seek(file_offset, os.SEEK_SET)

  def _ReadFileFooter(self):
    """Reads the file footer.

    Raises:
      IOError: if the file footer cannot be read.
    """
    file_offset = self._file_object.tell()

    try:
      file_footer = self._FILE_FOOTER.parse_stream(self._file_object)
    except (IOError, construct.FieldError) as exception:
      raise IOError((
          u'Unable to parse file footer at offset: 0x{0:08x} '
          u'with error: {1:s}').format(file_offset, exception))

    if file_footer.signature != self._FOOTER_SIGNATURE:
      raise IOError(u'Invalid footer signature at offset: 0x{0:08x}.'.format(
          file_offset))

  def Close(self):
    """Closes the .customDestinations-ms file."""
    if self._file_object_opened_in_object:
      self._file_object.close()
    self._file_object = None

  def Open(self, filename):
    """Opens the .customDestinations-ms file.

    Args:
      filename: the filename.
    """
    stat_object = os.stat(filename)
    self._file_size = stat_object.st_size

    self._file_object = open(filename, 'rb')
    self._file_object_opened_in_object = True

    self._ReadFileHeader()
    self._ReadLNKFiles()

    file_offset = self._file_object.tell()
    if file_offset < self._file_size - 4:
      # TODO: recover LNK files
      # * scan for LNK GUID and run _ReadLNKFiles on remaining data.
      if self._debug:
        print(u'Detected trailing data')
        print(u'')

    self._ReadFileFooter()


def Main():
  """The main program function.

  Returns:
    A boolean containing True if successful or False if not.
  """
  argument_parser = argparse.ArgumentParser(description=(
      u'Extracts information from Windows Jump List files.'))

  argument_parser.add_argument(
      u'-d', u'--debug', dest=u'debug', action=u'store_true', default=False,
      help=u'enable debug output.')

  argument_parser.add_argument(
      u'source', nargs=u'?', action=u'store', metavar=u'PATH',
      default=None, help=u'path of the Windows Jump List file.')

  options = argument_parser.parse_args()

  if not options.source:
    print(u'Source file missing.')
    print(u'')
    argument_parser.print_help()
    print(u'')
    return False

  logging.basicConfig(
      level=logging.INFO, format=u'[%(levelname)s] %(message)s')

  if pyolecf.check_file_signature(options.source):
    jump_list_file = AutomaticDestinationsFile(debug=options.debug)

  else:
    jump_list_file = CustomDestinationsFile(debug=options.debug)

  jump_list_file.Open(options.source)

  print(u'Windows Jump List information:')
  print(u'Number of entries:\t\t{0:d}'.format(len(jump_list_file.entries)))
  print(u'Number of recovered entries:\t{0:d}'.format(
      len(jump_list_file.recovered_entries)))
  print(u'')

  for lnk_file_entry in jump_list_file.entries:
    print(u'LNK file entry: {0:s}'.format(lnk_file_entry.identifier))

    for shell_item in lnk_file_entry.GetShellItems():
      print(u'Shell item: 0x{0:02x}'.format(shell_item.class_type))

    print(u'')

  jump_list_file.Close()

  return True


if __name__ == '__main__':
  if not Main():
    sys.exit(1)
  else:
    sys.exit(0)
