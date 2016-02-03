#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Script to parse Copy in and out (CPIO) archive files."""

from __future__ import print_function
import argparse
import hashlib
import logging
import os
import sys

import construct

import hexdump


class CPIOArchiveFileEntry(object):
  """Class that contains a CPIO archive file entry."""

  def __init__(self, file_object):
    """Initializes the CPIO archive file entry object.

    Args:
      file_object: the file-like object of the CPIO archive file.
    """
    super(CPIOArchiveFileEntry, self).__init__()
    self._current_offset = 0
    self._file_object = file_object

    self.data_offset = None
    self.data_size = None
    self.inode_number = None
    self.mode = None
    self.modification_time = None
    self.path = None
    self.size = None

  def read(self, size=None):
    """Reads a byte string from the file-like object at the current offset.

    The function will read a byte string of the specified size or
    all of the remaining data if no size was specified.

    Args:
      size: Optional integer value containing the number of bytes to read.
            Default is all remaining data (None).

    Returns:
      A byte string containing the data read.

    Raises:
      IOError: if the read failed.
    """
    if self._current_offset >= self.data_size:
      return b''

    read_size = self.data_size - self._current_offset
    if read_size > size:
      read_size = size

    file_offset = self.data_offset + self._current_offset
    self._file_object.seek(file_offset, os.SEEK_SET)
    data = self._file_object.read(read_size)
    self._current_offset += len(data)
    return data

  def seek(self, offset, whence=os.SEEK_SET):
    """Seeks an offset within the file-like object.

    Args:
      offset: The offset to seek.
      whence: Optional value that indicates whether offset is an absolute
              or relative position within the file. Default is SEEK_SET.

    Raises:
      IOError: if the seek failed.
    """
    if whence == os.SEEK_CUR:
      self._current_offset += offset

    elif whence == os.SEEK_END:
      self._current_offset = self.data_size + offset

    elif whence == os.SEEK_SET:
      self._current_offset = offset

    else:
      raise IOError(u'Unsupported whence.')

  def get_offset(self):
    """Returns the current offset into the file-like object."""
    return self._current_offset

  # Pythonesque alias for get_offset().
  def tell(self):
    """Returns the current offset into the file-like object."""
    return self.get_offset()

  def get_size(self):
    """Returns the size of the file-like object."""
    return self.data_size


class CPIOArchiveFile(object):
  """Class that contains a CPIO archive file.

  Attributes:
    file_format: a string containing the CPIO file format.
  """

  _CPIO_SIGNATURE_BINARY_BIG_ENDIAN = b'\x71\xc7'
  _CPIO_SIGNATURE_BINARY_LITTLE_ENDIAN = b'\xc7\x71'
  _CPIO_SIGNATURE_PORTABLE_ASCII = b'070707'
  _CPIO_SIGNATURE_NEW_ASCII = b'070701'
  _CPIO_SIGNATURE_NEW_ASCII_WITH_CHECKSUM = b'070702'

  _CPIO_BINARY_BIG_ENDIAN_FILE_ENTRY_STRUCT = construct.Struct(
      u'cpio_binary_big_endian_file_entry',
      construct.UBInt16(u'signature'),
      construct.UBInt16(u'device_number'),
      construct.UBInt16(u'inode_number'),
      construct.UBInt16(u'mode'),
      construct.UBInt16(u'user_identifier'),
      construct.UBInt16(u'group_identifier'),
      construct.UBInt16(u'number_of_links'),
      construct.UBInt16(u'special_device_number'),
      construct.UBInt16(u'modification_time_upper'),
      construct.UBInt16(u'modification_time_lower'),
      construct.UBInt16(u'path_string_size'),
      construct.UBInt16(u'file_size_upper'),
      construct.UBInt16(u'file_size_lower'))

  _CPIO_BINARY_LITTLE_ENDIAN_FILE_ENTRY_STRUCT = construct.Struct(
      u'cpio_binary_little_endian_file_entry',
      construct.ULInt16(u'signature'),
      construct.ULInt16(u'device_number'),
      construct.ULInt16(u'inode_number'),
      construct.ULInt16(u'mode'),
      construct.ULInt16(u'user_identifier'),
      construct.ULInt16(u'group_identifier'),
      construct.ULInt16(u'number_of_links'),
      construct.ULInt16(u'special_device_number'),
      construct.ULInt16(u'modification_time_upper'),
      construct.ULInt16(u'modification_time_lower'),
      construct.ULInt16(u'path_string_size'),
      construct.ULInt16(u'file_size_upper'),
      construct.ULInt16(u'file_size_lower'))

  _CPIO_PORTABLE_ASCII_FILE_ENTRY_STRUCT = construct.Struct(
      u'cpio_portable_ascii_file_entry',
      construct.Bytes(u'signature', 6),
      construct.Bytes(u'device_number', 6),
      construct.Bytes(u'inode_number', 6),
      construct.Bytes(u'mode', 6),
      construct.Bytes(u'user_identifier', 6),
      construct.Bytes(u'group_identifier', 6),
      construct.Bytes(u'number_of_links', 6),
      construct.Bytes(u'special_device_number', 6),
      construct.Bytes(u'modification_time', 11),
      construct.Bytes(u'path_string_size', 6),
      construct.Bytes(u'file_size', 11))

  _CPIO_NEW_ASCII_FILE_ENTRY_STRUCT = construct.Struct(
      u'cpio_portable_ascii_file_entry',
      construct.Bytes(u'signature', 6),
      construct.Bytes(u'inode_number', 8),
      construct.Bytes(u'mode', 8),
      construct.Bytes(u'user_identifier', 8),
      construct.Bytes(u'group_identifier', 8),
      construct.Bytes(u'number_of_links', 8),
      construct.Bytes(u'modification_time', 8),
      construct.Bytes(u'file_size', 8),
      construct.Bytes(u'device_major_number', 8),
      construct.Bytes(u'device_minor_number', 8),
      construct.Bytes(u'special_device_major_number', 8),
      construct.Bytes(u'special_device_minor_number', 8),
      construct.Bytes(u'path_string_size', 8),
      construct.Bytes(u'checksum', 8))

  def __init__(self, debug=False):
    """Initializes the CPIO archive file object.

    Args:
      debug: optional boolean value to indicate if debug information should
             be printed.
    """
    super(CPIOArchiveFile, self).__init__()
    self._debug = debug
    self._file_entries = None
    self._file_object = None
    self._file_object_opened_in_object = False
    self._file_size = 0

    self.file_format = None

  def _ReadFileEntry(self, file_offset):
    """Reads a file entry.

    Args:
      file_offset: an integer containing the current file offset.

    Raises:
      IOError: if the file entry cannot be read.
    """
    if self._debug:
      print(u'Seeking file entry at offset: 0x{0:08x}'.format(file_offset))

    self._file_object.seek(file_offset, os.SEEK_SET)

    if self.file_format == u'bin-big-endian':
      file_entry_struct = self._CPIO_BINARY_BIG_ENDIAN_FILE_ENTRY_STRUCT
    elif self.file_format == u'bin-little-endian':
      file_entry_struct = self._CPIO_BINARY_LITTLE_ENDIAN_FILE_ENTRY_STRUCT
    elif self.file_format == u'odc':
      file_entry_struct = self._CPIO_PORTABLE_ASCII_FILE_ENTRY_STRUCT
    elif self.file_format in (u'crc', u'newc'):
      file_entry_struct = self._CPIO_NEW_ASCII_FILE_ENTRY_STRUCT

    file_entry_struct_size = file_entry_struct.sizeof()
    file_entry_data = self._file_object.read(file_entry_struct_size)
    file_offset += file_entry_struct_size

    if self._debug:
      print(u'File entry data:')
      print(hexdump.Hexdump(file_entry_data))

    try:
      file_entry_struct = file_entry_struct.parse(file_entry_data)
    except construct.FieldError as exception:
      raise IOError((
          u'Unable to parse file entry data section with error: '
          u'{0:s}').file_format(exception))

    if self.file_format in (u'bin-big-endian', u'bin-little-endian'):
      inode_number = file_entry_struct.inode_number
      mode = file_entry_struct.mode
      user_identifier = file_entry_struct.user_identifier
      group_identifier = file_entry_struct.group_identifier

      modification_time = (
          (file_entry_struct.modification_time_upper << 16) |
          file_entry_struct.modification_time_lower)

      path_string_size = file_entry_struct.path_string_size

      file_size = (
          (file_entry_struct.file_size_upper << 16) |
          file_entry_struct.file_size_lower)

    elif self.file_format == u'odc':
      inode_number = int(file_entry_struct.inode_number, 8)
      mode = int(file_entry_struct.mode, 8)
      user_identifier = int(file_entry_struct.user_identifier, 8)
      group_identifier = int(file_entry_struct.group_identifier, 8)
      modification_time = int(file_entry_struct.modification_time, 8)
      path_string_size = int(file_entry_struct.path_string_size, 8)
      file_size = int(file_entry_struct.file_size, 8)

    elif self.file_format in (u'crc', u'newc'):
      inode_number = int(file_entry_struct.inode_number, 16)
      mode = int(file_entry_struct.mode, 16)
      user_identifier = int(file_entry_struct.user_identifier, 16)
      group_identifier = int(file_entry_struct.group_identifier, 16)
      modification_time = int(file_entry_struct.modification_time, 16)
      path_string_size = int(file_entry_struct.path_string_size, 16)
      file_size = int(file_entry_struct.file_size, 16)

    if self._debug:
      if self.file_format in (u'bin-big-endian', u'bin-little-endian'):
        print(u'Signature\t\t\t\t\t\t\t\t: 0x{0:04x}'.format(
            file_entry_struct.signature))
      else:
        print(u'Signature\t\t\t\t\t\t\t\t: {0!s}'.format(
            file_entry_struct.signature))

      if self.file_format not in (u'crc', u'newc'):
        if self.file_format in (u'bin-big-endian', u'bin-little-endian'):
          device_number = file_entry_struct.device_number
        elif self.file_format == u'odc':
          device_number = int(file_entry_struct.device_number, 8)

        print(u'Device number\t\t\t\t\t\t\t\t: {0:d}'.format(device_number))

      print(u'Inode number\t\t\t\t\t\t\t\t: {0:d}'.format(inode_number))
      print(u'Mode\t\t\t\t\t\t\t\t\t: {0:o}'.format(mode))

      print(u'User identifier (UID)\t\t\t\t\t\t\t: {0:d}'.format(
          user_identifier))

      print(u'Group identifier (GID)\t\t\t\t\t\t\t: {0:d}'.format(
          group_identifier))

      if self.file_format in (u'bin-big-endian', u'bin-little-endian'):
        number_of_links = file_entry_struct.number_of_links
      elif self.file_format == u'odc':
        number_of_links = int(file_entry_struct.number_of_links, 8)
      elif self.file_format in (u'crc', u'newc'):
        number_of_links = int(file_entry_struct.number_of_links, 16)

      print(u'Number of links\t\t\t\t\t\t\t\t: {0:d}'.format(number_of_links))

      if self.file_format not in (u'crc', u'newc'):
        if self.file_format in (u'bin-big-endian', u'bin-little-endian'):
          special_device_number = file_entry_struct.special_device_number
        elif self.file_format == u'odc':
          special_device_number = int(file_entry_struct.special_device_number, 8)

        print(u'Special device number\t\t\t\t\t\t\t\t: {0:d}'.format(
            special_device_number))

      print(u'Modification time\t\t\t\t\t\t\t: {0:d}'.format(modification_time))

      if self.file_format not in (u'crc', u'newc'):
        print(u'Path string size\t\t\t\t\t\t\t: {0:d}'.format(path_string_size))

      print(u'File size\t\t\t\t\t\t\t\t: {0:d}'.format(file_size))

      if self.file_format in (u'crc', u'newc'):
        device_major_number = int(file_entry_struct.device_major_number, 16)

        print(u'Device major number\t\t\t\t\t\t\t: {0:d}'.format(device_major_number))

        device_minor_number = int(file_entry_struct.device_minor_number, 16)

        print(u'Device minor number\t\t\t\t\t\t\t: {0:d}'.format(device_minor_number))

        special_device_major_number = int(file_entry_struct.special_device_major_number, 16)

        print(u'Special device major number\t\t\t\t\t\t: {0:d}'.format(special_device_major_number))

        special_device_minor_number = int(file_entry_struct.special_device_minor_number, 16)

        print(u'Special device minor number\t\t\t\t\t\t: {0:d}'.format(special_device_minor_number))

        print(u'Path string size\t\t\t\t\t\t\t: {0:d}'.format(path_string_size))

        checksum = int(file_entry_struct.checksum, 16)

        print(u'Checksum\t\t\t\t\t\t\t\t: 0x{0:08x}'.format(checksum))

    path_string_data = self._file_object.read(path_string_size)
    file_offset += path_string_size

    # TODO: should this be ASCII?
    path_string = path_string_data.decode(u'ascii')
    path_string, _, _ = path_string.partition(u'\x00')

    if self._debug:
      print(u'Path string\t\t\t\t\t\t\t\t: {0:s}'.format(path_string))

    if self.file_format in (u'bin-big-endian', u'bin-little-endian'):
      padding_size = file_offset % 2
      if padding_size > 0:
        padding_size = 2 - padding_size

    elif self.file_format == u'odc':
      padding_size = 0

    elif self.file_format in (u'crc', u'newc'):
      padding_size = file_offset % 4
      if padding_size > 0:
        padding_size = 4 - padding_size

    if self._debug:
      padding_data = self._file_object.read(padding_size)
      print(u'Path string alignment padding:')
      print(hexdump.Hexdump(padding_data))

    file_offset += padding_size

    file_entry = CPIOArchiveFileEntry(self._file_object)

    file_entry.data_offset = file_offset
    file_entry.data_size = file_size
    file_entry.group_identifier = group_identifier
    file_entry.inode_number = inode_number
    file_entry.modification_time = modification_time
    file_entry.path = path_string
    file_entry.mode = mode
    file_entry.size = (
        file_entry_struct_size + path_string_size + padding_size + file_size)
    file_entry.user_identifier = user_identifier

    if self.file_format in (u'crc', u'newc'):
      file_offset += file_size

      padding_size = file_offset % 4
      if padding_size > 0:
        padding_size = 4 - padding_size

      if self._debug:
        self._file_object.seek(file_offset, os.SEEK_SET)
        padding_data = self._file_object.read(padding_size)

        print(u'File data alignment padding:')
        print(hexdump.Hexdump(padding_data))

      file_entry.size += padding_size

    if self._debug:
      print(u'')

    return file_entry

  def _ReadFileEntries(self):
    """Reads the file entries from the cpio archive."""
    file_offset = 0
    while file_offset < self._file_size:
      file_entry = self._ReadFileEntry(file_offset)
      file_offset += file_entry.size
      if file_entry.path == u'TRAILER!!!':
        break

      if file_entry.path in self._file_entries:
        continue

      self._file_entries[file_entry.path] = file_entry

      # TODO: move this to Main()
      sha256_context = hashlib.sha256()
      file_data = file_entry.read(4096)
      while file_data:
        sha256_context.update(file_data)
        file_data = file_entry.read(4096)

      print(u'SHA-256 sum: {0:s}'.format(sha256_context.hexdigest()))
      print(u'')

  def Close(self):
    """Closes the CPIO archive file."""
    if not self._file_object:
      return

    if self._file_object_opened_in_object:
      self._file_object.close()
    self._file_entries = None
    self._file_object = None

  def FileEntryExistsByPath(self, path):
    """Determines if file entry for a specific path exists.

    Returns:
      A boolean value indicating the file entry exists.
    """
    if self._file_entries is None:
      return False

    return path in self._file_entries

  def GetFileEntries(self, path_prefix=u''):
    """Retrieves the file entries.

    Args:
      path_prefix: a string containing the path prefix.

    Yields:
      A CPIO archive file entry (instance of CPIOArchiveFileEntry).
    """
    for path, file_entry in iter(self._file_entries.items()):
      if path.startswith(path_prefix):
        yield file_entry

  def GetFileEntryByPath(self, path):
    """Retrieves a file entry for a specific path.

    Returns:
      A CPIO archive file entry (instance of CPIOArchiveFileEntry) or None.
    """
    if self._file_entries is None:
      return

    return self._file_entries.get(path, None)

  def Open(self, filename):
    """Opens the CPIO archive file.

    Args:
      filename: the filename.

    Raises:
      IOError: if the file format signature is not supported.
    """
    file_object = open(filename, 'rb')
    file_object_opened_in_object = True

    file_object.seek(0, os.SEEK_SET)
    signature_data = file_object.read(6)

    self.file_format = None
    if len(signature_data) > 2:
      if signature_data[:2] == self._CPIO_SIGNATURE_BINARY_BIG_ENDIAN:
        self.file_format = u'bin-big-endian'
      elif signature_data[:2] == self._CPIO_SIGNATURE_BINARY_LITTLE_ENDIAN:
        self.file_format = u'bin-little-endian'
      elif signature_data == self._CPIO_SIGNATURE_PORTABLE_ASCII:
        self.file_format = u'odc'
      elif signature_data == self._CPIO_SIGNATURE_NEW_ASCII:
        self.file_format = u'newc'
      elif signature_data == self._CPIO_SIGNATURE_NEW_ASCII_WITH_CHECKSUM:
        self.file_format = u'crc'

    if self.file_format is None:
      raise IOError(u'Unsupported CPIO format.')

    stat_object = os.stat(filename)

    self._file_entries = {}
    self._file_object = file_object
    self._file_size = stat_object.st_size

    self._ReadFileEntries()

    # TODO: print trailing data


def Main():
  """The main program function.

  Returns:
    A boolean containing True if successful or False if not.
  """
  argument_parser = argparse.ArgumentParser(description=(
      u'Extracts information from CPIO archive files.'))

  argument_parser.add_argument(
      u'-d', u'--debug', dest=u'debug', action=u'store_true', default=False,
      help=u'enable debug output.')

  argument_parser.add_argument(
      u'source', nargs=u'?', action=u'store', metavar=u'PATH',
      default=None, help=u'path of the CPIO archive file.')

  options = argument_parser.parse_args()

  if not options.source:
    print(u'Source file missing.')
    print(u'')
    argument_parser.print_help()
    print(u'')
    return False

  logging.basicConfig(
      level=logging.INFO, format=u'[%(levelname)s] %(message)s')

  cpio_file = CPIOArchiveFile(debug=options.debug)
  cpio_file.Open(options.source)

  print(u'CPIO archive information:')
  print(u'\tFormat\t\t: {0:s}'.format(cpio_file.file_format))
  print(u'')

  cpio_file.Close()

  return True


if __name__ == '__main__':
  if not Main():
    sys.exit(1)
  else:
    sys.exit(0)
