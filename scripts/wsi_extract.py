#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Script to extract Windows Shell items."""

from __future__ import print_function
import argparse
import hashlib
import logging
import os
import sys

import pylnk
import pysigscan

from dtfabric import errors as dtfabric_errors
from dtfabric import fabric as dtfabric_fabric

from dfvfs.lib import definitions as dfvfs_definitions
from dfvfs.helpers import volume_scanner as dfvfs_volume_scanner
from dfvfs.resolver import resolver as dfvfs_resolver

import hexdump


class ParseError(Exception):
  """Error that is raised when data cannot be parsed."""


class WindowsShellItemsExtractor(dfvfs_volume_scanner.VolumeScanner):
  """Windows shell items extractor."""

  # TSK metadata files that need special handling.
  _METADATA_FILE_LOCATIONS_TSK = frozenset([
      # NTFS
      u'/$AttrDef',
      u'/$BadClus',
      u'/$Bitmap',
      u'/$Boot',
      u'/$Extend/$ObjId',
      u'/$Extend/$Quota',
      u'/$Extend/$Reparse',
      u'/$Extend/$RmMetadata/$Repair',
      u'/$Extend/$RmMetadata/$TxfLog/$Tops',
      u'/$Extend/$UsnJrnl',
      u'/$LogFile',
      u'/$MFT',
      u'/$MFTMirr',
      u'/$Secure',
      u'/$UpCase',
      u'/$Volume',
      # HFS+/HFSX
      u'/$ExtentsFile',
      u'/$CatalogFile',
      u'/$BadBlockFile',
      u'/$AllocationFile',
      u'/$AttributesFile',
  ])

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
      b'name: uint16le',
      b'type: integer',
      b'attributes:',
      b'  byte_order: little-endian',
      b'  format: unsigned',
      b'  size: 2',
      b'  units: bytes',
      b'---',
      b'name: extension_block',
      b'type: structure',
      b'attributes:',
      b'  byte_order: little-endian',
      b'members:',
      b'- name: size',
      b'  data_type: uint16',
      b'- name: version',
      b'  data_type: uint16',
      b'- name: signature',
      b'  data_type: uint32',
      b'- name: data',
      b'  type: sequence',
      b'  element_data_type: byte',
      (b'  number_of_elements: 0 if extension_block.size == 0 else '
       b'extension_block.size - 8'),
      b'---',
      b'name: shell_item',
      b'type: structure',
      b'attributes:',
      b'  byte_order: little-endian',
      b'members:',
      b'- name: size',
      b'  data_type: uint16',
      b'- name: data',
      b'  type: sequence',
      b'  element_data_type: byte',
      (b'  number_of_elements: 0 if shell_item.size == 0 else '
       b'shell_item.size - 2'),
  ])

  # TODO: add support for number of elements.

  _DATA_TYPE_FABRIC = dtfabric_fabric.DataTypeFabric(
      yaml_definition=_DATA_TYPE_FABRIC_DEFINITION)

  # TODO: add functionlity to set byte-order?
  _UINT16LE = _DATA_TYPE_FABRIC.CreateDataTypeMap(u'uint16le')

  _EXTENSION_BLOCK = _DATA_TYPE_FABRIC.CreateDataTypeMap(
      u'extension_block')

  _SHELL_ITEM = _DATA_TYPE_FABRIC.CreateDataTypeMap(u'shell_item')

  _SIGNATURES = [
      (u'creg', 0, b'CREG'),
      (u'lnk', 0, (b'\x4c\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0'
                   b'\x00\x00\x00\x00\x00\x00\x46')),
      (u'olecf', 0, b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'),
      (u'olecf_beta', 0, b'\x0e\x11\xfc\x0d\xd0\xcf\x11\x0e'),
      (u'regf', 0, b'regf'),
  ]

  def __init__(self, debug=False, mediator=None):
    """Initializes the Windows shell items extractor object.

    Args:
      debug (Optional[bool]): True if debug information should be printed.
      mediator (Optional[dfvfs.VolumeScannerMediator]): volume scanner mediator.
    """
    super(WindowsShellItemsExtractor, self).__init__(mediator=mediator)
    self._debug = debug
    self._file_scanner = self._GetSignatureScanner()

  def _ExtractFromData(self, shell_items_data, output_writer):
    """Extracts Windows shell items from data.

    Args:
      shell_items_data (bytes): shell items data.
      output_writer (OutputWriter): output writer.

    Raises:
      ParseError: if the shell item data cannot be read.
    """
    data_offset = 0
    last_data_offset = 0
    data_size = len(shell_items_data)

    while data_offset < data_size:
      try:
        shell_item_struct = self._SHELL_ITEM.MapByteStream(
            shell_items_data[data_offset:])

      except dtfabric_errors.MappingError as exception:
        raise ParseError((
            u'Unable to parse shell item at offset: 0x{0:08x} '
            u'with error: {1:s}').format(data_offset, exception))

      shell_item_data_size = shell_item_struct.size

      # The last shell item is the list terminator.
      if shell_item_data_size == 0:
        data_offset += 2
        break

      last_data_offset = data_offset
      data_offset += shell_item_data_size
      shell_item_data = shell_items_data[last_data_offset:data_offset]

      output_writer.WriteShellItem(shell_item_data)

      try:
        extension_version_offset = self._UINT16LE.MapByteStream(
            shell_item_data[-2:])

      except dtfabric_errors.MappingError as exception:
        raise ParseError((
            u'Unable to parse extension block offset at offset: 0x{0:08x} '
            u'with error: {1:s}').format(
                data_offset + len(shell_item_data) - 2, exception))

      # The extension block signature can be found by the extension
      # version offset.
      extension_signature_data = shell_item_struct.data[
          extension_version_offset+2:extension_version_offset+6]

      if extension_signature_data[-2:] == b'\xef\xbe':
        extension_block_offset = extension_version_offset - 2
        shell_item_data_size -= 2

        while extension_block_offset < shell_item_data_size:
          try:
            extension_block_struct = self._EXTENSION_BLOCK.MapByteStream(
                shell_item_struct.data[extension_block_offset:])

          except dtfabric_errors.MappingError as exception:
            raise ParseError((
                u'Unable to parse extension block at offset: 0x{0:08x} '
                u'with error: {1:s}').format(
                    extension_block_offset, exception))

          extension_block_size = extension_block_struct.size

          # The last extension block is the list terminator.
          if extension_block_size == 0:
            extension_block_offset += 2
            break

          extension_block_offset += extension_block_size

        # TODO: report trailing data.

    # TODO: report trailing data.

  def _ExtractFromDataStream(
      self, file_entry, data_stream_name, full_path, output_writer):
    """Extracts Windows shell items from a file entry data stream.

    Args:
      file_entry (dfvfs.FileEntry): file entry.
      data_stream_name (str): data stream name.
      full_path (str): full path of the file entry.
      output_writer (OutputWriter): output writer.

    Raises:
      IOError: if the extraction fails.
    """
    try:
      file_object = file_entry.GetFileObject(data_stream_name=data_stream_name)
    except IOError as exception:
      logging.warning((
          u'Unable to open path specification:\n{0:s}'
          u'with error: {1:s}').format(
              file_entry.path_spec.comparable, exception))
      return

    if not file_object:
      return

    try:
      self._ExtractFromFileObject(file_object, full_path, output_writer)
    except IOError as exception:
      logging.warning((
          u'Unable to read from path specification:\n{0:s}'
          u'with error: {1:s}').format(
              file_entry.path_spec.comparable, exception))
      return

    finally:
      file_object.close()

  def _ExtractFromFileEntry(
      self, file_system, file_entry, parent_full_path, output_writer):
    """Extracts Windows shell items from a file entry.

    Args:
      file_system (dfvfs.FileSystem): file system.
      file_entry (dfvfs.FileEntry): file entry.
      parent_full_path (str): full path of the parent file entry.
      output_writer (OutputWriter): output writer.
    """
    full_path = file_system.JoinPath([parent_full_path, file_entry.name])
    for data_stream in file_entry.data_streams:
      if data_stream.name:
        data_stream_path = u'{0:s}:{1:s}'.format(full_path, data_stream.name)
      else:
        data_stream_path = full_path

      self._ExtractFromDataStream(
          file_entry, data_stream.name, data_stream_path, output_writer)

    for sub_file_entry in file_entry.sub_file_entries:
      if self._IsMetadataFile(sub_file_entry):
        continue

      self._ExtractFromFileEntry(
          file_system, sub_file_entry, full_path, output_writer)

  def _ExtractFromFileObject(self, file_object, full_path, output_writer):
    """Extracts Windows shell items from a file-like object.

    Args:
      file_object (dfvfs.FileIO): file-like object.
      full_path (str): full path of the file entry.
      output_writer (OutputWriter): output writer.
    """
    signatures = self._GetSignatures(file_object)

    if u'lnk' in signatures:
      self._ExtractFromLNK(file_object, full_path, output_writer)

    if u'olecf' in signatures:
      # TODO: extract WSI from automatic destination JumpLists.
      pass

    if u'regf' in signatures:
      # TODO: extract WSI from BagsMRU.
      # TODO: extract WSI from MRU.
      # TODO: extract WSI from JumpLists.
      pass

    # TODO: extract WSI from custom destination JumpLists.

  def _ExtractFromLNK(self, file_object, unused_full_path, output_writer):
    """Extracts Windows shell items from a Windows Shortcut file-like object.

    Args:
      file_object (dfvfs.FileIO): file-like object.
      full_path (str): full path of the file entry.
      output_writer (OutputWriter): output writer.
    """
    lnk_file = pylnk.file()
    lnk_file.open_file_object(file_object)

    try:
      self._ExtractFromData(
          lnk_file.link_target_identifier_data, output_writer)
    finally:
      lnk_file.close()

  def _GetSignatures(self, file_object):
    """Determines the if the file content contains known signatures.

    Args:
      file_object (dfvfs.FileIO): file-like object.

    Returns:
      list[str]: signature identifiers or None if no known signatures
          were found.
    """
    scan_state = pysigscan.scan_state()
    self._file_scanner.scan_file_object(scan_state, file_object)
    # pylint: disable=not-an-iterable
    return [scan_result.identifier for scan_result in scan_state.scan_results]

  def _GetSignatureScanner(self):
    """Retrieves a signature scanner.

    Returns:
      pysigscan.scanner: signature scanner.
    """
    scanner_object = pysigscan.scanner()
    for identifier, pattern_offset, pattern in self._SIGNATURES:
      scanner_object.add_signature(
          identifier, pattern_offset, pattern,
          pysigscan.signature_flags.RELATIVE_FROM_START)

    return scanner_object

  def _IsMetadataFile(self, file_entry):
    """Determines if the file entry is a metadata file.

    Args:
      file_entry (dfvfs.FileEntry): file entry .

    Returns:
      bool: True if the file entry is a metadata file.
    """
    if (file_entry.type_indicator == dfvfs_definitions.TYPE_INDICATOR_TSK and
        file_entry.path_spec.location in self._METADATA_FILE_LOCATIONS_TSK):
      return True

    return False

  def ExtractWindowsShellItems(self, base_path_specs, output_writer):
    """Extracts Windows shell items.

    Args:
      base_path_specs (list[dfvfs.PathSpec]): source path specification.
      output_writer (OutputWriter): output writer.
    """
    for base_path_spec in base_path_specs:
      file_system = dfvfs_resolver.Resolver.OpenFileSystem(base_path_spec)
      file_entry = dfvfs_resolver.Resolver.OpenFileEntry(base_path_spec)
      if file_entry is None:
        logging.warning(
            u'Unable to open base path specification:\n{0:s}'.format(
                base_path_spec.comparable))
        continue

      self._ExtractFromFileEntry(file_system, file_entry, u'', output_writer)


class FileOutputWriter(object):
  """Class that defines a file output writer."""

  def __init__(self, output_directory):
    """Initializes the output writer object.

    Args:
      output_directory (str): path of the output directory.
    """
    super(FileOutputWriter, self).__init__()
    self._output_directory = output_directory

  def Close(self):
    """Closes the output writer object."""
    pass

  def Open(self):
    """Opens the output writer object.

    Returns:
      bool: True if successful or False if not.
    """
    return True

  def WriteShellItem(self, shell_item_data):
    """Writes a shell item.

    Args:
      shell_item_data (bytes): shell item data.
    """
    hash_context = hashlib.md5(shell_item_data)
    digest_hash = hash_context.hexdigest()

    output_path = os.path.join(self._output_directory, digest_hash)
    with open(output_path, 'wb') as output_file:
      output_file.write(shell_item_data)


class StdoutOutputWriter(object):
  """Class that defines a stdout output writer."""

  def Close(self):
    """Closes the output writer object."""
    pass

  def Open(self):
    """Opens the output writer object.

    Returns:
      bool: True if successful or False if not.
    """
    return True

  def WriteShellItem(self, shell_item_data):
    """Writes a shell item.

    Args:
      shell_item_data (bytes): shell item data.
    """
    print(hexdump.Hexdump(shell_item_data))


def Main():
  """The main program function.

  Returns:
    bool: True if successful or False if not.
  """
  argument_parser = argparse.ArgumentParser(description=(
      u'Extracts Windows Shell items from the source.'))

  argument_parser.add_argument(
      u'-d', u'--debug', dest=u'debug', action=u'store_true', default=False,
      help=u'enable debug output.')

  argument_parser.add_argument(
      u'-o', u'--output-directory', u'--output_directory',
      dest=u'output_directory', action=u'store', metavar=u'PATH',
      default=None, help=(
          u'path of the directory to write the output data to.'))

  argument_parser.add_argument(
      u'source', nargs=u'?', action=u'store', metavar=u'PATH',
      default=None, help=(
          u'path of the source to extract Windows Shell items from.'))

  options = argument_parser.parse_args()

  if not options.source:
    print(u'Source file missing.')
    print(u'')
    argument_parser.print_help()
    print(u'')
    return False

  logging.basicConfig(
      level=logging.INFO, format=u'[%(levelname)s] %(message)s')

  if options.output_directory:
    if not os.path.exists(options.output_directory):
      os.mkdir(options.output_directory)

    if not os.path.isdir(options.output_directory):
      print(u'{0:s} must be a directory'.format(options.output_directory))
      print(u'')
      return False

    output_writer = FileOutputWriter(options.output_directory)
  else:
    output_writer = StdoutOutputWriter()

  if not output_writer.Open():
    print(u'Unable to open output writer.')
    print(u'')
    return False

  # TODO: pass mediator.

  extractor = WindowsShellItemsExtractor(debug=options.debug)

  try:
    base_path_specs = extractor.GetBasePathSpecs(options.source)
    if not base_path_specs:
      print(u'No supported file system found in source.')
      print(u'')
      return False

    extractor.ExtractWindowsShellItems(base_path_specs, output_writer)

    print(u'')
    print(u'Completed.')

    return_value = True

  except KeyboardInterrupt:
    print(u'')
    print(u'Aborted by user.')

    return_value = False

  output_writer.Close()

  return return_value


if __name__ == '__main__':
  if not Main():
    sys.exit(1)
  else:
    sys.exit(0)
