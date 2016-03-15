#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Script to extract Windows Shell items."""

from __future__ import print_function
import argparse
import logging
import os
import sys

import pylnk
import pysigscan

import collector
import hexdump


class WindowsShellItemExtractor(collector.WindowsVolumeCollector):
  """Class that defines a Windows shell item extractor."""

  _SIGNATURES = [
      (u'creg', 0, b'CREG'),
      (u'lnk', 0, (b'\x4c\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0'
                   b'\x00\x00\x00\x00\x00\x00\x46')),
      (u'olecf', 0, b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'),
      (u'olecf_beta', 0, b'\x0e\x11\xfc\x0d\xd0\xcf\x11\x0e'),
      (u'regf', 0, b'regf'),
  ]

  def __init__(self, debug=False, mediator=None):
    """Initializes the Windows shell item extractor object.

    Args:
      debug: optional boolean value to indicate if debug information should
             be printed.
      mediator: a volume scanner mediator (instance of
                dfvfs.VolumeScannerMediator) or None.
    """
    super(WindowsShellItemExtractor, self).__init__(mediator=mediator)
    self._debug = debug

  # TODO: extract WSI from LNK.
  # TODO: extract WSI from BagsMRU.
  # TODO: extract WSI from MRU.
  # TODO: extract WSI from JumpLists.

  def _ExtractFromLNKFile(self, output_writer, path):
    """Extracts Windows shell item from a Windows Shortcut (LNK) file.

    Args:
      output_writer: the output writer (instance of OutputWriter).
      path: a string containing the path of the LNK file.
    """
    file_object = None

    try:
      lnk_file = pylnk.file()
      lnk_file.open_file_object(file_object)
      lnk_file.link_target_identifier_data
      lnk_file.close()
    finally:
      file_object.close()

  def _GetSignature(self, file_object):
    """Determins the if the file content contains a known signature.

    Args:
      file_object: a file-like object (instance of dfvfs.FileIO).

    Returns:
      A string containing the signature identifier or None if no known
      signature was found.
    """
    scan_state = pysigscan.scan_state()
    self._file_scanner.scan_file_object(scan_state, file_object)
    return scan_state.scan_results

  def _GetSignatureScanner(self):
    """Retrieves a signature scanner object.

    Returns:
      A scanner object (instance of pysigscan.scanner).
    """
    scanner_object = pysigscan.scanner()
    for identifier, pattern_offset, pattern in self._SIGNATURES:
      scanner_object.add_signature(
          identifier, pattern_offset, pattern,
          pysigscan.signature_flags.RELATIVE_FROM_START)

    return scanner_object

  def ExtractWindowsShellItems(self, output_writer, path):
    """Extracts Windows shell items.

    Args:
      output_writer: the output writer (instance of OutputWriter).
    """
    if self._single_file:
      # TODO: determine file type.
      file_object = self.OpenFile(path)
      signatures = self._GetSignature()
    else:
      # TODO: recurse and find supported file types.
      pass


class FileOutputWriter(object):
  """Class that defines a file output writer."""

  def __init__(self, output_directory):
    """Initializes the output writer object.

    Args:
      output_directory: a string containing the path of the output directory.
    """
    super(FileOutputWriter, self).__init__()
    self._output_directory = output_directory

  def Close(self):
    """Closes the output writer object."""
    pass

  def Open(self):
    """Opens the output writer object.

    Returns:
      A boolean containing True if successful or False if not.
    """
    return True

  def WriteShellItem(self, shell_item_data):
    """Writes a shell item.

    Args:
      shell_item_data: a binary string containing the shell item data.
    """
    with open(options.output_file, 'wb') as output_file:
      output_file.write(shell_item_data)


class StdoutOutputWriter(object):
  """Class that defines a stdout output writer."""

  def Close(self):
    """Closes the output writer object."""
    pass

  def Open(self):
    """Opens the output writer object.

    Returns:
      A boolean containing True if successful or False if not.
    """
    return True

  def WriteShellItem(self, shell_item_data):
    """Writes a shell item.

    Args:
      shell_item_data: a binary string containing the shell item data.
    """
    print(hexdump.Hexdump(shell_item_data))


def Main():
  """The main program function.

  Returns:
    A boolean containing True if successful or False if not.
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
  extractor = WindowsShellItemExtractor(debug=options.debug)

  if not extractor.ScanForWindowsVolume(options.source):
    print((u'Unable to retrieve the volume with the Windows directory from: '
           u'{0:s}.').format(options.source))
    print(u'')
    return False

  extractor.ExtractWindowsShellItems(output_writer)
  output_writer.Close()

  return True


if __name__ == '__main__':
  if not Main():
    sys.exit(1)
  else:
    sys.exit(0)
