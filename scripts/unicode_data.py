#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Script to parse UnicodeData.txt."""

from __future__ import unicode_literals

import argparse
import collections
import sys


def Main():
  """The main program function.

  Returns:
    bool: True if successful or False if not.
  """
  argument_parser = argparse.ArgumentParser(description=(
      'Parses a UnicodeData.txt file.'))

  argument_parser.add_argument(
      'source', nargs='?', action='store', metavar='PATH',
      default=None, help='path of the UnicodeData.txt file.')

  options = argument_parser.parse_args()

  if not options.source:
    print('Source file missing.')
    print('')
    argument_parser.print_help()
    print('')
    return False

  decomposition_mappings = collections.OrderedDict()

  with open(options.source, 'r') as file_object:
    for line in file_object.readlines():
      fields = line.split(';')

      unicode_character = int(fields[0], 16)

      decomposition_mapping = fields[5]

      if not decomposition_mapping:
        decomposition_mapping = [unicode_character]
      elif decomposition_mapping.startswith('<compat> '):
        decomposition_mapping = [
            int(character, 16)
            for character in decomposition_mapping[9:].split(' ')]
      elif decomposition_mapping.startswith('<'):
        decomposition_mapping = [unicode_character]
      else:
        decomposition_mapping = [
            int(character, 16) for character in decomposition_mapping.split(' ')]

      decomposition_mappings[unicode_character] = decomposition_mapping

    for unicode_character, decomposition_mapping in decomposition_mappings.items():
      is_normalized = False
      normalized_decomposition_mapping = []

      while not is_normalized:
        is_normalized = True
        normalized_decomposition_mapping = []

        for character in decomposition_mapping:
          characters = decomposition_mappings.get(character, [character])
          if characters != [character]:
            is_normalized = False

          normalized_decomposition_mapping.extend(characters)

        decomposition_mapping = normalized_decomposition_mapping

      decomposition_mappings[unicode_character] = normalized_decomposition_mapping


    mapping_ranges = {}
    range_start = 0
    for unicode_character, decomposition_mapping in decomposition_mappings.items():
      decomposition_mapping = [
          '0x{0:08x}'.format(character) for character in decomposition_mapping]

      if (len(decomposition_mapping) == 1 and
          int(decomposition_mapping[0], 16) == unicode_character):
        range_start = 0
        continue

      if range_start == 0:
        range_start = unicode_character

      mapping_ranges[range_start] = unicode_character

    last_range_end = 0
    for range_start, range_end in mapping_ranges.items():
      range_gap = range_start - last_range_end
      if last_range_end > 0 and range_gap >= 8:
        print('')

      _, remainder = divmod(range_start, 8)

      if remainder > 0 and range_gap > 0:
        if remainder >= range_gap:
          remainder = range_gap - 1
          range_value_start = last_range_end + 1
        else:
          range_value_start = range_start - remainder

        for range_value in range(0, remainder):
          print('0x{0:08x}\t0x{0:08x}'.format(range_value_start + range_value))

      for unicode_character in range(range_start, range_end + 1):
        decomposition_mapping = [
            '0x{0:08x}'.format(character)
            for character in decomposition_mappings[range_start]]

        print('0x{0:08x}\t{1:s}'.format(
            unicode_character, ', '.join(decomposition_mapping)))

      last_range_end = range_end

      # print('\t/* 0x{0:08x} */ {1:d}, {{ {2:s} }} }},'.format(
      #     unicode_character, len(decomposition_mapping),
      #     ', '.join(decomposition_mapping)))

      # print('\t{{ 0x{0:08x}, {1:d}, {{ {2:s} }} }},'.format(
      #     unicode_character, len(decomposition_mapping),
      #     ', '.join(decomposition_mapping)))

  return True


if __name__ == '__main__':
  if not Main():
    sys.exit(1)
  else:
    sys.exit(0)
