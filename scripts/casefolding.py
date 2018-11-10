#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Script to parse CaseFolding.txt."""

from __future__ import unicode_literals


last_unicode_character = 0
last_mappings = []

with open('CaseFolding.txt', 'r') as file_object:
  for line in file_object.readlines():
    line = line.strip()
    if not line or line[0] == '#':
      continue

    fields = line.split(';')

    status_field = fields[1].strip()
    if status_field not in ('C', 'S'):
      continue

    unicode_character = int(fields[0], 16)

    case_folding_mapping = fields[2].strip()
    case_folding_mapping = [
        int(character, 16) for character in case_folding_mapping.split(' ')]

    block_end = last_unicode_character - int(last_unicode_character % 8) + 7
    if last_unicode_character != 0:
      if unicode_character > block_end:
        fill_end = block_end
      else:
        fill_end = unicode_character - 1

      while last_unicode_character < fill_end:
        last_unicode_character += 1
        last_mappings.append((last_unicode_character, [last_unicode_character]))

    if unicode_character != last_unicode_character + 1:
      block_start = unicode_character - int(unicode_character % 8)

      if last_unicode_character != 0 and block_start - block_end < 128:
        block_start = block_end + 1

      if last_unicode_character < block_start and block_start != block_end + 1:
        if last_unicode_character != 0:
          while last_unicode_character < block_end:
            last_unicode_character += 1
            last_mappings.append(
                (last_unicode_character, [last_unicode_character]))

          print((
              'uint32_t libfsapfs_name_case_folding_mappings_0x{0:08x}'
              '[ {1:d} ] = {{').format(last_mappings[0][0], len(last_mappings)))

          for character, mapped_character in last_mappings:
            print('\t/* 0x{0:08x} */ 0x{1:08x},'.format(
                character, mapped_character[0]))

          print('};')
          print('')

          last_mappings = []

      last_unicode_character = block_start
      while last_unicode_character < unicode_character:
        last_mappings.append((last_unicode_character, [last_unicode_character]))
        last_unicode_character += 1

    # print('\t/* 0x{0:08x} */ {1:d}, {{ {2:s} }} }},'.format(
    #     unicode_character, len(case_folding_mapping),
    #     ', '.join(case_folding_mapping)))

    last_mappings.append((unicode_character, case_folding_mapping))

    last_unicode_character = unicode_character
