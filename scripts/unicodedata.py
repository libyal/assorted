#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Script to parse UnicodeData.txt."""

from __future__ import unicode_literals

import collections


decomposition_mappings = collections.OrderedDict()

with open('UnicodeData.txt', 'r') as file_object:
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

  for unicode_character, decomposition_mapping in decomposition_mappings.items():
    decomposition_mapping = [
        '0x{0:08x}'.format(character) for character in decomposition_mapping]

    print('\t/* 0x{0:08x} */ {1:d}, {{ {2:s} }} }},'.format(
        unicode_character, len(decomposition_mapping),
        ', '.join(decomposition_mapping)))

    # print('\t{{ 0x{0:08x}, {1:d}, {{ {2:s} }} }},'.format(
    #     unicode_character, len(decomposition_mapping),
    #     ', '.join(decomposition_mapping)))
