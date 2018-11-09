#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Script to export Unicode NFD decomposition mappings."""

from __future__ import unicode_literals

import codecs
import unicodedata


unicode_character_ranges = [
    (0x00000000, 0x0010ffff)]

unicode_character_ranges = [
    (0x000000c0, 0x0000017f),
    (0x000001a0, 0x00000237),
    (0x00000340, 0x000003d7),
    (0x00000400, 0x000004ff),
    (0x00000620, 0x000006d7),
    (0x00000928, 0x000009df),
    (0x00000a30, 0x00000a5f),
    (0x00000b48, 0x00000bcf),
    (0x00000c48, 0x00000ccf),
    (0x00000d48, 0x00000ddf),
    (0x00000f40, 0x00001027),
    (0x00001b00, 0x00001b47),
    (0x00001e00, 0x00002007),
    (0x00002120, 0x000021cf),
    (0x00002200, 0x0000232f),
    (0x00002ad8, 0x00002adf),
    (0x00003048, 0x000030ff),
    (0x0000f900, 0x0000fadf),
    (0x0000fb18, 0x0000fb4f),
    (0x00011098, 0x000110af),
    (0x00011128, 0x0001112f),
    (0x00011348, 0x0001134f),
    (0x000114b8, 0x000114bf),
    (0x000115b8, 0x000115bf),
    (0x0001d158, 0x0001d167),
    (0x0001d1b8, 0x0001d1c7),
    (0x0002f800, 0x0002fa1f)]

for unicode_character, last_unicode_character in unicode_character_ranges:
  print('libfsapfs_name_decomposition_mapping_t libfsapfs_name_decomposition_mappings_0x{0:08x}[ {1:d} ] = {{'.format(
      unicode_character, last_unicode_character - unicode_character + 1))

  while unicode_character <= last_unicode_character:
      unicode_string = chr(unicode_character)

      nfd_string = unicodedata.normalize('NFD', unicode_string)

      utf8_string = unicode_string.encode('utf-32-be')
      nfd_string = nfd_string.encode('utf-32-be')

      utf8_string = codecs.encode(utf8_string, 'hex')
      nfd_string = codecs.encode(nfd_string, 'hex')

      if last_unicode_character != 0x0010ffff:
        nfd_string = nfd_string.decode('utf-8')
        nfd_characters = [
            '0x{0:s}'.format(nfd_string[index:index + 8])
            for index in range(0, len(nfd_string), 8)]
        nfd_string = ', '.join(nfd_characters)
        output_string = '\t/* 0x{0:08x} */ {{ {1:d}, {{ {2:s} }} }}'.format(
            unicode_character, len(nfd_characters), nfd_string)
        if unicode_character == last_unicode_character:
          print('{0:s}'.format(output_string))
        else:
          print('{0:s},'.format(output_string))

      elif utf8_string != nfd_string:
        nfd_string = nfd_string.decode('utf-8')
        nfd_characters = [
            '0x{0:s}'.format(nfd_string[index:index + 8])
            for index in range(0, len(nfd_string), 8)]
        nfd_string = ' '.join(nfd_characters)
        print('\\U{0:X}\t{1:s}'.format(unicode_character, nfd_string))

      unicode_character += 1

      if unicode_character == 0x0000d800:
        unicode_character = 0x0000e000

  print('};')
  print('')

for unicode_character, last_unicode_character in unicode_character_ranges:

  output_string = (
      '\t\tif( ( unicode_character >= 0x{0:08x}UL )\n'
      '\t\t && ( unicode_character <= 0x{1:08x}UL ) )\n'
      '\t\t{{\n'
      '\t\t\tnfd_mapping = libfsapfs_name_decomposition_mappings_0x{0:08x}[ unicode_character - 0x{0:08x}UL ];\n'
      '\t\t}}\n').format(unicode_character, last_unicode_character)

  print(output_string)
