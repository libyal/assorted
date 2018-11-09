#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Script to export Unicode NFD decomposition mappings."""

from __future__ import unicode_literals

import codecs
import unicodedata

unicode_character = 0

while unicode_character <= 0x0010ffff:
    unicode_string = chr(unicode_character)

    nfd_string = unicodedata.normalize('NFKD', unicode_string)

    utf8_string = unicode_string.encode('utf-32-be')
    nfd_string = nfd_string.encode('utf-32-be')

    utf8_string = codecs.encode(utf8_string, 'hex')
    nfd_string = codecs.encode(nfd_string, 'hex')

    if utf8_string != nfd_string:
      nfd_string = nfd_string.decode('utf-8')
      nfd_string = ' '.join([
          nfd_string[index:index + 8]
          for index in range(0, len(nfd_string), 8)])
      print('\\U{0:X}\t{1:s}'.format(unicode_character, nfd_string))

    unicode_character += 1

    if unicode_character == 0x0000d800:
      unicode_character = 0x0000e000
