#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Script to calculate Windows Prefetch hashes."""

from __future__ import print_function
import argparse
import sys


def CalculatePrefetchHashXP(path):
  """Calculates a Windows XP Prefetch hash.

  Args:
    path: a string containing the path to calculate the Prefetch hash of.

  Returns:
    An integer containing the Prefetch hash.
  """
  path = path.upper().encode('utf-16-le')

  hash_value = 0
  for character in path:
    hash_value = ((hash_value * 37) + ord(character)) % 0x100000000

  hash_value = (hash_value * 314159269) % 0x100000000

  if hash_value > 0x80000000:
    hash_value = 0x100000000 - hash_value

  return (abs(hash_value) % 1000000007) % 0x100000000


def CalculatePrefetchHashVista(path):
  """Calculates a Windows Vista Prefetch hash.

  Args:
    path: a string containing the path to calculate the Prefetch hash of.

  Returns:
    An integer containing the Prefetch hash.
  """
  path = path.upper().encode('utf-16-le')

  hash_value = 314159

  for character in path:
    hash_value = ((hash_value * 37) + ord(character)) % 0x100000000

  return hash_value


def CalculatePrefetchHash2008(path):
  """Calculates a Windows 2008 Prefetch hash.

  Args:
    path: a string containing the path to calculate the Prefetch hash of.

  Returns:
    An integer containing the Prefetch hash.
  """
  path = path.upper().encode('utf-16-le')

  hash_value = 314159
  path_index = 0
  path_length = len(path)

  while path_index + 8 < path_length:
    character_value = ord(path[path_index + 1]) * 37
    character_value += ord(path[path_index + 2])
    character_value *= 37
    character_value += ord(path[path_index + 3])
    character_value *= 37
    character_value += ord(path[path_index + 4])
    character_value *= 37
    character_value += ord(path[path_index + 5])
    character_value *= 37
    character_value += ord(path[path_index + 6])
    character_value *= 37
    character_value += ord(path[path_index]) * 442596621
    character_value += ord(path[path_index + 7])

    hash_value = (character_value - (hash_value * 803794207)) % 0x100000000

    path_index += 8

  while path_index < path_length:
    hash_value = ((37 * hash_value) + ord(path[path_index])) % 0x100000000

    path_index += 1

  return hash_value


def Main():
  """The main program function.

  Returns:
    A boolean containing True if successful or False if not.
  """
  argument_parser = argparse.ArgumentParser(description=(
      u'Calculate Windows Prefetch hashes'))

  argument_parser.add_argument(
      u'path', nargs=u'?', action=u'store', metavar=u'PATH',
      default=None, help=u'path to calculate the Prefetch hash of.')

  options = argument_parser.parse_args()

  if not options.path:
    print(u'Path missing.')
    print(u'')
    argument_parser.print_help()
    print(u'')
    return False

  print(u'Windows Prefetch hashes:')

  prefetch_hash = CalculatePrefetchHashXP(options.path)
  print(u'\tWindows XP\t: 0x{0:08x}'.format(prefetch_hash))

  prefetch_hash = CalculatePrefetchHashVista(options.path)
  print(u'\tWindows Vista\t: 0x{0:08x}'.format(prefetch_hash))

  prefetch_hash = CalculatePrefetchHash2008(options.path)
  print(u'\tWindows 2008\t: 0x{0:08x}'.format(prefetch_hash))

  print(u'')

  return True


if __name__ == '__main__':
  if not Main():
    sys.exit(1)
  else:
    sys.exit(0)
