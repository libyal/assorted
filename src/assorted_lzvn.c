/*
 * LZVN (un)compression functions
 *
 * Copyright (C) 2008-2022, Joachim Metz <joachim.metz@gmail.com>
 *
 * Refer to AUTHORS for acknowledgements.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <common.h>
#include <memory.h>
#include <types.h>

#include "assorted_libcerror.h"
#include "assorted_libcnotify.h"
#include "assorted_lzvn.h"

enum ASSORTED_LZVN_OPPCODE_TYPES
{
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_LARGE,
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_MEDIUM,
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_PREVIOUS,
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,
	ASSORTED_LZVN_OPPCODE_TYPE_END_OF_STREAM,
	ASSORTED_LZVN_OPPCODE_TYPE_INVALID,
	ASSORTED_LZVN_OPPCODE_TYPE_LITERAL_LARGE,
	ASSORTED_LZVN_OPPCODE_TYPE_LITERAL_SMALL,
	ASSORTED_LZVN_OPPCODE_TYPE_MATCH_LARGE,
	ASSORTED_LZVN_OPPCODE_TYPE_MATCH_SMALL,
	ASSORTED_LZVN_OPPCODE_TYPE_NONE,
};

/* Lookup table to map an oppcode to its type
 */
uint8_t assorted_lzvn_oppcode_types[ 256 ] = {
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x00 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x01 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x02 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x03 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x04 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x05 */
	ASSORTED_LZVN_OPPCODE_TYPE_END_OF_STREAM,	/* 0x06 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_LARGE,	/* 0x07 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x08 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x09 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x0a */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x0b */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x0c */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x0d */
	ASSORTED_LZVN_OPPCODE_TYPE_NONE,			/* 0x0e */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_LARGE,	/* 0x0f */

	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x10 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x11 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x12 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x13 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x14 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x15 */
	ASSORTED_LZVN_OPPCODE_TYPE_NONE,			/* 0x16 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_LARGE,	/* 0x17 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x18 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x19 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x1a */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x1b */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x1c */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x1d */
	ASSORTED_LZVN_OPPCODE_TYPE_INVALID,		/* 0x1e */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_LARGE,	/* 0x1f */

	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x20 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x21 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x22 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x23 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x24 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x25 */
	ASSORTED_LZVN_OPPCODE_TYPE_INVALID,		/* 0x26 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_LARGE,	/* 0x27 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x28 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x29 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x2a */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x2b */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x2c */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x2d */
	ASSORTED_LZVN_OPPCODE_TYPE_INVALID,		/* 0x2e */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_LARGE,	/* 0x2f */

	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x30 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x31 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x32 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x33 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x34 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x35 */
	ASSORTED_LZVN_OPPCODE_TYPE_INVALID,		/* 0x36 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_LARGE,	/* 0x37 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x38 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x39 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x3a */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x3b */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x3c */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x3d */
	ASSORTED_LZVN_OPPCODE_TYPE_INVALID,		/* 0x3e */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_LARGE,	/* 0x3f */

	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x40 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x41 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x42 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x43 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x44 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x45 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_PREVIOUS,	/* 0x46 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_LARGE,	/* 0x47 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x48 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x49 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x4a */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x4b */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x4c */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x4d */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_PREVIOUS,	/* 0x4e */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_LARGE,	/* 0x4f */

	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x50 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x51 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x52 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x53 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x54 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x55 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_PREVIOUS,	/* 0x56 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_LARGE,	/* 0x57 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x58 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x59 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x5a */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x5b */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x5c */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x5d */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_PREVIOUS,	/* 0x5e */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_LARGE,	/* 0x5f */

	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x60 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x61 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x62 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x63 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x64 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x65 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_PREVIOUS,	/* 0x66 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_LARGE,	/* 0x67 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x68 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x69 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x6a */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x6b */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x6c */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x6d */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_PREVIOUS,	/* 0x6e */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_LARGE,	/* 0x6f */

	ASSORTED_LZVN_OPPCODE_TYPE_INVALID,		/* 0x70 */
	ASSORTED_LZVN_OPPCODE_TYPE_INVALID,		/* 0x71 */
	ASSORTED_LZVN_OPPCODE_TYPE_INVALID,		/* 0x72 */
	ASSORTED_LZVN_OPPCODE_TYPE_INVALID,		/* 0x73 */
	ASSORTED_LZVN_OPPCODE_TYPE_INVALID,		/* 0x74 */
	ASSORTED_LZVN_OPPCODE_TYPE_INVALID,		/* 0x75 */
	ASSORTED_LZVN_OPPCODE_TYPE_INVALID,		/* 0x76 */
	ASSORTED_LZVN_OPPCODE_TYPE_INVALID,		/* 0x77 */
	ASSORTED_LZVN_OPPCODE_TYPE_INVALID,		/* 0x78 */
	ASSORTED_LZVN_OPPCODE_TYPE_INVALID,		/* 0x79 */
	ASSORTED_LZVN_OPPCODE_TYPE_INVALID,		/* 0x7a */
	ASSORTED_LZVN_OPPCODE_TYPE_INVALID,		/* 0x7b */
	ASSORTED_LZVN_OPPCODE_TYPE_INVALID,		/* 0x7c */
	ASSORTED_LZVN_OPPCODE_TYPE_INVALID,		/* 0x7d */
	ASSORTED_LZVN_OPPCODE_TYPE_INVALID,		/* 0x7e */
	ASSORTED_LZVN_OPPCODE_TYPE_INVALID,		/* 0x7f */

	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x80 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x81 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x82 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x83 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x84 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x85 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_PREVIOUS,	/* 0x86 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_LARGE,	/* 0x87 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x88 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x89 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x8a */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x8b */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x8c */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x8d */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_PREVIOUS,	/* 0x8e */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_LARGE,	/* 0x8f */

	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x90 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x91 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x92 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x93 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x94 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x95 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_PREVIOUS,	/* 0x96 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_LARGE,	/* 0x97 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x98 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x99 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x9a */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x9b */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x9c */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x9d */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_PREVIOUS,	/* 0x9e */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_LARGE,	/* 0x9f */

	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_MEDIUM,	/* 0xa0 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_MEDIUM,	/* 0xa1 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_MEDIUM,	/* 0xa2 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_MEDIUM,	/* 0xa3 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_MEDIUM,	/* 0xa4 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_MEDIUM,	/* 0xa5 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_MEDIUM,	/* 0xa6 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_MEDIUM,	/* 0xa7 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_MEDIUM,	/* 0xa8 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_MEDIUM,	/* 0xa9 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_MEDIUM,	/* 0xaa */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_MEDIUM,	/* 0xab */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_MEDIUM,	/* 0xac */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_MEDIUM,	/* 0xad */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_MEDIUM,	/* 0xae */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_MEDIUM,	/* 0xaf */

	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_MEDIUM,	/* 0xb0 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_MEDIUM,	/* 0xb1 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_MEDIUM,	/* 0xb2 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_MEDIUM,	/* 0xb3 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_MEDIUM,	/* 0xb4 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_MEDIUM,	/* 0xb5 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_MEDIUM,	/* 0xb6 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_MEDIUM,	/* 0xb7 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_MEDIUM,	/* 0xb8 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_MEDIUM,	/* 0xb9 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_MEDIUM,	/* 0xba */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_MEDIUM,	/* 0xbb */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_MEDIUM,	/* 0xbc */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_MEDIUM,	/* 0xbd */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_MEDIUM,	/* 0xbe */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_MEDIUM,	/* 0xbf */

	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0xc0 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0xc1 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0xc2 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0xc3 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0xc4 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0xc5 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_PREVIOUS,	/* 0xc6 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_LARGE,	/* 0xc7 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0xc8 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0xc9 */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0xca */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0xcb */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0xcc */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0xcd */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_PREVIOUS,	/* 0xce */
	ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_LARGE,	/* 0xcf */

	ASSORTED_LZVN_OPPCODE_TYPE_INVALID,		/* 0xd0 */
	ASSORTED_LZVN_OPPCODE_TYPE_INVALID,		/* 0xd1 */
	ASSORTED_LZVN_OPPCODE_TYPE_INVALID,		/* 0xd2 */
	ASSORTED_LZVN_OPPCODE_TYPE_INVALID,		/* 0xd3 */
	ASSORTED_LZVN_OPPCODE_TYPE_INVALID,		/* 0xd4 */
	ASSORTED_LZVN_OPPCODE_TYPE_INVALID,		/* 0xd5 */
	ASSORTED_LZVN_OPPCODE_TYPE_INVALID,		/* 0xd6 */
	ASSORTED_LZVN_OPPCODE_TYPE_INVALID,		/* 0xd7 */
	ASSORTED_LZVN_OPPCODE_TYPE_INVALID,		/* 0xd8 */
	ASSORTED_LZVN_OPPCODE_TYPE_INVALID,		/* 0xd9 */
	ASSORTED_LZVN_OPPCODE_TYPE_INVALID,		/* 0xda */
	ASSORTED_LZVN_OPPCODE_TYPE_INVALID,		/* 0xdb */
	ASSORTED_LZVN_OPPCODE_TYPE_INVALID,		/* 0xdc */
	ASSORTED_LZVN_OPPCODE_TYPE_INVALID,		/* 0xdd */
	ASSORTED_LZVN_OPPCODE_TYPE_INVALID,		/* 0xde */
	ASSORTED_LZVN_OPPCODE_TYPE_INVALID,		/* 0xdf */

	ASSORTED_LZVN_OPPCODE_TYPE_LITERAL_LARGE,	/* 0xe0 */
	ASSORTED_LZVN_OPPCODE_TYPE_LITERAL_SMALL,	/* 0xe1 */
	ASSORTED_LZVN_OPPCODE_TYPE_LITERAL_SMALL,	/* 0xe2 */
	ASSORTED_LZVN_OPPCODE_TYPE_LITERAL_SMALL,	/* 0xe3 */
	ASSORTED_LZVN_OPPCODE_TYPE_LITERAL_SMALL,	/* 0xe4 */
	ASSORTED_LZVN_OPPCODE_TYPE_LITERAL_SMALL,	/* 0xe5 */
	ASSORTED_LZVN_OPPCODE_TYPE_LITERAL_SMALL,	/* 0xe6 */
	ASSORTED_LZVN_OPPCODE_TYPE_LITERAL_SMALL,	/* 0xe7 */
	ASSORTED_LZVN_OPPCODE_TYPE_LITERAL_SMALL,	/* 0xe8 */
	ASSORTED_LZVN_OPPCODE_TYPE_LITERAL_SMALL,	/* 0xe9 */
	ASSORTED_LZVN_OPPCODE_TYPE_LITERAL_SMALL,	/* 0xea */
	ASSORTED_LZVN_OPPCODE_TYPE_LITERAL_SMALL,	/* 0xeb */
	ASSORTED_LZVN_OPPCODE_TYPE_LITERAL_SMALL,	/* 0xec */
	ASSORTED_LZVN_OPPCODE_TYPE_LITERAL_SMALL,	/* 0xed */
	ASSORTED_LZVN_OPPCODE_TYPE_LITERAL_SMALL,	/* 0xee */
	ASSORTED_LZVN_OPPCODE_TYPE_LITERAL_SMALL,	/* 0xef */

	ASSORTED_LZVN_OPPCODE_TYPE_MATCH_LARGE,		/* 0xf0 */
	ASSORTED_LZVN_OPPCODE_TYPE_MATCH_SMALL,		/* 0xf1 */
	ASSORTED_LZVN_OPPCODE_TYPE_MATCH_SMALL,		/* 0xf2 */
	ASSORTED_LZVN_OPPCODE_TYPE_MATCH_SMALL,		/* 0xf3 */
	ASSORTED_LZVN_OPPCODE_TYPE_MATCH_SMALL,		/* 0xf4 */
	ASSORTED_LZVN_OPPCODE_TYPE_MATCH_SMALL,		/* 0xf5 */
	ASSORTED_LZVN_OPPCODE_TYPE_MATCH_SMALL,		/* 0xf6 */
	ASSORTED_LZVN_OPPCODE_TYPE_MATCH_SMALL,		/* 0xf7 */
	ASSORTED_LZVN_OPPCODE_TYPE_MATCH_SMALL,		/* 0xf8 */
	ASSORTED_LZVN_OPPCODE_TYPE_MATCH_SMALL,		/* 0xf9 */
	ASSORTED_LZVN_OPPCODE_TYPE_MATCH_SMALL,		/* 0xfa */
	ASSORTED_LZVN_OPPCODE_TYPE_MATCH_SMALL,		/* 0xfb */
	ASSORTED_LZVN_OPPCODE_TYPE_MATCH_SMALL,		/* 0xfc */
	ASSORTED_LZVN_OPPCODE_TYPE_MATCH_SMALL,		/* 0xfd */
	ASSORTED_LZVN_OPPCODE_TYPE_MATCH_SMALL,		/* 0xfe */
	ASSORTED_LZVN_OPPCODE_TYPE_MATCH_SMALL,		/* 0xff */
};

/* Decompresses LZVN compressed data
 * Returns 1 on success or -1 on error
 */
int assorted_lzvn_decompress(
     const uint8_t *compressed_data,
     size_t compressed_data_size,
     uint8_t *uncompressed_data,
     size_t *uncompressed_data_size,
     libcerror_error_t **error )
{
	static char *function              = "assorted_lzvn_decompress";
	size_t compressed_data_offset      = 0;
	size_t match_offset                = 0;
	size_t safe_uncompressed_data_size = 0;
	size_t uncompressed_data_offset    = 0;
	uint16_t distance                  = 0;
	uint16_t literal_size              = 0;
	uint16_t match_size                = 0;
	uint8_t oppcode                    = 0;
	uint8_t oppcode_type               = 0;
	uint8_t oppcode_value              = 0;

#if defined( HAVE_DEBUG_OUTPUT )
	size_t debug_match_offset          = 0;
	size_t oppcode_data_offset         = 0;
	size_t oppcode_data_size           = 0;
	uint16_t debug_match_size          = 0;
#endif

	if( compressed_data == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid compressed data.",
		 function );

		return( -1 );
	}
	if( compressed_data_size > (size_t) SSIZE_MAX )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_EXCEEDS_MAXIMUM,
		 "%s: invalid compressed data size value exceeds maximum.",
		 function );

		return( -1 );
	}
	if( uncompressed_data == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid uncompressed data.",
		 function );

		return( -1 );
	}
	if( uncompressed_data_size == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid uncompressed data size.",
		 function );

		return( -1 );
	}
	safe_uncompressed_data_size = *uncompressed_data_size;

	if( safe_uncompressed_data_size > (size_t) SSIZE_MAX )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_EXCEEDS_MAXIMUM,
		 "%s: invalid uncompressed data size value exceeds maximum.",
		 function );

		return( -1 );
	}
	while( compressed_data_offset < compressed_data_size )
	{
		if( uncompressed_data_offset >= safe_uncompressed_data_size )
		{
			break;
		}
		if( compressed_data_offset >= compressed_data_size )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
			 LIBCERROR_ARGUMENT_ERROR_VALUE_TOO_SMALL,
			 "%s: compressed data size value too small.",
			 function );

			return( -1 );
		}
#if defined( HAVE_DEBUG_OUTPUT )
		oppcode_data_offset = compressed_data_offset;
		oppcode_data_size   = 1;
#endif
		oppcode = compressed_data[ compressed_data_offset++ ];

		oppcode_type = assorted_lzvn_oppcode_types[ oppcode ];

		literal_size = 0;
		match_size   = 0;

		switch( oppcode_type )
		{
			case ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_LARGE:
#if defined( HAVE_DEBUG_OUTPUT )
				oppcode_data_size += 2;
#endif
				if( ( compressed_data_offset + 1 ) >= compressed_data_size )
				{
					libcerror_error_set(
					 error,
					 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
					 LIBCERROR_ARGUMENT_ERROR_VALUE_TOO_SMALL,
					 "%s: compressed data size value too small.",
					 function );

					return( -1 );
				}
				oppcode_value = compressed_data[ compressed_data_offset++ ];

				literal_size = ( oppcode & 0xc0 ) >> 6;
				match_size   = ( ( oppcode & 0x38 ) >> 3 ) + 3;
				distance     = ( (uint16_t) compressed_data[ compressed_data_offset++ ] << 8 ) | oppcode_value;

				break;

			case ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_MEDIUM:
#if defined( HAVE_DEBUG_OUTPUT )
				oppcode_data_size += 2;
#endif
				if( ( compressed_data_offset + 1 ) >= compressed_data_size )
				{
					libcerror_error_set(
					 error,
					 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
					 LIBCERROR_ARGUMENT_ERROR_VALUE_TOO_SMALL,
					 "%s: compressed data size value too small.",
					 function );

					return( -1 );
				}
				oppcode_value = compressed_data[ compressed_data_offset++ ];

				literal_size = ( oppcode & 0x18 ) >> 3;
				match_size   = ( ( ( oppcode & 0x07 ) << 2 ) | ( oppcode_value & 0x03 ) ) + 3;
				distance     = ( (uint16_t) compressed_data[ compressed_data_offset++ ] << 6 ) | ( ( oppcode_value & 0xfc ) >> 2 );

				break;

			case ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_PREVIOUS:
				literal_size = ( oppcode & 0xc0 ) >> 6;
				match_size   = ( ( oppcode & 0x38 ) >> 3 ) + 3;

				break;

			case ASSORTED_LZVN_OPPCODE_TYPE_DISTANCE_SMALL:
#if defined( HAVE_DEBUG_OUTPUT )
				oppcode_data_size += 1;
#endif
				if( compressed_data_offset >= compressed_data_size )
				{
					libcerror_error_set(
					 error,
					 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
					 LIBCERROR_ARGUMENT_ERROR_VALUE_TOO_SMALL,
					 "%s: compressed data size value too small.",
					 function );

					return( -1 );
				}
				literal_size = ( oppcode & 0xc0 ) >> 6;
				match_size   = ( ( oppcode & 0x38 ) >> 3 ) + 3;
				distance     = ( (uint16_t) ( oppcode & 0x07 ) << 8 ) | compressed_data[ compressed_data_offset++ ];

				break;

			case ASSORTED_LZVN_OPPCODE_TYPE_LITERAL_LARGE:
#if defined( HAVE_DEBUG_OUTPUT )
				oppcode_data_size += 1;
#endif
				if( compressed_data_offset >= compressed_data_size )
				{
					libcerror_error_set(
					 error,
					 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
					 LIBCERROR_ARGUMENT_ERROR_VALUE_TOO_SMALL,
					 "%s: compressed data size value too small.",
					 function );

					return( -1 );
				}
				literal_size = (uint16_t) compressed_data[ compressed_data_offset++ ] + 16;

				break;

			case ASSORTED_LZVN_OPPCODE_TYPE_LITERAL_SMALL:
				literal_size = oppcode & 0x0f;

				break;

			case ASSORTED_LZVN_OPPCODE_TYPE_MATCH_LARGE:
#if defined( HAVE_DEBUG_OUTPUT )
				oppcode_data_size += 1;
#endif
				if( compressed_data_offset >= compressed_data_size )
				{
					libcerror_error_set(
					 error,
					 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
					 LIBCERROR_ARGUMENT_ERROR_VALUE_TOO_SMALL,
					 "%s: compressed data size value too small.",
					 function );

					return( -1 );
				}
				match_size = (uint16_t) compressed_data[ compressed_data_offset++ ] + 16;

				break;

			case ASSORTED_LZVN_OPPCODE_TYPE_MATCH_SMALL:
				match_size = oppcode & 0x0f;

				break;

			case ASSORTED_LZVN_OPPCODE_TYPE_END_OF_STREAM:
			case ASSORTED_LZVN_OPPCODE_TYPE_NONE:
				break;

			case ASSORTED_LZVN_OPPCODE_TYPE_INVALID:
			default:
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_RUNTIME,
				 LIBCERROR_RUNTIME_ERROR_UNSUPPORTED_VALUE,
				 "%s: invalid oppcode: 0x%02" PRIx8 ".",
				 function,
				 oppcode );

				return( -1 );
		}
#if defined( HAVE_DEBUG_OUTPUT )
		if( libcnotify_verbose != 0 )
		{
			libcnotify_printf(
			 "%s: oppcode data:\n",
			 function );
			libcnotify_print_data(
			 &( compressed_data[ oppcode_data_offset ] ),
			 oppcode_data_size,
			 LIBCNOTIFY_PRINT_DATA_FLAG_GROUP_DATA );

			libcnotify_printf(
			 "%s: oppcode\t\t\t\t\t\t: 0x%02" PRIx8 "\n",
			 function,
			 oppcode );

			libcnotify_printf(
			 "%s: literal size\t\t\t\t\t\t: %" PRIu16 "\n",
			 function,
			 literal_size );

			libcnotify_printf(
			 "%s: match size\t\t\t\t\t\t: %" PRIu16 "\n",
			 function,
			 match_size );

			libcnotify_printf(
			 "%s: distance\t\t\t\t\t\t: %" PRIu16 "\n",
			 function,
			 distance );

			libcnotify_printf(
			 "\n" );
		}
#endif /* defined( HAVE_DEBUG_OUTPUT ) */

		if( oppcode_type == ASSORTED_LZVN_OPPCODE_TYPE_END_OF_STREAM )
		{
			break;
		}
		if( literal_size > 0 )
		{
			if( ( (size_t) literal_size > compressed_data_size )
			 || ( compressed_data_offset > ( compressed_data_size - literal_size ) ) )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_RUNTIME,
				 LIBCERROR_RUNTIME_ERROR_VALUE_OUT_OF_BOUNDS,
				 "%s: literal size value exceeds compressed data size.",
				 function );

				return( -1 );
			}
			if( ( (size_t) literal_size > safe_uncompressed_data_size )
			 || ( uncompressed_data_offset > ( safe_uncompressed_data_size - literal_size ) ) )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_RUNTIME,
				 LIBCERROR_RUNTIME_ERROR_VALUE_OUT_OF_BOUNDS,
				 "%s: literal size value exceeds uncompressed data size.",
				 function );

				return( -1 );
			}
#if defined( HAVE_DEBUG_OUTPUT )
			if( libcnotify_verbose != 0 )
			{
				libcnotify_printf(
				 "%s: literal:\n",
				 function );
				libcnotify_print_data(
				 &( compressed_data[ compressed_data_offset ] ),
				 literal_size,
				 LIBCNOTIFY_PRINT_DATA_FLAG_GROUP_DATA );
			}
#endif
			if( memory_copy(
			     &( uncompressed_data[ uncompressed_data_offset ] ),
			     &( compressed_data[ compressed_data_offset ] ),
			     (size_t) literal_size ) == NULL )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_MEMORY,
				 LIBCERROR_MEMORY_ERROR_COPY_FAILED,
				 "%s: unable to copy literal to uncompressed data.",
				 function );

				return( -1 );
			}
			compressed_data_offset   += (size_t) literal_size;
			uncompressed_data_offset += (size_t) literal_size;
		}
		if( match_size > 0 )
		{
			if( (size_t) distance > uncompressed_data_offset )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_RUNTIME,
				 LIBCERROR_RUNTIME_ERROR_VALUE_OUT_OF_BOUNDS,
				 "%s: distance value exceeds uncompressed data offset.",
				 function );

				return( -1 );
			}
			match_offset = uncompressed_data_offset - distance;

			if( ( (size_t) match_size > safe_uncompressed_data_size )
			 || ( uncompressed_data_offset > ( safe_uncompressed_data_size - match_size ) ) )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_RUNTIME,
				 LIBCERROR_RUNTIME_ERROR_VALUE_OUT_OF_BOUNDS,
				 "%s: match size value exceeds uncompressed data size.",
				 function );

				return( -1 );
			}
#if defined( HAVE_DEBUG_OUTPUT )
			if( libcnotify_verbose != 0 )
			{
				debug_match_offset = match_offset;
				debug_match_size   = match_size;

				libcnotify_printf(
				 "%s: match offset\t\t\t\t\t\t: 0x%" PRIzx "\n",
				 function,
				 debug_match_offset );
			}
#endif
			while( match_size > 0 )
			{
				uncompressed_data[ uncompressed_data_offset++ ] = uncompressed_data[ match_offset++ ];

				match_size--;
			}
#if defined( HAVE_DEBUG_OUTPUT )
			if( libcnotify_verbose != 0 )
			{
				libcnotify_printf(
				 "%s: match:\n",
				 function );
				libcnotify_print_data(
				 &( uncompressed_data[ debug_match_offset ] ),
				 debug_match_size,
				 LIBCNOTIFY_PRINT_DATA_FLAG_GROUP_DATA );
			}
#endif
		}
	}
	*uncompressed_data_size = uncompressed_data_offset;

	return( 1 );
}

