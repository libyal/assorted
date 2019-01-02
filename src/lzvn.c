/*
 * LZVN (un)compression functions
 *
 * Copyright (C) 2008-2019, Joachim Metz <joachim.metz@gmail.com>
 *
 * Refer to AUTHORS for acknowledgements.
 *
 * This software is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this software.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <common.h>
#include <memory.h>
#include <types.h>

#include "assorted_libcerror.h"
#include "assorted_libcnotify.h"
#include "lzvn.h"

enum LZVN_OPPCODE_TYPES
{
	LZVN_OPPCODE_TYPE_DISTANCE_LARGE,
	LZVN_OPPCODE_TYPE_DISTANCE_MEDIUM,
	LZVN_OPPCODE_TYPE_DISTANCE_PREVIOUS,
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,
	LZVN_OPPCODE_TYPE_END_OF_STREAM,
	LZVN_OPPCODE_TYPE_INVALID,
	LZVN_OPPCODE_TYPE_LITERAL_LARGE,
	LZVN_OPPCODE_TYPE_LITERAL_SMALL,
	LZVN_OPPCODE_TYPE_MATCH_LARGE,
	LZVN_OPPCODE_TYPE_MATCH_SMALL,
	LZVN_OPPCODE_TYPE_NONE,
};

/* Lookup table to map an oppcode to its type
 */
uint8_t lzvn_oppcode_types[ 256 ] = {
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x00 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x01 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x02 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x03 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x04 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x05 */
	LZVN_OPPCODE_TYPE_END_OF_STREAM,	/* 0x06 */
	LZVN_OPPCODE_TYPE_DISTANCE_LARGE,	/* 0x07 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x08 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x09 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x0a */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x0b */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x0c */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x0d */
	LZVN_OPPCODE_TYPE_NONE,			/* 0x0e */
	LZVN_OPPCODE_TYPE_DISTANCE_LARGE,	/* 0x0f */

	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x10 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x11 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x12 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x13 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x14 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x15 */
	LZVN_OPPCODE_TYPE_NONE,			/* 0x16 */
	LZVN_OPPCODE_TYPE_DISTANCE_LARGE,	/* 0x17 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x18 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x19 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x1a */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x1b */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x1c */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x1d */
	LZVN_OPPCODE_TYPE_INVALID,		/* 0x1e */
	LZVN_OPPCODE_TYPE_DISTANCE_LARGE,	/* 0x1f */

	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x20 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x21 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x22 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x23 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x24 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x25 */
	LZVN_OPPCODE_TYPE_INVALID,		/* 0x26 */
	LZVN_OPPCODE_TYPE_DISTANCE_LARGE,	/* 0x27 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x28 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x29 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x2a */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x2b */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x2c */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x2d */
	LZVN_OPPCODE_TYPE_INVALID,		/* 0x2e */
	LZVN_OPPCODE_TYPE_DISTANCE_LARGE,	/* 0x2f */

	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x30 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x31 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x32 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x33 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x34 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x35 */
	LZVN_OPPCODE_TYPE_INVALID,		/* 0x36 */
	LZVN_OPPCODE_TYPE_DISTANCE_LARGE,	/* 0x37 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x38 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x39 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x3a */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x3b */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x3c */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x3d */
	LZVN_OPPCODE_TYPE_INVALID,		/* 0x3e */
	LZVN_OPPCODE_TYPE_DISTANCE_LARGE,	/* 0x3f */

	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x40 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x41 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x42 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x43 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x44 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x45 */
	LZVN_OPPCODE_TYPE_DISTANCE_PREVIOUS,	/* 0x46 */
	LZVN_OPPCODE_TYPE_DISTANCE_LARGE,	/* 0x47 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x48 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x49 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x4a */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x4b */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x4c */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x4d */
	LZVN_OPPCODE_TYPE_DISTANCE_PREVIOUS,	/* 0x4e */
	LZVN_OPPCODE_TYPE_DISTANCE_LARGE,	/* 0x4f */

	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x50 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x51 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x52 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x53 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x54 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x55 */
	LZVN_OPPCODE_TYPE_DISTANCE_PREVIOUS,	/* 0x56 */
	LZVN_OPPCODE_TYPE_DISTANCE_LARGE,	/* 0x57 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x58 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x59 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x5a */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x5b */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x5c */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x5d */
	LZVN_OPPCODE_TYPE_DISTANCE_PREVIOUS,	/* 0x5e */
	LZVN_OPPCODE_TYPE_DISTANCE_LARGE,	/* 0x5f */

	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x60 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x61 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x62 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x63 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x64 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x65 */
	LZVN_OPPCODE_TYPE_DISTANCE_PREVIOUS,	/* 0x66 */
	LZVN_OPPCODE_TYPE_DISTANCE_LARGE,	/* 0x67 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x68 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x69 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x6a */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x6b */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x6c */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x6d */
	LZVN_OPPCODE_TYPE_DISTANCE_PREVIOUS,	/* 0x6e */
	LZVN_OPPCODE_TYPE_DISTANCE_LARGE,	/* 0x6f */

	LZVN_OPPCODE_TYPE_INVALID,		/* 0x70 */
	LZVN_OPPCODE_TYPE_INVALID,		/* 0x71 */
	LZVN_OPPCODE_TYPE_INVALID,		/* 0x72 */
	LZVN_OPPCODE_TYPE_INVALID,		/* 0x73 */
	LZVN_OPPCODE_TYPE_INVALID,		/* 0x74 */
	LZVN_OPPCODE_TYPE_INVALID,		/* 0x75 */
	LZVN_OPPCODE_TYPE_INVALID,		/* 0x76 */
	LZVN_OPPCODE_TYPE_INVALID,		/* 0x77 */
	LZVN_OPPCODE_TYPE_INVALID,		/* 0x78 */
	LZVN_OPPCODE_TYPE_INVALID,		/* 0x79 */
	LZVN_OPPCODE_TYPE_INVALID,		/* 0x7a */
	LZVN_OPPCODE_TYPE_INVALID,		/* 0x7b */
	LZVN_OPPCODE_TYPE_INVALID,		/* 0x7c */
	LZVN_OPPCODE_TYPE_INVALID,		/* 0x7d */
	LZVN_OPPCODE_TYPE_INVALID,		/* 0x7e */
	LZVN_OPPCODE_TYPE_INVALID,		/* 0x7f */

	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x80 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x81 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x82 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x83 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x84 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x85 */
	LZVN_OPPCODE_TYPE_DISTANCE_PREVIOUS,	/* 0x86 */
	LZVN_OPPCODE_TYPE_DISTANCE_LARGE,	/* 0x87 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x88 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x89 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x8a */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x8b */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x8c */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x8d */
	LZVN_OPPCODE_TYPE_DISTANCE_PREVIOUS,	/* 0x8e */
	LZVN_OPPCODE_TYPE_DISTANCE_LARGE,	/* 0x8f */

	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x90 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x91 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x92 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x93 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x94 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x95 */
	LZVN_OPPCODE_TYPE_DISTANCE_PREVIOUS,	/* 0x96 */
	LZVN_OPPCODE_TYPE_DISTANCE_LARGE,	/* 0x97 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x98 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x99 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x9a */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x9b */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x9c */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0x9d */
	LZVN_OPPCODE_TYPE_DISTANCE_PREVIOUS,	/* 0x9e */
	LZVN_OPPCODE_TYPE_DISTANCE_LARGE,	/* 0x9f */

	LZVN_OPPCODE_TYPE_DISTANCE_MEDIUM,	/* 0xa0 */
	LZVN_OPPCODE_TYPE_DISTANCE_MEDIUM,	/* 0xa1 */
	LZVN_OPPCODE_TYPE_DISTANCE_MEDIUM,	/* 0xa2 */
	LZVN_OPPCODE_TYPE_DISTANCE_MEDIUM,	/* 0xa3 */
	LZVN_OPPCODE_TYPE_DISTANCE_MEDIUM,	/* 0xa4 */
	LZVN_OPPCODE_TYPE_DISTANCE_MEDIUM,	/* 0xa5 */
	LZVN_OPPCODE_TYPE_DISTANCE_MEDIUM,	/* 0xa6 */
	LZVN_OPPCODE_TYPE_DISTANCE_MEDIUM,	/* 0xa7 */
	LZVN_OPPCODE_TYPE_DISTANCE_MEDIUM,	/* 0xa8 */
	LZVN_OPPCODE_TYPE_DISTANCE_MEDIUM,	/* 0xa9 */
	LZVN_OPPCODE_TYPE_DISTANCE_MEDIUM,	/* 0xaa */
	LZVN_OPPCODE_TYPE_DISTANCE_MEDIUM,	/* 0xab */
	LZVN_OPPCODE_TYPE_DISTANCE_MEDIUM,	/* 0xac */
	LZVN_OPPCODE_TYPE_DISTANCE_MEDIUM,	/* 0xad */
	LZVN_OPPCODE_TYPE_DISTANCE_MEDIUM,	/* 0xae */
	LZVN_OPPCODE_TYPE_DISTANCE_MEDIUM,	/* 0xaf */

	LZVN_OPPCODE_TYPE_DISTANCE_MEDIUM,	/* 0xb0 */
	LZVN_OPPCODE_TYPE_DISTANCE_MEDIUM,	/* 0xb1 */
	LZVN_OPPCODE_TYPE_DISTANCE_MEDIUM,	/* 0xb2 */
	LZVN_OPPCODE_TYPE_DISTANCE_MEDIUM,	/* 0xb3 */
	LZVN_OPPCODE_TYPE_DISTANCE_MEDIUM,	/* 0xb4 */
	LZVN_OPPCODE_TYPE_DISTANCE_MEDIUM,	/* 0xb5 */
	LZVN_OPPCODE_TYPE_DISTANCE_MEDIUM,	/* 0xb6 */
	LZVN_OPPCODE_TYPE_DISTANCE_MEDIUM,	/* 0xb7 */
	LZVN_OPPCODE_TYPE_DISTANCE_MEDIUM,	/* 0xb8 */
	LZVN_OPPCODE_TYPE_DISTANCE_MEDIUM,	/* 0xb9 */
	LZVN_OPPCODE_TYPE_DISTANCE_MEDIUM,	/* 0xba */
	LZVN_OPPCODE_TYPE_DISTANCE_MEDIUM,	/* 0xbb */
	LZVN_OPPCODE_TYPE_DISTANCE_MEDIUM,	/* 0xbc */
	LZVN_OPPCODE_TYPE_DISTANCE_MEDIUM,	/* 0xbd */
	LZVN_OPPCODE_TYPE_DISTANCE_MEDIUM,	/* 0xbe */
	LZVN_OPPCODE_TYPE_DISTANCE_MEDIUM,	/* 0xbf */

	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0xc0 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0xc1 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0xc2 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0xc3 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0xc4 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0xc5 */
	LZVN_OPPCODE_TYPE_DISTANCE_PREVIOUS,	/* 0xc6 */
	LZVN_OPPCODE_TYPE_DISTANCE_LARGE,	/* 0xc7 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0xc8 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0xc9 */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0xca */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0xcb */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0xcc */
	LZVN_OPPCODE_TYPE_DISTANCE_SMALL,	/* 0xcd */
	LZVN_OPPCODE_TYPE_DISTANCE_PREVIOUS,	/* 0xce */
	LZVN_OPPCODE_TYPE_DISTANCE_LARGE,	/* 0xcf */

	LZVN_OPPCODE_TYPE_INVALID,		/* 0xd0 */
	LZVN_OPPCODE_TYPE_INVALID,		/* 0xd1 */
	LZVN_OPPCODE_TYPE_INVALID,		/* 0xd2 */
	LZVN_OPPCODE_TYPE_INVALID,		/* 0xd3 */
	LZVN_OPPCODE_TYPE_INVALID,		/* 0xd4 */
	LZVN_OPPCODE_TYPE_INVALID,		/* 0xd5 */
	LZVN_OPPCODE_TYPE_INVALID,		/* 0xd6 */
	LZVN_OPPCODE_TYPE_INVALID,		/* 0xd7 */
	LZVN_OPPCODE_TYPE_INVALID,		/* 0xd8 */
	LZVN_OPPCODE_TYPE_INVALID,		/* 0xd9 */
	LZVN_OPPCODE_TYPE_INVALID,		/* 0xda */
	LZVN_OPPCODE_TYPE_INVALID,		/* 0xdb */
	LZVN_OPPCODE_TYPE_INVALID,		/* 0xdc */
	LZVN_OPPCODE_TYPE_INVALID,		/* 0xdd */
	LZVN_OPPCODE_TYPE_INVALID,		/* 0xde */
	LZVN_OPPCODE_TYPE_INVALID,		/* 0xdf */

	LZVN_OPPCODE_TYPE_LITERAL_LARGE,	/* 0xe0 */
	LZVN_OPPCODE_TYPE_LITERAL_SMALL,	/* 0xe1 */
	LZVN_OPPCODE_TYPE_LITERAL_SMALL,	/* 0xe2 */
	LZVN_OPPCODE_TYPE_LITERAL_SMALL,	/* 0xe3 */
	LZVN_OPPCODE_TYPE_LITERAL_SMALL,	/* 0xe4 */
	LZVN_OPPCODE_TYPE_LITERAL_SMALL,	/* 0xe5 */
	LZVN_OPPCODE_TYPE_LITERAL_SMALL,	/* 0xe6 */
	LZVN_OPPCODE_TYPE_LITERAL_SMALL,	/* 0xe7 */
	LZVN_OPPCODE_TYPE_LITERAL_SMALL,	/* 0xe8 */
	LZVN_OPPCODE_TYPE_LITERAL_SMALL,	/* 0xe9 */
	LZVN_OPPCODE_TYPE_LITERAL_SMALL,	/* 0xea */
	LZVN_OPPCODE_TYPE_LITERAL_SMALL,	/* 0xeb */
	LZVN_OPPCODE_TYPE_LITERAL_SMALL,	/* 0xec */
	LZVN_OPPCODE_TYPE_LITERAL_SMALL,	/* 0xed */
	LZVN_OPPCODE_TYPE_LITERAL_SMALL,	/* 0xee */
	LZVN_OPPCODE_TYPE_LITERAL_SMALL,	/* 0xef */

	LZVN_OPPCODE_TYPE_MATCH_LARGE,		/* 0xf0 */
	LZVN_OPPCODE_TYPE_MATCH_SMALL,		/* 0xf1 */
	LZVN_OPPCODE_TYPE_MATCH_SMALL,		/* 0xf2 */
	LZVN_OPPCODE_TYPE_MATCH_SMALL,		/* 0xf3 */
	LZVN_OPPCODE_TYPE_MATCH_SMALL,		/* 0xf4 */
	LZVN_OPPCODE_TYPE_MATCH_SMALL,		/* 0xf5 */
	LZVN_OPPCODE_TYPE_MATCH_SMALL,		/* 0xf6 */
	LZVN_OPPCODE_TYPE_MATCH_SMALL,		/* 0xf7 */
	LZVN_OPPCODE_TYPE_MATCH_SMALL,		/* 0xf8 */
	LZVN_OPPCODE_TYPE_MATCH_SMALL,		/* 0xf9 */
	LZVN_OPPCODE_TYPE_MATCH_SMALL,		/* 0xfa */
	LZVN_OPPCODE_TYPE_MATCH_SMALL,		/* 0xfb */
	LZVN_OPPCODE_TYPE_MATCH_SMALL,		/* 0xfc */
	LZVN_OPPCODE_TYPE_MATCH_SMALL,		/* 0xfd */
	LZVN_OPPCODE_TYPE_MATCH_SMALL,		/* 0xfe */
	LZVN_OPPCODE_TYPE_MATCH_SMALL,		/* 0xff */
};

/* Decompresses LZVN compressed data
 * Returns 1 on success or -1 on error
 */
int lzvn_decompress(
     const uint8_t *compressed_data,
     size_t compressed_data_size,
     uint8_t *uncompressed_data,
     size_t *uncompressed_data_size,
     libcerror_error_t **error )
{
	static char *function           = "lzvn_decompress";
	size_t compressed_data_offset   = 0;
	size_t match_offset             = 0;
	size_t uncompressed_data_offset = 0;
	uint16_t distance               = 0;
	uint16_t literal_size           = 0;
	uint16_t match_size             = 0;
	uint8_t oppcode                 = 0;
	uint8_t oppcode_type            = 0;
	uint8_t oppcode_value           = 0;

#if defined( HAVE_DEBUG_OUTPUT )
	size_t debug_match_offset       = 0;
	size_t oppcode_data_offset      = 0;
	size_t oppcode_data_size        = 0;
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
	if( *uncompressed_data_size > (size_t) SSIZE_MAX )
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
		if( uncompressed_data_offset >= *uncompressed_data_size )
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

		oppcode_type = lzvn_oppcode_types[ oppcode ];

		literal_size = 0;
		match_size   = 0;

		switch( oppcode_type )
		{
			case LZVN_OPPCODE_TYPE_DISTANCE_LARGE:
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

			case LZVN_OPPCODE_TYPE_DISTANCE_MEDIUM:
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

			case LZVN_OPPCODE_TYPE_DISTANCE_PREVIOUS:
				literal_size = ( oppcode & 0xc0 ) >> 6;
				match_size   = ( ( oppcode & 0x38 ) >> 3 ) + 3;

				break;

			case LZVN_OPPCODE_TYPE_DISTANCE_SMALL:
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

			case LZVN_OPPCODE_TYPE_LITERAL_LARGE:
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

			case LZVN_OPPCODE_TYPE_LITERAL_SMALL:
				literal_size = oppcode & 0x0f;

				break;

			case LZVN_OPPCODE_TYPE_MATCH_LARGE:
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

			case LZVN_OPPCODE_TYPE_MATCH_SMALL:
				match_size = oppcode & 0x0f;

				break;

			case LZVN_OPPCODE_TYPE_END_OF_STREAM:
			case LZVN_OPPCODE_TYPE_NONE:
				break;

			case LZVN_OPPCODE_TYPE_INVALID:
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

		if( oppcode_type == LZVN_OPPCODE_TYPE_END_OF_STREAM )
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
			if( ( (size_t) literal_size > *uncompressed_data_size )
			 || ( uncompressed_data_offset > ( *uncompressed_data_size - literal_size ) ) )
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

			if( ( (size_t) match_size > *uncompressed_data_size )
			 || ( uncompressed_data_offset > ( *uncompressed_data_size - match_size ) ) )
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
				 match_size,
				 LIBCNOTIFY_PRINT_DATA_FLAG_GROUP_DATA );
			}
#endif
		}
	}
	*uncompressed_data_size = uncompressed_data_offset;

	return( 1 );
}

