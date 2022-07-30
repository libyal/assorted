/*
 * LZFSE (un)compression functions
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
#include <byte_stream.h>
#include <memory.h>
#include <types.h>

#include "assorted_libcerror.h"
#include "assorted_libcnotify.h"
#include "lzfse.h"
#include "lzvn.h"

#define LZFSE_ENDOFSTREAM_BLOCK_MARKER		0x24787662UL
#define LZFSE_UNCOMPRESSED_BLOCK_MARKER		0x2d787662UL
#define LZFSE_COMPRESSED_BLOCK_V1_MARKER	0x31787662UL
#define LZFSE_COMPRESSED_BLOCK_V2_MARKER	0x32787662UL
#define LZFSE_COMPRESSED_BLOCK_LZVN_MARKER	0x6e787662UL

const uint8_t lzfse_freq_nbits_table[ 32 ] = {
      2, 3, 2, 5, 2, 3, 2, 8, 2, 3, 2, 5, 2, 3, 2, 14,
      2, 3, 2, 5, 2, 3, 2, 8, 2, 3, 2, 5, 2, 3, 2, 14 };

const uint16_t lzfse_freq_value_table[ 32 ] = {
      0, 2, 1, 4, 0, 3, 1, 0xffff, 0, 2, 1, 5, 0, 3, 1, 0xffff,
      0, 2, 1, 6, 0, 3, 1, 0xffff, 0, 2, 1, 7, 0, 3, 1, 0xffff };

/* Decodes the frequency table bit stream
 * Returns 1 on success or -1 on error
 */
int lzfse_decode_frequency_table_stream(
     const uint8_t *bit_stream,
     size_t bit_stream_size,
     uint16_t *frequency_table,
     libcerror_error_t **error )
{
	static char *function        = "lzfse_decode_frequency_table_stream";
	size_t bit_stream_offset     = 0;
	uint32_t value_32bit         = 0;
	uint16_t frequency_value     = 0;
	uint8_t frequency_value_size = 0;
	uint8_t lookup_index         = 0;
	uint8_t number_of_bits       = 0;
	int table_index              = 0;

	if( bit_stream == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid bit stream.",
		 function );

		return( -1 );
	}
	if( ( bit_stream_size < 4 )
	 || ( bit_stream_size > (size_t) SSIZE_MAX ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_OUT_OF_BOUNDS,
		 "%s: invalid bit stream size value out of bounds.",
		 function );

		return( -1 );
	}
	if( frequency_table == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid frequency table.",
		 function );

		return( -1 );
	}
	byte_stream_copy_to_uint32_little_endian(
	 bit_stream,
	 value_32bit );

	bit_stream_offset = 4;
	number_of_bits    = 32;

	for( table_index = 0;
	     table_index < 360;
	     table_index++ )
	{
		lookup_index         = (uint8_t) ( value_32bit & 0x0000001fUL );
		frequency_value_size = lzfse_freq_nbits_table[ lookup_index ];

		if( frequency_value_size == 8 )
		{
			frequency_value = (uint16_t) ( ( value_32bit >> 4 ) & 0x0000000fUL ) + 8;
		}
		else if( frequency_value_size == 14 )
		{
			frequency_value = (uint16_t) ( ( value_32bit >> 4 ) & 0x000003ffUL ) + 24;
		}
		else
		{
			frequency_value = lzfse_freq_value_table[ lookup_index ];
		}
		frequency_table[ table_index ] = frequency_value;

		value_32bit   >>= frequency_value_size;
		number_of_bits -= frequency_value_size;

		if( ( number_of_bits <= 24 )
		 && ( bit_stream_offset < bit_stream_size ) )
		{
			value_32bit |= ( (uint32_t) bit_stream[ bit_stream_offset++ ] ) << 24;
		}
	}
	return( 1 );
}

/* Decompresses a LZFSE compressed block
 * Returns 1 on success or -1 on error
 */
int lzfse_decompress_block(
     const uint8_t *compressed_data,
     size_t compressed_data_size,
     size_t *compressed_data_offset,
     uint8_t *uncompressed_data,
     size_t uncompressed_data_size,
     size_t *uncompressed_data_offset,
     libcerror_error_t **error )
{
	static char *function                = "lzfse_decompress_block";
	size_t safe_compressed_data_offset   = 0;
	size_t safe_uncompressed_data_offset = 0;

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
	if( ( compressed_data_size < 8 )
	 || ( compressed_data_size > (size_t) SSIZE_MAX ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_OUT_OF_BOUNDS,
		 "%s: invalid compressed data size value out of bounds.",
		 function );

		return( -1 );
	}
	if( compressed_data_offset == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid compressed offset.",
		 function );

		return( -1 );
	}
	safe_compressed_data_offset = *compressed_data_offset;

	if( safe_compressed_data_offset > ( compressed_data_size - 8 ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_OUT_OF_BOUNDS,
		 "%s: invalid compressed data offset value out of bounds.",
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
	if( uncompressed_data_size > (size_t) SSIZE_MAX )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_EXCEEDS_MAXIMUM,
		 "%s: invalid uncompressed data size value exceeds maximum.",
		 function );

		return( -1 );
	}
	if( uncompressed_data_offset == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid uncompressed offset.",
		 function );

		return( -1 );
	}
	safe_uncompressed_data_offset = *uncompressed_data_offset;

	if( safe_uncompressed_data_offset > uncompressed_data_size )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_OUT_OF_BOUNDS,
		 "%s: invalid uncompressed data offset value out of bounds.",
		 function );

		return( -1 );
	}
	*compressed_data_offset   = safe_compressed_data_offset;
	*uncompressed_data_offset = safe_uncompressed_data_offset;

	return( 1 );
}

/* Decompresses LZFSE compressed data
 * Returns 1 on success or -1 on error
 */
int lzfse_decompress(
     const uint8_t *compressed_data,
     size_t compressed_data_size,
     uint8_t *uncompressed_data,
     size_t *uncompressed_data_size,
     libcerror_error_t **error )
{
	uint16_t frequency_table[ 360 ];

	static char *function               = "lzfse_decompress";
	size_t compressed_data_offset       = 0;
	size_t safe_uncompressed_block_size = 0;
	size_t safe_uncompressed_data_size  = 0;
	size_t uncompressed_data_offset     = 0;
	uint64_t packed_fields1             = 0;
	uint64_t packed_fields2             = 0;
	uint64_t packed_fields3             = 0;
	uint32_t block_marker               = 0;
	uint32_t compressed_block_size      = 0;
	uint32_t uncompressed_block_size    = 0;
	int table_index                     = 0;

/* TODO refactor */
	uint32_t n_literals                 = 0;
	uint32_t n_matches                  = 0;
	uint32_t n_literal_payload_bytes    = 0;
	uint32_t n_lmd_payload_bytes        = 0;
	uint32_t literal_bits               = 0;
	uint32_t lmd_bits                   = 0;
	uint32_t header_size                = 0;
	uint16_t l_state = 0;
	uint16_t m_state = 0;
	uint16_t d_state = 0;

	uint16_t literal_state[ 4 ];

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
	if( ( compressed_data_size < 4 )
	 || ( compressed_data_size > (size_t) SSIZE_MAX ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_OUT_OF_BOUNDS,
		 "%s: invalid compressed data size value out of bounds.",
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
		if( compressed_data_offset > ( compressed_data_size + 4 ) )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
			 LIBCERROR_ARGUMENT_ERROR_VALUE_TOO_SMALL,
			 "%s: compressed data size value too small.",
			 function );

			return( -1 );
		}
		byte_stream_copy_to_uint32_little_endian(
		 &( compressed_data[ compressed_data_offset ] ),
		 block_marker );

#if defined( HAVE_DEBUG_OUTPUT )
		if( libcnotify_verbose != 0 )
		{
			if( ( block_marker != LZFSE_ENDOFSTREAM_BLOCK_MARKER )
			 && ( block_marker != LZFSE_UNCOMPRESSED_BLOCK_MARKER )
			 && ( block_marker != LZFSE_COMPRESSED_BLOCK_V1_MARKER )
			 && ( block_marker != LZFSE_COMPRESSED_BLOCK_V2_MARKER )
			 && ( block_marker != LZFSE_COMPRESSED_BLOCK_LZVN_MARKER ) )
			{
				libcnotify_printf(
				 "%s: block marker\t\t\t\t\t\t: 0x%08" PRIx32 "\n",
				 function,
				 block_marker );
			}
			else
			{
				libcnotify_printf(
				 "%s: block marker\t\t\t\t\t\t: %c%c%c%c (",
				 function,
				 compressed_data[ compressed_data_offset ],
				 compressed_data[ compressed_data_offset + 1 ],
				 compressed_data[ compressed_data_offset + 2 ],
				 compressed_data[ compressed_data_offset + 3 ] );

				switch( block_marker )
				{
					case LZFSE_ENDOFSTREAM_BLOCK_MARKER:
						libcnotify_printf(
						 "end-of-stream" );
						break;

					case LZFSE_UNCOMPRESSED_BLOCK_MARKER:
						libcnotify_printf(
						 "uncompressed" );
						break;

					case LZFSE_COMPRESSED_BLOCK_V1_MARKER:
						libcnotify_printf(
						 "compressed version 1" );
						break;

					case LZFSE_COMPRESSED_BLOCK_V2_MARKER:
						libcnotify_printf(
						 "compressed version 2" );
						break;

					case LZFSE_COMPRESSED_BLOCK_LZVN_MARKER:
						libcnotify_printf(
						 "compressed LZVN" );
						break;

					default:
						libcnotify_printf(
						 "UNKNOWN" );
						break;
				}
				libcnotify_printf(
				 ")\n" );
			}
		}
#endif /* defined( HAVE_DEBUG_OUTPUT ) */

		compressed_data_offset += 4;

		if( block_marker == LZFSE_ENDOFSTREAM_BLOCK_MARKER )
		{
			break;
		}
		else if( ( block_marker != LZFSE_UNCOMPRESSED_BLOCK_MARKER )
		      && ( block_marker != LZFSE_COMPRESSED_BLOCK_V1_MARKER )
		      && ( block_marker != LZFSE_COMPRESSED_BLOCK_V2_MARKER )
		      && ( block_marker != LZFSE_COMPRESSED_BLOCK_LZVN_MARKER ) )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
			 LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
			 "%s: unsupported block marker: 0x%08" PRIx32 ".",
			 function,
			 block_marker );

			return( -1 );
		}
		if( compressed_data_offset > ( compressed_data_size + 4 ) )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
			 LIBCERROR_ARGUMENT_ERROR_VALUE_TOO_SMALL,
			 "%s: compressed data size value too small.",
			 function );

			return( -1 );
		}
		byte_stream_copy_to_uint32_little_endian(
		 &( compressed_data[ compressed_data_offset ] ),
		 uncompressed_block_size );

		compressed_data_offset += 4;

#if defined( HAVE_DEBUG_OUTPUT )
		if( libcnotify_verbose != 0 )
		{
			libcnotify_printf(
			 "%s: uncompressed block size\t\t\t\t: %" PRIu32 "\n",
			 function,
			 uncompressed_block_size );
		}
#endif
		switch( block_marker )
		{
			case LZFSE_COMPRESSED_BLOCK_LZVN_MARKER:
				if( compressed_data_offset > ( compressed_data_size + 4 ) )
				{
					libcerror_error_set(
					 error,
					 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
					 LIBCERROR_ARGUMENT_ERROR_VALUE_TOO_SMALL,
					 "%s: compressed data size value too small.",
					 function );

					return( -1 );
				}
				byte_stream_copy_to_uint32_little_endian(
				 &( compressed_data[ compressed_data_offset ] ),
				 compressed_block_size );

				compressed_data_offset += 4;

				break;

			case LZFSE_COMPRESSED_BLOCK_V1_MARKER:
				if( compressed_data_offset > ( compressed_data_size + 762 ) )
				{
					libcerror_error_set(
					 error,
					 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
					 LIBCERROR_ARGUMENT_ERROR_VALUE_TOO_SMALL,
					 "%s: compressed data size value too small.",
					 function );

					return( -1 );
				}
				byte_stream_copy_to_uint32_little_endian(
				 &( compressed_data[ compressed_data_offset ] ),
				 compressed_block_size );

				compressed_data_offset += 4;

				byte_stream_copy_to_uint32_little_endian(
				 &( compressed_data[ compressed_data_offset ] ),
				 n_literals );

				compressed_data_offset += 4;

				byte_stream_copy_to_uint32_little_endian(
				 &( compressed_data[ compressed_data_offset ] ),
				 n_matches );

				compressed_data_offset += 4;

				byte_stream_copy_to_uint32_little_endian(
				 &( compressed_data[ compressed_data_offset ] ),
				 n_literal_payload_bytes );

				compressed_data_offset += 4;

				byte_stream_copy_to_uint32_little_endian(
				 &( compressed_data[ compressed_data_offset ] ),
				 n_lmd_payload_bytes );

				compressed_data_offset += 4;

				byte_stream_copy_to_uint32_little_endian(
				 &( compressed_data[ compressed_data_offset ] ),
				 literal_bits );

				compressed_data_offset += 4;

				byte_stream_copy_to_uint16_little_endian(
				 &( compressed_data[ compressed_data_offset ] ),
				 literal_state[ 0 ] );

				compressed_data_offset += 2;

				byte_stream_copy_to_uint16_little_endian(
				 &( compressed_data[ compressed_data_offset ] ),
				 literal_state[ 1 ] );

				compressed_data_offset += 2;

				byte_stream_copy_to_uint16_little_endian(
				 &( compressed_data[ compressed_data_offset ] ),
				 literal_state[ 2 ] );

				compressed_data_offset += 2;

				byte_stream_copy_to_uint16_little_endian(
				 &( compressed_data[ compressed_data_offset ] ),
				 literal_state[ 3 ] );

				compressed_data_offset += 2;

				byte_stream_copy_to_uint32_little_endian(
				 &( compressed_data[ compressed_data_offset ] ),
				 lmd_bits );

				compressed_data_offset += 4;

				byte_stream_copy_to_uint16_little_endian(
				 &( compressed_data[ compressed_data_offset ] ),
				 l_state );

				compressed_data_offset += 2;

				byte_stream_copy_to_uint16_little_endian(
				 &( compressed_data[ compressed_data_offset ] ),
				 m_state );

				compressed_data_offset += 2;

				byte_stream_copy_to_uint16_little_endian(
				 &( compressed_data[ compressed_data_offset ] ),
				 d_state );

				compressed_data_offset += 2;

				for( table_index = 0;
				     table_index < 360;
				     table_index++ )
				{
					byte_stream_copy_to_uint16_little_endian(
					 &( compressed_data[ compressed_data_offset ] ),
					 frequency_table[ table_index ] );

					compressed_data_offset += 2;
				}
				break;

			case LZFSE_COMPRESSED_BLOCK_V2_MARKER:
				if( compressed_data_offset > ( compressed_data_size + 24 ) )
				{
					libcerror_error_set(
					 error,
					 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
					 LIBCERROR_ARGUMENT_ERROR_VALUE_TOO_SMALL,
					 "%s: compressed data size value too small.",
					 function );

					return( -1 );
				}
				byte_stream_copy_to_uint64_little_endian(
				 &( compressed_data[ compressed_data_offset ] ),
				 packed_fields1 );

				compressed_data_offset += 8;

				byte_stream_copy_to_uint64_little_endian(
				 &( compressed_data[ compressed_data_offset ] ),
				 packed_fields2 );

				compressed_data_offset += 8;

				byte_stream_copy_to_uint64_little_endian(
				 &( compressed_data[ compressed_data_offset ] ),
				 packed_fields3 );

				compressed_data_offset += 8;

#if defined( HAVE_DEBUG_OUTPUT )
				if( libcnotify_verbose != 0 )
				{
					libcnotify_printf(
					 "%s: packed fields 1\t\t\t\t\t: 0x%08" PRIx64 "\n",
					 function,
					 packed_fields1 );

					libcnotify_printf(
					 "%s: packed fields 2\t\t\t\t\t: 0x%08" PRIx64 "\n",
					 function,
					 packed_fields2 );

					libcnotify_printf(
					 "%s: packed fields 3\t\t\t\t\t: 0x%08" PRIx64 "\n",
					 function,
					 packed_fields3 );
				}
#endif /* defined( HAVE_DEBUG_OUTPUT ) */

				n_literals              = (uint32_t) ( packed_fields1 & 0x000fffffUL );
				n_literal_payload_bytes = (uint32_t) ( ( packed_fields1 >> 20 ) & 0x000fffffUL );
				n_matches               = (uint32_t) ( ( packed_fields1 >> 40 ) & 0x000fffffUL );
				literal_bits            = (uint32_t) ( ( packed_fields1 >> 60 ) & 0x00000003UL );

				literal_state[ 0 ]      = (uint16_t) ( packed_fields2 & 0x000003ffUL );
				literal_state[ 1 ]      = (uint16_t) ( ( packed_fields2 >> 10 ) & 0x000003ffUL );
				literal_state[ 2 ]      = (uint16_t) ( ( packed_fields2 >> 20 ) & 0x000003ffUL );
				literal_state[ 3 ]      = (uint16_t) ( ( packed_fields2 >> 30 ) & 0x000003ffUL );
				n_lmd_payload_bytes     = (uint32_t) ( ( packed_fields2 >> 40 ) & 0x000fffffUL );
				lmd_bits                = (uint32_t) ( ( packed_fields2 >> 60 ) & 0x00000003UL );

				header_size             = (uint32_t) ( packed_fields3 & 0xffffffffUL );
				l_state                 = (uint16_t) ( ( packed_fields3 >> 32 ) & 0x000003ffUL );
				m_state                 = (uint16_t) ( ( packed_fields3 >> 42 ) & 0x000003ffUL );
				d_state                 = (uint16_t) ( ( packed_fields3 >> 52 ) & 0x000003ffUL );

				if( ( header_size < 32 )
				 || ( header_size > 720 ) )
				{
					libcerror_error_set(
					 error,
					 LIBCERROR_ERROR_DOMAIN_RUNTIME,
					 LIBCERROR_RUNTIME_ERROR_VALUE_OUT_OF_BOUNDS,
					 "%s: invalid header size value out of bounds.",
					 function );

					return( -1 );
				}
				if( header_size > 32 )
				{
					if( lzfse_decode_frequency_table_stream(
					     &( compressed_data[ compressed_data_offset ] ),
					     header_size - 32,
					     frequency_table,
					     error ) != 1 )
					{
						libcerror_error_set(
						 error,
						 LIBCERROR_ERROR_DOMAIN_COMPRESSION,
						 LIBCERROR_COMPRESSION_ERROR_DECOMPRESS_FAILED,
						 "%s: unable to decode frequency table data.",
						 function );

						return( -1 );
					}
					compressed_data_offset += (size_t) header_size - 32;
				}
				break;
		}
#if defined( HAVE_DEBUG_OUTPUT )
		if( libcnotify_verbose != 0 )
		{
			if( ( block_marker == LZFSE_COMPRESSED_BLOCK_V1_MARKER )
			 || ( block_marker == LZFSE_COMPRESSED_BLOCK_V2_MARKER )
			 || ( block_marker == LZFSE_COMPRESSED_BLOCK_LZVN_MARKER ) )
			{
				libcnotify_printf(
				 "%s: compressed block size\t\t\t\t\t: %" PRIu32 "\n",
				 function,
				 compressed_block_size );
			}
			if( ( block_marker == LZFSE_COMPRESSED_BLOCK_V1_MARKER )
			 || ( block_marker == LZFSE_COMPRESSED_BLOCK_V2_MARKER ) )
			{
				libcnotify_printf(
				 "%s: n_literals\t\t\t\t\t\t: %" PRIu32 "\n",
				 function,
				 n_literals );

				libcnotify_printf(
				 "%s: n_matches\t\t\t\t\t\t: %" PRIu32 "\n",
				 function,
				 n_matches );

				libcnotify_printf(
				 "%s: n_literal_payload_bytes\t\t\t\t: %" PRIu32 "\n",
				 function,
				 n_literal_payload_bytes );

				libcnotify_printf(
				 "%s: n_lmd_payload_bytes\t\t\t\t\t: %" PRIu32 "\n",
				 function,
				 n_lmd_payload_bytes );

				libcnotify_printf(
				 "%s: literal_bits\t\t\t\t\t\t: %" PRIu32 "\n",
				 function,
				 literal_bits );

				libcnotify_printf(
				 "%s: literal_state[ 0 ]\t\t\t\t\t: %" PRIu16 "\n",
				 function,
				 literal_state[ 0 ] );

				libcnotify_printf(
				 "%s: literal_state[ 1 ]\t\t\t\t\t: %" PRIu16 "\n",
				 function,
				 literal_state[ 1 ] );

				libcnotify_printf(
				 "%s: literal_state[ 2 ]\t\t\t\t\t: %" PRIu16 "\n",
				 function,
				 literal_state[ 2 ] );

				libcnotify_printf(
				 "%s: literal_state[ 3 ]\t\t\t\t\t: %" PRIu16 "\n",
				 function,
				 literal_state[ 3 ] );

				libcnotify_printf(
				 "%s: lmd_bits\t\t\t\t\t\t: %" PRIu32 "\n",
				 function,
				 lmd_bits );
			}
			if( block_marker == LZFSE_COMPRESSED_BLOCK_V2_MARKER )
			{
				libcnotify_printf(
				 "%s: header_size\t\t\t\t\t\t: %" PRIu32 "\n",
				 function,
				 header_size );
			}
			if( ( block_marker == LZFSE_COMPRESSED_BLOCK_V1_MARKER )
			 || ( block_marker == LZFSE_COMPRESSED_BLOCK_V2_MARKER ) )
			{
				libcnotify_printf(
				 "%s: l_state\t\t\t\t\t\t: %" PRIu16 "\n",
				 function,
				 l_state );

				libcnotify_printf(
				 "%s: m_state\t\t\t\t\t\t: %" PRIu16 "\n",
				 function,
				 m_state );

				libcnotify_printf(
				 "%s: d_state\t\t\t\t\t\t: %" PRIu16 "\n",
				 function,
				 d_state );

				for( table_index = 0;
				     table_index < 360;
				     table_index++ )
				{
					if( frequency_table[ table_index ] != 0 )
					{
						libcnotify_printf(
						 "%s: frequency table: %d value\t\t\t\t: %" PRIu16 "\n",
						 function,
						 table_index,
						 frequency_table[ table_index ] );
					}
				}
			}
		}
#endif /* defined( HAVE_DEBUG_OUTPUT ) */

		switch( block_marker )
		{
			case LZFSE_UNCOMPRESSED_BLOCK_MARKER:
				if( ( (size_t) uncompressed_block_size > compressed_data_size )
				 || ( compressed_data_offset > ( compressed_data_size - uncompressed_block_size ) ) )
				{
					libcerror_error_set(
					 error,
					 LIBCERROR_ERROR_DOMAIN_RUNTIME,
					 LIBCERROR_RUNTIME_ERROR_VALUE_OUT_OF_BOUNDS,
					 "%s: literal size value exceeds compressed data size.",
					 function );

					return( -1 );
				}
				if( ( (size_t) uncompressed_block_size > safe_uncompressed_data_size )
				 || ( uncompressed_data_offset > ( safe_uncompressed_data_size - uncompressed_block_size ) ) )
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
					 "%s: uncompressed:\n",
					 function );
					libcnotify_print_data(
					 &( compressed_data[ compressed_data_offset ] ),
					 uncompressed_block_size,
					 LIBCNOTIFY_PRINT_DATA_FLAG_GROUP_DATA );
				}
#endif
				if( memory_copy(
				     &( uncompressed_data[ uncompressed_data_offset ] ),
				     &( compressed_data[ compressed_data_offset ] ),
				     (size_t) uncompressed_block_size ) == NULL )
				{
					libcerror_error_set(
					 error,
					 LIBCERROR_ERROR_DOMAIN_MEMORY,
					 LIBCERROR_MEMORY_ERROR_COPY_FAILED,
					 "%s: unable to copy literal to uncompressed data.",
					 function );

					return( -1 );
				}
				compressed_data_offset   += (size_t) uncompressed_block_size;
				uncompressed_data_offset += (size_t) uncompressed_block_size;

				break;

			case LZFSE_COMPRESSED_BLOCK_V1_MARKER:
			case LZFSE_COMPRESSED_BLOCK_V2_MARKER:

/* TODO decode lmd tables
 */
#if defined( HAVE_DEBUG_OUTPUT )
				if( libcnotify_verbose != 0 )
				{
					libcnotify_printf(
					 "\n" );
				}
#endif
				break;

			case LZFSE_COMPRESSED_BLOCK_LZVN_MARKER:
				safe_uncompressed_block_size = (size_t) uncompressed_block_size;

				if( lzvn_decompress(
				     &( compressed_data[ compressed_data_offset ] ),
				     compressed_block_size,
				     &( uncompressed_data[ uncompressed_data_offset ] ),
				     &safe_uncompressed_block_size,
				     error ) != 1 )
				{
					libcerror_error_set(
					 error,
					 LIBCERROR_ERROR_DOMAIN_COMPRESSION,
					 LIBCERROR_COMPRESSION_ERROR_DECOMPRESS_FAILED,
					 "%s: unable to decompress LZVN compressed data.",
					 function );

					return( -1 );
				}
				compressed_data_offset   += (size_t) compressed_block_size;
				uncompressed_data_offset += (size_t) uncompressed_block_size;

				break;
		}
	}
	*uncompressed_data_size = uncompressed_data_offset;

	return( 1 );
}

