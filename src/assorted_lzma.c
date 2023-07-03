/*
 * LZMA (un)compression functions
 *
 * Copyright (C) 2008-2023, Joachim Metz <joachim.metz@gmail.com>
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

#include "assorted_bit_stream.h"
#include "assorted_libcerror.h"
#include "assorted_libcnotify.h"
#include "assorted_lzma.h"

enum ASSORTED_LZMA_CONTROL_CODES
{
	ASSORTED_LZMA_CONTROL_CODE_LITERAL	= 0x00,
	ASSORTED_LZMA_CONTROL_CODE_MATCH	= 0x02,
	ASSORTED_LZMA_CONTROL_CODE_SHORTREP	= 0x0c,
	ASSORTED_LZMA_CONTROL_CODE_REP0		= 0x0d,
	ASSORTED_LZMA_CONTROL_CODE_REP1		= 0x0e,
	ASSORTED_LZMA_CONTROL_CODE_REP2		= 0x1e,
	ASSORTED_LZMA_CONTROL_CODE_REP3		= 0x1f,
};

/* Reads the stream header
 * Returns 1 on success or -1 on error
 */
int assorted_lzma_read_stream_header(
     const uint8_t *compressed_data,
     size_t compressed_data_size,
     size_t *compressed_data_offset,
     libcerror_error_t **error )
{
	static char *function              = "assorted_lzma_read_stream_header";
	size_t safe_compressed_data_offset = 0;

#if defined( HAVE_DEBUG_OUTPUT )
	uint32_t value_32bit               = 0;
	uint16_t value_16bit               = 0;
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
	if( ( compressed_data_size < 12 )
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
		 "%s: invalid compressed data offset.",
		 function );

		return( -1 );
	}
	safe_compressed_data_offset = *compressed_data_offset;

	if( safe_compressed_data_offset > ( compressed_data_size - 12 ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_TOO_SMALL,
		 "%s: invalid compressed data value too small.",
		 function );

		return( -1 );
	}
#if defined( HAVE_DEBUG_OUTPUT )
	if( libcnotify_verbose != 0 )
	{
		libcnotify_printf(
		 "%s: stream header data:\n",
		 function );
		libcnotify_print_data(
		 &( compressed_data[ safe_compressed_data_offset ] ),
		 12,
		 0 );
	}
#endif
	if( ( compressed_data[ safe_compressed_data_offset ] != 0xfd )
	 || ( compressed_data[ safe_compressed_data_offset + 1 ] != '7' )
	 || ( compressed_data[ safe_compressed_data_offset + 2 ] != 'z' )
	 || ( compressed_data[ safe_compressed_data_offset + 3 ] != 'X' )
	 || ( compressed_data[ safe_compressed_data_offset + 4 ] != 'Z' )
	 || ( compressed_data[ safe_compressed_data_offset + 5 ] != 0 ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_UNSUPPORTED_VALUE,
		 "%s: unsupported signature.",
		 function );

		return( -1 );
	}
#if defined( HAVE_DEBUG_OUTPUT )
	if( libcnotify_verbose != 0 )
	{
		libcnotify_printf(
		 "%s: signature\t\t\t\t: \\x%02" PRIx8 "%c%c%c%c\\x%02" PRIx8 "\n",
		 function,
		 compressed_data[ safe_compressed_data_offset ],
		 compressed_data[ safe_compressed_data_offset + 1 ],
		 compressed_data[ safe_compressed_data_offset + 2 ],
		 compressed_data[ safe_compressed_data_offset + 3 ],
		 compressed_data[ safe_compressed_data_offset + 4 ],
		 compressed_data[ safe_compressed_data_offset + 5 ] );

		byte_stream_copy_to_uint16_little_endian(
		 &( compressed_data[ safe_compressed_data_offset + 6 ] ),
		 value_16bit );
		libcnotify_printf(
		 "%s: stream flags\t\t\t\t: 0x%04" PRIx16 "\n",
		 function,
		 value_16bit );

		byte_stream_copy_to_uint32_little_endian(
		 &( compressed_data[ safe_compressed_data_offset + 8 ] ),
		 value_32bit );
		libcnotify_printf(
		 "%s: checksum\t\t\t\t: 0x%08" PRIx32 "\n",
		 function,
		 value_32bit );

		libcnotify_printf(
		 "\n" );
	}
#endif /* defined( HAVE_DEBUG_OUTPUT ) */

	*compressed_data_offset = safe_compressed_data_offset + 12;

	return( 1 );
}

/* Reads the block header
 * Returns 1 on success or -1 on error
 */
int assorted_lzma_read_block_header(
     const uint8_t *compressed_data,
     size_t compressed_data_size,
     size_t *compressed_data_offset,
     libcerror_error_t **error )
{
	static char *function              = "assorted_lzma_read_block_header";
	size_t safe_compressed_data_offset = 0;
	size_t header_size                 = 0;

#if defined( HAVE_DEBUG_OUTPUT )
	uint32_t value_32bit               = 0;
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
	if( ( compressed_data_size < 1 )
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
		 "%s: invalid compressed data offset.",
		 function );

		return( -1 );
	}
	safe_compressed_data_offset = *compressed_data_offset;

	if( safe_compressed_data_offset > ( compressed_data_size - 1 ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_TOO_SMALL,
		 "%s: invalid compressed data value too small.",
		 function );

		return( -1 );
	}
	header_size = ( (size_t) compressed_data[ safe_compressed_data_offset ] + 1 ) * 4;

	if( ( header_size < 6 )
	 || ( header_size > compressed_data_size ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_OUT_OF_BOUNDS,
		 "%s: invalid header size value out of bounds.",
		 function );

		return( -1 );
	}
	if( safe_compressed_data_offset > ( compressed_data_size - header_size ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_TOO_SMALL,
		 "%s: invalid compressed data value too small.",
		 function );

		return( -1 );
	}
#if defined( HAVE_DEBUG_OUTPUT )
	if( libcnotify_verbose != 0 )
	{
		libcnotify_printf(
		 "%s: block header data:\n",
		 function );
		libcnotify_print_data(
		 &( compressed_data[ safe_compressed_data_offset ] ),
		 header_size,
		 0 );
	}
#endif

#if defined( HAVE_DEBUG_OUTPUT )
	if( libcnotify_verbose != 0 )
	{
		libcnotify_printf(
		 "%s: header size\t\t\t\t: %" PRIzd "\n",
		 function,
		 header_size );

		libcnotify_printf(
		 "%s: header flags\t\t\t\t: 0x%02" PRIx8 "\n",
		 function,
		 compressed_data[ safe_compressed_data_offset + 1 ] );
	}
#endif /* defined( HAVE_DEBUG_OUTPUT ) */

/* TODO implement */

#if defined( HAVE_DEBUG_OUTPUT )
	if( libcnotify_verbose != 0 )
	{
		byte_stream_copy_to_uint32_little_endian(
		 &( compressed_data[ safe_compressed_data_offset + header_size - 4 ] ),
		 value_32bit );
		libcnotify_printf(
		 "%s: checksum\t\t\t\t: 0x%08" PRIx32 "\n",
		 function,
		 value_32bit );

		libcnotify_printf(
		 "\n" );
	}
#endif /* defined( HAVE_DEBUG_OUTPUT ) */

	*compressed_data_offset = safe_compressed_data_offset + header_size;

	return( 1 );
}

/* Reads a LZMA encoded block
 * Returns 1 on success or -1 on error
 */
int assorted_lzma_read_lzma(
     assorted_bit_stream_t *bit_stream,
     uint8_t *uncompressed_data,
     size_t uncompressed_data_size,
     size_t *uncompressed_data_offset,
     libcerror_error_t **error )
{
	static char *function                = "assorted_lzma_read_lzma";
	size_t safe_uncompressed_data_offset = 0;
	size_t current_distance              = 0;
	size_t last_distance0                = 0;
	size_t last_distance1                = 0;
	size_t last_distance2                = 0;
	size_t last_distance3                = 0;
	uint32_t value_32bit                 = 0;
	uint16_t length                      = 0;
	uint8_t bit_index                    = 0;
	uint8_t code_sequence                = 0;
	uint8_t length_number_of_bits        = 0;
	uint8_t length_sequence              = 0;

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
		 "%s: invalid uncompressed data offset.",
		 function );

		return( -1 );
	}
	safe_uncompressed_data_offset = *uncompressed_data_offset;

	if( safe_uncompressed_data_offset > (size_t) SSIZE_MAX )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_EXCEEDS_MAXIMUM,
		 "%s: invalid uncompressed data offset value exceeds maximum.",
		 function );

		return( -1 );
	}
	if( assorted_bit_stream_get_value(
	     bit_stream,
	     8,
	     &value_32bit,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to retrieve value from bit stream.",
		 function );

		return( -1 );
	}
	/* The first byte in the encoded bit-stream should be 0
	 */
	if( value_32bit != 0 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_OUT_OF_BOUNDS,
		 "%s: unsupported first encoded byte value out of bounds.",
		 function );

		return( -1 );
	}
	while( bit_stream->byte_stream_offset < bit_stream->byte_stream_size )
	{
		code_sequence = 0;

		for( bit_index = 0;
		     bit_index < 5;
		     bit_index++ )
		{
			if( assorted_bit_stream_get_value(
			     bit_stream,
			     1,
			     &value_32bit,
			     error ) != 1 )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_RUNTIME,
				 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
				 "%s: unable to retrieve value from bit stream.",
				 function );

				return( -1 );
			}
			code_sequence <<= 1;
			code_sequence  |= (uint8_t) value_32bit;

			if( value_32bit == 0 )
			{
				break;
			}
		}
		if( code_sequence == 0x06 )
		{
			if( assorted_bit_stream_get_value(
			     bit_stream,
			     1,
			     &value_32bit,
			     error ) != 1 )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_RUNTIME,
				 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
				 "%s: unable to retrieve value from bit stream.",
				 function );

				return( -1 );
			}
			code_sequence <<= 1;
			code_sequence  |= (uint8_t) value_32bit;
		}
#if defined( HAVE_DEBUG_OUTPUT )
		if( libcnotify_verbose != 0 )
		{
			libcnotify_printf(
			 "%s: code sequence\t\t\t\t\t: 0x%02" PRIx8 "\n",
			 function,
			 code_sequence );
		}
#endif
		if( code_sequence == ASSORTED_LZMA_CONTROL_CODE_LITERAL )
		{
			if( assorted_bit_stream_get_value(
			     bit_stream,
			     8,
			     &value_32bit,
			     error ) != 1 )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_RUNTIME,
				 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
				 "%s: unable to retrieve value from bit stream.",
				 function );

				return( -1 );
			}
#if defined( HAVE_DEBUG_OUTPUT )
			if( libcnotify_verbose != 0 )
			{
				libcnotify_printf(
				 "%s: literal\t\t\t\t\t: 0x%02" PRIx32 "\n",
				 function,
				 value_32bit );
			}
#endif
			if( safe_uncompressed_data_offset >= uncompressed_data_size )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
				 LIBCERROR_ARGUMENT_ERROR_VALUE_TOO_SMALL,
				 "%s: invalid uncompressed data value too small.",
				 function );

				return( -1 );
			}
			current_distance = safe_uncompressed_data_offset;

			uncompressed_data[ safe_uncompressed_data_offset++ ] = (uint8_t) value_32bit;
		}
		else if( code_sequence == ASSORTED_LZMA_CONTROL_CODE_MATCH )
		{
/* TODO implement */
			break;
		}
		else if( code_sequence == ASSORTED_LZMA_CONTROL_CODE_SHORTREP )
		{
			if( safe_uncompressed_data_offset >= uncompressed_data_size )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
				 LIBCERROR_ARGUMENT_ERROR_VALUE_TOO_SMALL,
				 "%s: invalid uncompressed data value too small.",
				 function );

				return( -1 );
			}
#if defined( HAVE_DEBUG_OUTPUT )
			if( libcnotify_verbose != 0 )
			{
				libcnotify_printf(
				 "%s: shortrep\t\t\t\t\t: 0x%02" PRIx8 "\n",
				 function,
				 uncompressed_data[ current_distance ] );
			}
#endif
			uncompressed_data[ safe_uncompressed_data_offset++ ] = uncompressed_data[ current_distance ];
/* TODO determine what current_distance is */
		}
		else if( ( code_sequence == ASSORTED_LZMA_CONTROL_CODE_REP0 )
		      || ( code_sequence == ASSORTED_LZMA_CONTROL_CODE_REP1 )
		      || ( code_sequence == ASSORTED_LZMA_CONTROL_CODE_REP2 )
		      || ( code_sequence == ASSORTED_LZMA_CONTROL_CODE_REP3 ) )
		{
			length_sequence = 0;

			for( bit_index = 0;
			     bit_index < 2;
			     bit_index++ )
			{
				if( assorted_bit_stream_get_value(
				     bit_stream,
				     1,
				     &value_32bit,
				     error ) != 1 )
				{
					libcerror_error_set(
					 error,
					 LIBCERROR_ERROR_DOMAIN_RUNTIME,
					 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
					 "%s: unable to retrieve value from bit stream.",
					 function );

					return( -1 );
				}
				length_sequence <<= 1;
				length_sequence  |= (uint8_t) value_32bit;

				if( value_32bit == 0 )
				{
					break;
				}
			}
			if( length_sequence == 0x00 )
			{
				length_number_of_bits = 3;
				length                = 2;
			}
			else if( length_sequence == 0x02 )
			{
				length_number_of_bits = 3;
				length                = 10;
			}
			else if( length_sequence == 0x03 )
			{
				length_number_of_bits = 8;
				length                = 18;
			}
			if( assorted_bit_stream_get_value(
			     bit_stream,
			     length_number_of_bits,
			     &value_32bit,
			     error ) != 1 )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_RUNTIME,
				 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
				 "%s: unable to retrieve value from bit stream.",
				 function );

				return( -1 );
			}
			length += (uint16_t) value_32bit;

#if defined( HAVE_DEBUG_OUTPUT )
			if( libcnotify_verbose != 0 )
			{
				libcnotify_printf(
				 "%s: length sequence\t\t\t\t: 0x%02" PRIx8 "\n",
				 function,
				 length_sequence );

				libcnotify_printf(
				 "%s: length\t\t\t\t\t\t: %" PRIu16 "\n",
				 function,
				 length );
			}
#endif
			if( code_sequence == ASSORTED_LZMA_CONTROL_CODE_REP0 )
			{
				current_distance = last_distance0;
			}
			else if( code_sequence == ASSORTED_LZMA_CONTROL_CODE_REP1 )
			{
				current_distance = last_distance1;
			}
			else if( code_sequence == ASSORTED_LZMA_CONTROL_CODE_REP2 )
			{
				current_distance = last_distance2;
			}
			else if( code_sequence == ASSORTED_LZMA_CONTROL_CODE_REP3 )
			{
				current_distance = last_distance3;
			}
			if( ( length > uncompressed_data_size )
			 || ( safe_uncompressed_data_offset >= ( uncompressed_data_size - length ) ) )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
				 LIBCERROR_ARGUMENT_ERROR_VALUE_TOO_SMALL,
				 "%s: invalid uncompressed data value too small.",
				 function );

				return( -1 );
			}
			while( length > 0 )
			{
				uncompressed_data[ safe_uncompressed_data_offset++ ] = uncompressed_data[ current_distance++ ];

				length--;
			}
		}
		else
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_UNSUPPORTED_VALUE,
			 "%s: unsupported code sequence: 0x%02" PRIx8 ".",
			 function,
			 code_sequence );

			return( -1 );
		}
/* TODO determine what when last_distance[0-3] should be updated is */
		last_distance3 = last_distance2;
		last_distance2 = last_distance1;
		last_distance1 = last_distance0;
		last_distance0 = current_distance;
	}
#if defined( HAVE_DEBUG_OUTPUT )
	if( libcnotify_verbose != 0 )
	{
		libcnotify_printf(
		 "\n" );
	}
#endif
	*uncompressed_data_offset = safe_uncompressed_data_offset;

	return( 1 );
}

/* Reads a LZMA2 encoded block
 * Returns 1 on success or -1 on error
 */
int assorted_lzma_read_lzma2_block(
     const uint8_t *compressed_data,
     size_t compressed_data_size,
     size_t *compressed_data_offset,
     uint8_t *uncompressed_data,
     size_t uncompressed_data_size,
     size_t *uncompressed_data_offset,
     libcerror_error_t **error )
{
	assorted_bit_stream_t *bit_stream    = NULL;
	static char *function                = "assorted_lzma_read_lzma2_block";
	size_t safe_compressed_data_offset   = 0;
	size_t safe_uncompressed_data_offset = 0;
	uint32_t chunk_data_size             = 0;
	uint32_t uncompressed_chunk_size     = 0;
	uint8_t control_code                 = 0;
	uint8_t properties_value             = 0;
	uint8_t read_encoded_data            = 0;
	uint8_t read_properties              = 0;
	uint8_t read_uncompressed_chunk_size = 0;
	uint8_t reset_dictionary             = 0;

	uint8_t pb_value                     = 0;
	uint8_t lp_value                     = 0;
	uint8_t lc_value                     = 0;

#if defined( HAVE_DEBUG_OUTPUT )
	size_t block_data_offset             = 0;
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
	if( ( compressed_data_size < 1 )
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
		 "%s: invalid compressed data offset.",
		 function );

		return( -1 );
	}
	safe_compressed_data_offset = *compressed_data_offset;

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
		 "%s: invalid uncompressed data offset.",
		 function );

		return( -1 );
	}
	safe_uncompressed_data_offset = *uncompressed_data_offset;

	if( safe_uncompressed_data_offset > (size_t) SSIZE_MAX )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_EXCEEDS_MAXIMUM,
		 "%s: invalid uncompressed data offset value exceeds maximum.",
		 function );

		return( -1 );
	}
	while( safe_compressed_data_offset < compressed_data_size )
	{
		if( safe_compressed_data_offset > ( compressed_data_size - 1 ) )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
			 LIBCERROR_ARGUMENT_ERROR_VALUE_TOO_SMALL,
			 "%s: invalid compressed data value too small.",
			 function );

			goto on_error;
		}
		control_code = compressed_data[ safe_compressed_data_offset++ ];

#if defined( HAVE_DEBUG_OUTPUT )
		if( libcnotify_verbose != 0 )
		{
			libcnotify_printf(
			 "%s: control code\t\t\t\t: 0x%02" PRIx8 "\n",
			 function,
			 control_code );
		}
#endif
		if( control_code == 0x00 )
		{
			break;
		}
		if( ( control_code >= 0x02 )
		 && ( control_code <= 0x7f ) )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_VALUE_OUT_OF_BOUNDS,
			 "%s: unsupported control code value out of bounds.",
			 function );

			goto on_error;
		}
		if( control_code == 0x01 )
		{
			reset_dictionary  = 1;
			read_encoded_data = 0;
		}
		else
		{
			if( control_code >= 0xe0 )
			{
				reset_dictionary = 1;
			}
			if( control_code >= 0xc0 )
			{
				read_properties = 1;
			}
			if( control_code >= 0xa0 )
			{
/* TODO implement */
			}
			read_uncompressed_chunk_size = 1;
			read_encoded_data            = 1;
		}
		if( read_uncompressed_chunk_size != 0 )
		{
			if( safe_compressed_data_offset > ( compressed_data_size - 2 ) )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
				 LIBCERROR_ARGUMENT_ERROR_VALUE_TOO_SMALL,
				 "%s: invalid compressed data value too small.",
				 function );

				goto on_error;
			}
			uncompressed_chunk_size  = (uint32_t) ( control_code & 0x1f ) << 8;
			uncompressed_chunk_size += (uint32_t) compressed_data[ safe_compressed_data_offset++ ] << 8;
			uncompressed_chunk_size |= compressed_data[ safe_compressed_data_offset++ ];
			uncompressed_chunk_size += 1;

#if defined( HAVE_DEBUG_OUTPUT )
			if( libcnotify_verbose != 0 )
			{
				libcnotify_printf(
				 "%s: uncompressed chunk size\t\t\t: %" PRIu32 "\n",
				 function,
				 uncompressed_chunk_size );
			}
#endif
			read_uncompressed_chunk_size = 0;
		}
		if( safe_compressed_data_offset > ( compressed_data_size - 2 ) )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
			 LIBCERROR_ARGUMENT_ERROR_VALUE_TOO_SMALL,
			 "%s: invalid compressed data value too small.",
			 function );

			goto on_error;
		}
		chunk_data_size  = (uint32_t) compressed_data[ safe_compressed_data_offset++ ] << 8;
		chunk_data_size |= compressed_data[ safe_compressed_data_offset++ ];
		chunk_data_size += 1;

#if defined( HAVE_DEBUG_OUTPUT )
		if( libcnotify_verbose != 0 )
		{
			libcnotify_printf(
			 "%s: chunk data size\t\t\t\t: %" PRIu32 "\n",
			 function,
			 chunk_data_size );
		}
#endif
		if( read_properties != 0 )
		{
			if( safe_compressed_data_offset > ( compressed_data_size - 1 ) )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
				 LIBCERROR_ARGUMENT_ERROR_VALUE_TOO_SMALL,
				 "%s: invalid compressed data value too small.",
				 function );

				goto on_error;
			}
			properties_value = compressed_data[ safe_compressed_data_offset++ ];

/* TODO implement */
			pb_value          = properties_value / ( 9 * 5 );
			properties_value -= pb_value * 9 * 5;
			lp_value          = properties_value / 9;
			lc_value          = properties_value - ( properties_value * 9 );
			properties_value += pb_value * 9 * 5;

#if defined( HAVE_DEBUG_OUTPUT )
			if( libcnotify_verbose != 0 )
			{
				libcnotify_printf(
				 "%s: properties value\t\t\t: 0x%02" PRIx8 " (pb: %" PRId8 ", lp: %" PRId8 ", lc: %" PRId8 ")\n",
				 function,
				 properties_value,
				 pb_value,
				 lp_value,
				 lc_value );
			}
#endif
			read_properties = 0;
		}
		if( ( chunk_data_size > compressed_data_size )
		 || ( safe_compressed_data_offset > ( compressed_data_size - chunk_data_size ) ) )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
			 LIBCERROR_ARGUMENT_ERROR_VALUE_TOO_SMALL,
			 "%s: invalid compressed data value too small.",
			 function );

			goto on_error;
		}
#if defined( HAVE_DEBUG_OUTPUT )
		if( libcnotify_verbose != 0 )
		{
			libcnotify_printf(
			 "%s: compressed chunk data:\n",
			 function );
			libcnotify_print_data(
			 &( compressed_data[ safe_compressed_data_offset ] ),
			 chunk_data_size,
			 0 );
		}
#endif
#if defined( HAVE_DEBUG_OUTPUT )
		block_data_offset = safe_uncompressed_data_offset;
#endif
		if( read_encoded_data != 0 )
		{
			if( assorted_bit_stream_initialize(
			     &bit_stream,
			     compressed_data,
			     compressed_data_size,
			     safe_compressed_data_offset,
			     ASSORTED_BIT_STREAM_STORAGE_TYPE_BYTE_FRONT_TO_BACK,
			     error ) != 1 )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_RUNTIME,
				 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
				 "%s: unable to create bit stream.",
				 function );

				goto on_error;
			}
			if( assorted_lzma_read_lzma(
			     bit_stream,
			     uncompressed_data,
			     uncompressed_data_size,
			     &safe_uncompressed_data_offset,
			     error ) != 1 )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_IO,
				 LIBCERROR_IO_ERROR_READ_FAILED,
				 "%s: unable to read LZMA encoded data.",
				 function );

				goto on_error;
			}
			if( assorted_bit_stream_free(
			     &bit_stream,
			     error ) != 1 )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_RUNTIME,
				 LIBCERROR_RUNTIME_ERROR_FINALIZE_FAILED,
				 "%s: unable to free bit stream.",
				 function );

				goto on_error;
			}
		}
		else
		{
/* TODO implement read uncompressed data */
		}
#if defined( HAVE_DEBUG_OUTPUT )
		if( libcnotify_verbose != 0 )
		{
			libcnotify_printf(
			 "%s: chunk data:\n",
			 function );
			libcnotify_print_data(
			 &( uncompressed_data[ block_data_offset ] ),
			 safe_uncompressed_data_offset - block_data_offset,
			 0 );
		}
#endif
		safe_compressed_data_offset += chunk_data_size;
	}
#if defined( HAVE_DEBUG_OUTPUT )
	if( libcnotify_verbose != 0 )
	{
		libcnotify_printf(
		 "\n" );
	}
#endif
	*compressed_data_offset = safe_compressed_data_offset;

	return( 1 );

on_error:
	if( bit_stream != NULL )
	{
		assorted_bit_stream_free(
		 &bit_stream,
		 NULL );
	}
	return( -1 );
}

/* Reads the stream footer
 * Returns 1 on success or -1 on error
 */
int assorted_lzma_read_stream_footer(
     const uint8_t *compressed_data,
     size_t compressed_data_size,
     size_t *compressed_data_offset,
     libcerror_error_t **error )
{
	static char *function              = "assorted_lzma_read_stream_footer";
	size_t safe_compressed_data_offset = 0;

#if defined( HAVE_DEBUG_OUTPUT )
	uint32_t value_32bit               = 0;
	uint16_t value_16bit               = 0;
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
	if( ( compressed_data_size < 12 )
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
		 "%s: invalid compressed data offset.",
		 function );

		return( -1 );
	}
	safe_compressed_data_offset = *compressed_data_offset;

	if( safe_compressed_data_offset > ( compressed_data_size - 12 ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_TOO_SMALL,
		 "%s: invalid compressed data value too small.",
		 function );

		return( -1 );
	}
#if defined( HAVE_DEBUG_OUTPUT )
	if( libcnotify_verbose != 0 )
	{
		libcnotify_printf(
		 "%s: stream footer data:\n",
		 function );
		libcnotify_print_data(
		 &( compressed_data[ safe_compressed_data_offset ] ),
		 12,
		 0 );
	}
#endif
	if( ( compressed_data[ safe_compressed_data_offset + 10 ] != 'Y' )
	 || ( compressed_data[ safe_compressed_data_offset + 11 ] != 'Z' ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_UNSUPPORTED_VALUE,
		 "%s: unsupported signature.",
		 function );

		return( -1 );
	}
#if defined( HAVE_DEBUG_OUTPUT )
	if( libcnotify_verbose != 0 )
	{
		byte_stream_copy_to_uint32_little_endian(
		 &( compressed_data[ safe_compressed_data_offset ] ),
		 value_32bit );
		libcnotify_printf(
		 "%s: checksum\t\t\t\t: 0x%08" PRIx32 "\n",
		 function,
		 value_32bit );

		byte_stream_copy_to_uint32_little_endian(
		 &( compressed_data[ safe_compressed_data_offset + 4 ] ),
		 value_32bit );
		libcnotify_printf(
		 "%s: backwards size\t\t\t\t: %" PRIu32 "\n",
		 function,
		 value_32bit );

		byte_stream_copy_to_uint16_little_endian(
		 &( compressed_data[ safe_compressed_data_offset + 8 ] ),
		 value_16bit );
		libcnotify_printf(
		 "%s: stream flags\t\t\t\t: 0x%04" PRIx16 "\n",
		 function,
		 value_16bit );

		libcnotify_printf(
		 "%s: signature\t\t\t\t: %c%c\n",
		 function,
		 compressed_data[ safe_compressed_data_offset + 10 ],
		 compressed_data[ safe_compressed_data_offset + 11 ] );

		libcnotify_printf(
		 "\n" );
	}
#endif /* defined( HAVE_DEBUG_OUTPUT ) */

	*compressed_data_offset = safe_compressed_data_offset + 12;

	return( 1 );
}

/* Decompresses LZMA compressed data
 * Returns 1 on success or -1 on error
 */
int assorted_lzma_decompress(
     const uint8_t *compressed_data,
     size_t compressed_data_size,
     uint8_t *uncompressed_data,
     size_t *uncompressed_data_size,
     libcerror_error_t **error )
{
	static char *function              = "assorted_lzma_decompress";
	size_t compressed_data_offset      = 0;
	size_t safe_uncompressed_data_size = 0;
	size_t uncompressed_data_offset    = 0;

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

	if( assorted_lzma_read_stream_header(
	     compressed_data,
	     compressed_data_size,
	     &compressed_data_offset,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_IO,
		 LIBCERROR_IO_ERROR_READ_FAILED,
		 "%s: unable to read stream header.",
		 function );

		return( -1 );
	}
	while( compressed_data_offset < compressed_data_size )
	{
		if( assorted_lzma_read_block_header(
		     compressed_data,
		     compressed_data_size,
		     &compressed_data_offset,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_IO,
			 LIBCERROR_IO_ERROR_READ_FAILED,
			 "%s: unable to read block header.",
			 function );

			return( -1 );
		}
/* TODO make sure LZMA2 filter is present */
		if( assorted_lzma_read_lzma2_block(
		     compressed_data,
		     compressed_data_size,
		     &compressed_data_offset,
		     uncompressed_data,
		     safe_uncompressed_data_size,
		     &uncompressed_data_offset,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_IO,
			 LIBCERROR_IO_ERROR_READ_FAILED,
			 "%s: unable to read LZMA2 block.",
			 function );

			return( -1 );
		}
	}
	if( assorted_lzma_read_stream_footer(
	     compressed_data,
	     compressed_data_size,
	     &compressed_data_offset,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_IO,
		 LIBCERROR_IO_ERROR_READ_FAILED,
		 "%s: unable to read stream footer.",
		 function );

		return( -1 );
	}
	*uncompressed_data_size = uncompressed_data_offset;

	return( 1 );
}

