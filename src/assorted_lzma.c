/*
 * LZMA (un)compression functions
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
#include "assorted_lzma.h"

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

/* Reads the block
 * Returns 1 on success or -1 on error
 */
int assorted_lzma_read_block(
     const uint8_t *compressed_data,
     size_t compressed_data_size,
     size_t *compressed_data_offset,
     libcerror_error_t **error )
{
	static char *function              = "assorted_lzma_read_block";
	size_t safe_compressed_data_offset = 0;
	uint16_t uncompressed_chunk_size   = 0;
	uint8_t byte_value                 = 0;
	uint8_t has_properties             = 0;
	uint8_t reset_dictionary           = 0;

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

			return( -1 );
		}
		byte_value = compressed_data[ safe_compressed_data_offset++ ];

#if defined( HAVE_DEBUG_OUTPUT )
		if( libcnotify_verbose != 0 )
		{
			libcnotify_printf(
			 "%s: control value\t\t\t\t\t: 0x%02" PRIx8 "\n",
			 function,
			 byte_value );
		}
#endif
		if( byte_value == 0x00 )
		{
			break;
		}
		if( ( byte_value >= 0x02 )
		 && ( byte_value <= 0x7f ) )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_VALUE_OUT_OF_BOUNDS,
			 "%s: unsupported control code value out of bounds.",
			 function );

			return( -1 );
		}
		if( ( byte_value == 0x01 )
		 && ( byte_value >= 0xe0 ) )
		{
			reset_dictionary = 1;
		}
		if( byte_value >= 0xc0 )
		{
			has_properties = 1;
		}
		uncompressed_chunk_size = (uint16_t) ( byte_value & 0x1f ) << 8;
/* TODO implement */
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
		if( assorted_lzma_read_block(
		     compressed_data,
		     compressed_data_size,
		     &compressed_data_offset,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_IO,
			 LIBCERROR_IO_ERROR_READ_FAILED,
			 "%s: unable to read block.",
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

