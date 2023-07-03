/*
 * LZFu (un)compression functions
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

#include "assorted_crc32.h"
#include "assorted_libcerror.h"
#include "assorted_libcnotify.h"
#include "assorted_lzfu.h"

#define ASSORTED_LZFU_SIGNATURE_COMPRESSED        0x75465a4c
#define ASSORTED_LZFU_SIGNATURE_UNCOMPRESSED      0x414c454d

const char *assorted_lzfu_rtf_dictionary = \
	"{\\rtf1\\ansi\\mac\\deff0\\deftab720"
	"{\\fonttbl;}"
	"{\\f0\\fnil \\froman \\fswiss \\fmodern \\fscript \\fdecor MS Sans SerifSymbolArialTimes New RomanCourier"
	"{\\colortbl\\red0\\green0\\blue0\r\n\\par \\pard\\plain\\f0\\fs20\\b\\i\\u\\tab\\tx";

/* Determines the uncompressed data size from the LZFu header in the compressed data
 * Return 1 on success or -1 on error
 */
int assorted_lzfu_get_uncompressed_data_size(
     const uint8_t *compressed_data,
     size_t compressed_data_size,
     size_t *uncompressed_data_size,
     libcerror_error_t **error )
{
	assorted_lzfu_header_t lzfu_header;

	uint8_t *lzfu_data                = 0;
	static char *function             = "lzfu_get_uncompressed_data_size";

	uint8_t lz_buffer[ 4096 ];

	uint8_t *lzfu_reference_data      = 0;
	size_t compressed_data_iterator   = 0;
	size_t uncompressed_data_iterator = 0;
	uint16_t lz_buffer_iterator       = 0;
	uint16_t reference_offset         = 0;
	uint16_t reference_size           = 0;
	uint16_t reference_iterator       = 0;
	uint8_t flag_byte_bit_mask        = 0;
	uint8_t flag_byte                 = 0;

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
	lzfu_data = compressed_data;

	byte_stream_copy_to_uint32_little_endian(
	 lzfu_data,
	 lzfu_header.compressed_data_size );

	lzfu_data += 4;

	byte_stream_copy_to_uint32_little_endian(
	 lzfu_data,
	 lzfu_header.uncompressed_data_size );

	lzfu_data += 4;

	byte_stream_copy_to_uint32_little_endian(
	 lzfu_data,
	 lzfu_header.signature );

	lzfu_data += 8;

	if( ( lzfu_header.signature != ASSORTED_LZFU_SIGNATURE_COMPRESSED )
	 && ( lzfu_header.signature != ASSORTED_LZFU_SIGNATURE_UNCOMPRESSED ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_UNSUPPORTED_VALUE,
		 "%s: unsupported compression signature: 0x%08" PRIx32 ".",
		 function,
		 lzfu_header.signature );

		return( -1 );
	}
	compressed_data_size -= sizeof( assorted_lzfu_header_t );

	/* The compressed data size includes 12 bytes of the header
	 */
	lzfu_header.compressed_data_size -= 12;

#ifdef X
	if( (size_t) lzfu_header.compressed_data_size != compressed_data_size )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_OUT_OF_RANGE,
		 "%s: mismatch in compressed data size (%" PRIu32 " != %" PRIzd ").",
		 function,
		 lzfu_header.compressed_data_size,
		 compressed_data_size );

		return( -1 );
	}
#endif
	if( memory_copy(
	     lz_buffer,
	     assorted_lzfu_rtf_dictionary,
	     207 ) == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_COPY_FAILED,
		 "%s: unable to initialize lz buffer.",
		 function );

		return( -1 );
	}
	lz_buffer_iterator = 207;

	if( memory_set(
	     &( lz_buffer[ lz_buffer_iterator ] ),
	     0,
	     ( 4096 - lz_buffer_iterator ) ) == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_SET_FAILED,
		 "%s: unable to clear lz buffer.",
		 function );

		return( -1 );
	}
	while( compressed_data_iterator < (size_t) lzfu_header.compressed_data_size )
	{
		flag_byte = lzfu_data[ compressed_data_iterator++ ];

		/* Check every bit in the chunk flag byte from LSB to MSB
		 */
		for( flag_byte_bit_mask = 0x01;
		     flag_byte_bit_mask != 0x00;
		     flag_byte_bit_mask <<= 1 )
		{
			if( compressed_data_iterator == (size_t) lzfu_header.compressed_data_size )
			{
				break;
			}
			/* Check if the byte value is a literal or a reference
			 */
			if( ( flag_byte & flag_byte_bit_mask ) == 0 )
			{
				lz_buffer[ lz_buffer_iterator++ ] = lzfu_data[ compressed_data_iterator ];

				uncompressed_data_iterator++;
				compressed_data_iterator++;

				/* Make sure the lz buffer iterator wraps around
				 */
				lz_buffer_iterator %= 4096;

				lz_buffer[ lz_buffer_iterator ] = 0;
			}
			else
			{
				lzfu_reference_data = &( lzfu_data[ compressed_data_iterator ] );

				compressed_data_iterator += 2;

				byte_stream_copy_to_uint16_big_endian(
				 lzfu_reference_data,
				 reference_offset );

				reference_size     = ( reference_offset & 0x000f ) + 2;
				reference_offset >>= 4;

				for( reference_iterator = 0; reference_iterator < reference_size; reference_iterator++ )
				{
					lz_buffer[ lz_buffer_iterator++ ] = lz_buffer[ reference_offset ];

					uncompressed_data_iterator++;
					reference_offset++;

					/* Make sure the lz buffer iterator and reference offset wrap around
					 */
					lz_buffer_iterator %= 4096;
					reference_offset   %= 4096;

					lz_buffer[ lz_buffer_iterator ] = 0;
				}
			}
		}
	}
	if( (size_t) ( lzfu_header.uncompressed_data_size + 2 ) != uncompressed_data_iterator )
	{
		if( libcnotify_verbose != 0 )
		{
			libcnotify_printf(
			 "%s: mismatch in uncompressed data size (in header: %" PRIu32 " != required: %" PRIzd ").\n",
			 function,
			 lzfu_header.uncompressed_data_size + 2,
			 uncompressed_data_iterator );
		}
	}
	/* Compensate for the 2 trailing zero bytes
	 */
	*uncompressed_data_size = lzfu_header.uncompressed_data_size + 2;

	return( 1 );
}

/* Compresses data using LZFu compression
 * Returns 1 on success or -1 on error
 */
int assorted_lzfu_compress(
     const uint8_t *uncompressed_data,
     size_t uncompressed_data_size,
     uint8_t *compressed_data,
     size_t *compressed_data_size,
     libcerror_error_t **error )
{
	static char *function = "lzfu_compress";

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
	if( compressed_data_size == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid compressed data size.",
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
/* TODO implement */
	libcerror_error_set(
	 error,
	 LIBCERROR_ERROR_DOMAIN_RUNTIME,
	 LIBCERROR_RUNTIME_ERROR_GENERIC,
	 "%s: NOT IMPLEMENTED YET",
	 function );

	return( -1 );
}

/* Decompresses data using LZFu compression
 * Returns 1 on success or -1 on error
 */
int assorted_lzfu_decompress(
     const uint8_t *compressed_data,
     size_t compressed_data_size,
     uint8_t *uncompressed_data,
     size_t *uncompressed_data_size,
     libcerror_error_t **error )
{
	uint8_t lz_buffer[ 4096 ];

	assorted_lzfu_header_t lzfu_header;

	const uint8_t *lzfu_data           = NULL;
	const uint8_t *lzfu_reference_data = NULL;
	static char *function              = "lzfu_decompress";
	size_t compressed_data_iterator    = 0;
	size_t uncompressed_data_iterator  = 0;
	uint32_t calculated_crc            = 0;
	uint16_t lz_buffer_iterator        = 0;
	uint16_t reference_iterator        = 0;
	uint16_t reference_offset          = 0;
	uint16_t reference_size            = 0;
	uint8_t flag_byte                  = 0;
	uint8_t flag_byte_bit_mask         = 0;

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
	if( memory_copy(
	     lz_buffer,
	     assorted_lzfu_rtf_dictionary,
	     207 ) == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_COPY_FAILED,
		 "%s: unable to initialize lz buffer.",
		 function );

		return( -1 );
	}
	lz_buffer_iterator = 207;

	if( memory_set(
	     &( lz_buffer[ lz_buffer_iterator ] ),
	     0,
	     ( 4096 - lz_buffer_iterator ) ) == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_SET_FAILED,
		 "%s: unable to clear lz buffer.",
		 function );

		return( -1 );
	}
	lzfu_data = compressed_data;

	byte_stream_copy_to_uint32_little_endian(
	 lzfu_data,
	 lzfu_header.compressed_data_size );

	lzfu_data += 4;

	byte_stream_copy_to_uint32_little_endian(
	 lzfu_data,
	 lzfu_header.uncompressed_data_size );

	lzfu_data += 4;

	byte_stream_copy_to_uint32_little_endian(
	 lzfu_data,
	 lzfu_header.signature );

	lzfu_data += 4;

	byte_stream_copy_to_uint32_little_endian(
	 lzfu_data,
	 lzfu_header.crc );

	lzfu_data += 4;

	if( libcnotify_verbose != 0 )
	{
		libcnotify_printf(
		 "%s: lzfu header compressed data size\t: %" PRIu32 "\n",
		 function,
		 lzfu_header.compressed_data_size );

		libcnotify_printf(
		 "%s: lzfu header uncompressed data size\t: %" PRIu32 "\n",
		 function,
		 lzfu_header.uncompressed_data_size );

		libcnotify_printf(
		 "%s: lzfu header signature\t\t\t: 0x08%" PRIx32 "\n",
		 function,
		 lzfu_header.signature );

		libcnotify_printf(
		 "%s: lzfu header crc\t\t\t: %" PRIu32 "\n",
		 function,
		 lzfu_header.crc );
	}
	if( ( lzfu_header.signature != ASSORTED_LZFU_SIGNATURE_COMPRESSED )
	 && ( lzfu_header.signature != ASSORTED_LZFU_SIGNATURE_UNCOMPRESSED ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
		 "%s: unsupported compression signature: 0x%08" PRIx32 ".",
		 function,
		 lzfu_header.signature );

		return( -1 );
	}
	compressed_data_size -= sizeof( assorted_lzfu_header_t );

	/* The compressed data size includes 12 bytes of the header
	 */
	lzfu_header.compressed_data_size -= 12;

#ifdef X
	if( lzfu_header.compressed_data_size != compressed_data_size )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_OUT_OF_RANGE,
		 "%s: mismatch in compressed data size (%" PRIu32 " != %" PRIzd ").",
		 function,
		 lzfu_header.compressed_data_size,
		 compressed_data_size );

		return( -1 );
	}
#endif
	/* Make sure the uncompressed buffer is large enough
	 */
	if( *uncompressed_data_size < lzfu_header.uncompressed_data_size )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_TOO_SMALL,
		 "%s: uncompressed data too small.",
		 function );

		*uncompressed_data_size = lzfu_header.uncompressed_data_size;

		return( -1 );
	}
	if( assorted_crc32_calculate(
	     &calculated_crc,
	     lzfu_data,
	     (size_t) lzfu_header.compressed_data_size,
	     0,
	     1,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_SET_FAILED,
		 "%s: unable to calculate weak CRC.",
		 function );

		return( -1 );
	}
	if( lzfu_header.crc != calculated_crc )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_INPUT,
		 LIBCERROR_INPUT_ERROR_CHECKSUM_MISMATCH,
		 "%s: mismatch in crc ( %" PRIu32 " != %" PRIu32 " ).",
		 function,
		 lzfu_header.crc,
		 calculated_crc );

		return( -1 );
	}
	while( compressed_data_iterator < (size_t) lzfu_header.compressed_data_size )
	{
		flag_byte = lzfu_data[ compressed_data_iterator++ ];

		/* Check every bit in the chunk flag byte from LSB to MSB
		 */
		for( flag_byte_bit_mask = 0x01; flag_byte_bit_mask != 0x00; flag_byte_bit_mask <<= 1 )
		{
			if( compressed_data_iterator == (size_t) lzfu_header.compressed_data_size )
			{
				break;
			}
			/* Check if the byte value is a literal or a reference
			 */
			if( ( flag_byte & flag_byte_bit_mask ) == 0 )
			{
				if( compressed_data_iterator >= (size_t) lzfu_header.compressed_data_size )
				{
					libcerror_error_set(
					 error,
					 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
					 LIBCERROR_ARGUMENT_ERROR_VALUE_TOO_SMALL,
					 "%s: missing compressed data.",
					 function );

					*uncompressed_data_size = 0;

					return( -1 );
				}
				if( uncompressed_data_iterator >= *uncompressed_data_size )
				{
					libcerror_error_set(
					 error,
					 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
					 LIBCERROR_ARGUMENT_ERROR_VALUE_TOO_SMALL,
					 "%s: uncompressed data too small.",
					 function );

					*uncompressed_data_size = uncompressed_data_iterator;

					return( -1 );
				}
				lz_buffer[ lz_buffer_iterator++ ]                 = lzfu_data[ compressed_data_iterator ];
				uncompressed_data[ uncompressed_data_iterator++ ] = lzfu_data[ compressed_data_iterator ];

				compressed_data_iterator++;

				/* Make sure the lz buffer iterator wraps around
				 */
				lz_buffer_iterator %= 4096;

				lz_buffer[ lz_buffer_iterator ] = 0;
			}
			else
			{
				if( ( compressed_data_iterator + 1 ) >= (size_t) lzfu_header.compressed_data_size )
				{
					libcerror_error_set(
					 error,
					 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
					 LIBCERROR_ARGUMENT_ERROR_VALUE_TOO_SMALL,
					 "%s: missing compressed data.",
					 function );

					*uncompressed_data_size = 0;

					return( -1 );
				}
				lzfu_reference_data = &( lzfu_data[ compressed_data_iterator ] );

				compressed_data_iterator += 2;

				byte_stream_copy_to_uint16_big_endian(
				 lzfu_reference_data,
				 reference_offset );

				reference_size     = ( reference_offset & 0x000f ) + 2;
				reference_offset >>= 4;

				if( ( uncompressed_data_iterator + reference_size - 1 ) >= *uncompressed_data_size )
				{
					libcerror_error_set(
					 error,
					 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
					 LIBCERROR_ARGUMENT_ERROR_VALUE_TOO_SMALL,
					 "%s: uncompressed data too small.",
					 function );

					*uncompressed_data_size = uncompressed_data_iterator + reference_size;

					return( -1 );
				}
				for( reference_iterator = 0; reference_iterator < reference_size; reference_iterator++ )
				{
					lz_buffer[ lz_buffer_iterator++ ]                 = lz_buffer[ reference_offset ];
					uncompressed_data[ uncompressed_data_iterator++ ] = lz_buffer[ reference_offset ];

					reference_offset++;

					/* Make sure the lz buffer iterator and reference offset wrap around
					 */
					lz_buffer_iterator %= 4096;
					reference_offset   %= 4096;

					lz_buffer[ lz_buffer_iterator ] = 0;
				}
			}
		}
	}
	*uncompressed_data_size = uncompressed_data_iterator;

	return( 1 );
}

