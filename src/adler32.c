/*
 * Adler-32 functions
 *
 * Copyright (C) 2008-2018, Joachim Metz <joachim.metz@gmail.com>
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
#include <byte_stream.h>
#include <types.h>

#if defined( HAVE_STDLIB_H )
#include <stdlib.h>
#endif

#include "adler32.h"
#include "assorted_libcerror.h"

typedef union
{
	uint8_t vector __attribute__ ((vector_size (8)));
	uint8_t integer[ 8 ];

} adler32_8byte_vector_t;

/* The largest primary (or scalar) available
 * supported by a single load and store instruction
 */
typedef unsigned long int adler32_aligned_t;

/* Calculates the Adler-32 of a buffer
 * Use a previous key of 0 to calculate a new Adler-32
 * Returns 1 if successful or -1 on error
 */
int checksum_calculate_adler32_basic1(
     uint32_t *checksum_value,
     uint8_t *buffer,
     size_t size,
     uint32_t initial_value,
     libcerror_error_t **error )
{
	static char *function = "checksum_calculate_adler32_basic1";
	size_t buffer_index   = 0;
	uint32_t lower_word   = 0;
	uint32_t upper_word   = 0;

	if( checksum_value == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid checksum value.",
		 function );

		return( -1 );
	}
	if( buffer == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid buffer.",
		 function );

		return( -1 );
	}
	if( size > (size_t) SSIZE_MAX )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_EXCEEDS_MAXIMUM,
		 "%s: invalid size value exceeds maximum.",
		 function );

		return( -1 );
	}
	lower_word = initial_value & 0xffff;
	upper_word = ( initial_value >> 16 ) & 0xffff;

	for( buffer_index = 0;
	     buffer_index < size;
	     buffer_index++ )
	{
		lower_word += buffer[ buffer_index ];
		upper_word += lower_word;

		if( ( buffer_index != 0 )
		 && ( ( ( buffer_index % 0x15b0 ) == 0 )
		  || ( buffer_index == size - 1 ) ) )
		{
			lower_word = lower_word % 0xfff1;
			upper_word = upper_word % 0xfff1;
		}
	}
	*checksum_value = ( upper_word << 16 ) | lower_word;

	return( 1 );
}

/* Calculates the Adler-32 of a buffer
 * Use a previous key of 0 to calculate a new Adler-32
 * Returns 1 if successful or -1 on error
 */
int checksum_calculate_adler32_basic2(
     uint32_t *checksum_value,
     uint8_t *buffer,
     size_t size,
     uint32_t initial_value,
     libcerror_error_t **error )
{
	static char *function = "checksum_calculate_adler32_basic2";
	size_t buffer_offset  = 0;
	uint32_t lower_word   = 0;
	uint32_t upper_word   = 0;

	if( checksum_value == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid checksum value.",
		 function );

		return( -1 );
	}
	if( buffer == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid buffer.",
		 function );

		return( -1 );
	}
	if( size > (size_t) SSIZE_MAX )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_EXCEEDS_MAXIMUM,
		 "%s: invalid size value exceeds maximum.",
		 function );

		return( -1 );
	}
	lower_word = initial_value & 0xffff;
	upper_word = ( initial_value >> 16 ) & 0xffff;

	if( size > 0 )
	{
		while( size > 0 )
		{
			lower_word += buffer[ buffer_offset ];
			upper_word += lower_word;

			if( ( buffer_offset != 0 )
			 && ( ( buffer_offset % 0x15b0 ) == 0 ) )
			{
				lower_word %= 0xfff1;
				upper_word %= 0xfff1;
			}
			buffer_offset++;
			size--;
		}
		lower_word %= 0xfff1;
		upper_word %= 0xfff1;
	}
	*checksum_value = ( upper_word << 16 ) | lower_word;

	return( 1 );
}

/* Calculates the Adler-32 of a buffer
 * Use a previous key of 0 to calculate a new Adler-32
 * Returns 1 if successful or -1 on error
 */
int checksum_calculate_adler32_unfolded4_1(
     uint32_t *checksum_value,
     uint8_t *buffer,
     size_t size,
     uint32_t initial_value,
     libcerror_error_t **error )
{
	static char *function = "checksum_calculate_adler32_unfolded4_1";
	size_t buffer_offset  = 0;
	uint32_t lower_word   = 0;
	uint32_t upper_word   = 0;

	if( checksum_value == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid checksum value.",
		 function );

		return( -1 );
	}
	if( buffer == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid buffer.",
		 function );

		return( -1 );
	}
	if( size > (size_t) SSIZE_MAX )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_EXCEEDS_MAXIMUM,
		 "%s: invalid size value exceeds maximum.",
		 function );

		return( -1 );
	}
	lower_word = initial_value & 0xffff;
	upper_word = ( initial_value >> 16 ) & 0xffff;

	while( ( buffer_offset + 3 ) < ( size - 4 ) )
	{
		lower_word += buffer[ buffer_offset ];

		upper_word += lower_word;

		if( ( buffer_offset != 0 )
		 && ( ( buffer_offset % 0x15b0 == 0 )
		  || ( buffer_offset == size - 1 ) ) )
		{
			lower_word %= 0xfff1;
			upper_word %= 0xfff1;
		}
		upper_word += ( 3 * lower_word )
			    + ( 3 * buffer[ buffer_offset + 1 ] )
			    + ( 2 * buffer[ buffer_offset + 2 ] )
			    + buffer[ buffer_offset + 3 ];

		lower_word += buffer[ buffer_offset + 1 ]
			    + buffer[ buffer_offset + 2 ]
			    + buffer[ buffer_offset + 3 ];

		buffer_offset += 4;
	}
	while( buffer_offset < size )
	{
		lower_word += buffer[ buffer_offset ];
		upper_word += lower_word;

		if( ( buffer_offset != 0 )
		 && ( ( ( buffer_offset % 0x15b0 ) == 0 )
		  || ( buffer_offset == size - 1 ) ) )
		{
			lower_word %= 0xfff1;
			upper_word %= 0xfff1;
		}
		buffer_offset++;
	}
	*checksum_value = ( upper_word << 16 ) | lower_word;

	return( 1 );
}

/* Calculates the Adler-32 of a buffer
 * Use a previous key of 0 to calculate a new Adler-32
 * Returns 1 if successful or -1 on error
 */
int checksum_calculate_adler32_unfolded4_2(
     uint32_t *checksum_value,
     uint8_t *buffer,
     size_t size,
     uint32_t initial_value,
     libcerror_error_t **error )
{
	uint8_t *buffer_index = NULL;
	static char *function = "checksum_calculate_adler32_unfolded4_2";
	size_t buffer_offset  = 0;
	uint32_t lower_word   = 0;
	uint32_t upper_word   = 0;

	if( checksum_value == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid checksum value.",
		 function );

		return( -1 );
	}
	if( buffer == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid buffer.",
		 function );

		return( -1 );
	}
	if( size > (size_t) SSIZE_MAX )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_EXCEEDS_MAXIMUM,
		 "%s: invalid size value exceeds maximum.",
		 function );

		return( -1 );
	}
	lower_word = initial_value & 0xffff;
	upper_word = ( initial_value >> 16 ) & 0xffff;

	buffer_index = (uint8_t *) buffer;

	while( ( buffer_offset + 3 ) < ( size - 4 ) )
	{
		lower_word += *buffer_index;
		upper_word += lower_word;

		buffer_index++;

		if( ( buffer_offset != 0 )
		 && ( ( buffer_offset % 0x15b0 == 0 )
		  || ( buffer_offset == size - 1 ) ) )
		{
			lower_word %= 0xfff1;
			upper_word %= 0xfff1;
		}
		upper_word += ( 3 * lower_word )
		            + ( 3 * *buffer_index );

		lower_word += *buffer_index;

		buffer_index++;

		lower_word += *buffer_index;
		upper_word += 2 * *buffer_index;

		buffer_index++;

		lower_word += *buffer_index;
		upper_word += *buffer_index;

		buffer_index++;

		buffer_offset += 4;
	}
	while( buffer_offset < size )
	{
		lower_word += *buffer_index;
		upper_word += lower_word;

		if( ( buffer_offset != 0 )
		 && ( ( ( buffer_offset % 0x15b0 ) == 0 )
		  || ( buffer_offset == size - 1 ) ) )
		{
			lower_word %= 0xfff1;
			upper_word %= 0xfff1;
		}
		buffer_index++;
		buffer_offset++;
	}
	*checksum_value = ( upper_word << 16 ) | lower_word;

	return( 1 );
}

/* Calculates the Adler-32 of a buffer
 * Use a previous key of 0 to calculate a new Adler-32
 * Returns 1 if successful or -1 on error
 */
int checksum_calculate_adler32_unfolded16_1(
     uint32_t *checksum_value,
     uint8_t *buffer,
     size_t size,
     uint32_t initial_value,
     libcerror_error_t **error )
{
	static char *function = "checksum_calculate_adler32_unfolded16_1";
	size_t buffer_offset  = 0;
	uint32_t lower_word   = 0;
	uint32_t upper_word   = 0;
	int block_index       = 0;

	if( checksum_value == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid checksum value.",
		 function );

		return( -1 );
	}
	if( buffer == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid buffer.",
		 function );

		return( -1 );
	}
	if( size > (size_t) SSIZE_MAX )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_EXCEEDS_MAXIMUM,
		 "%s: invalid size value exceeds maximum.",
		 function );

		return( -1 );
	}
	lower_word = initial_value & 0xffff;
	upper_word = ( initial_value >> 16 ) & 0xffff;

	while( size >= 0x15b0 )
	{
		/* The modulo calculation is needed per 5552 (0x15b0) bytes
		 * 5552 / 16 = 347
		 */
		for( block_index = 0;
		     block_index < 347;
		     block_index++ )
		{
			upper_word += ( 16 * lower_word )
				    + ( 16 * buffer[ buffer_offset ] )
				    + ( 15 * buffer[ buffer_offset + 1 ] )
				    + ( 14 * buffer[ buffer_offset + 2 ] )
				    + ( 13 * buffer[ buffer_offset + 3 ] )
				    + ( 12 * buffer[ buffer_offset + 4 ] )
				    + ( 11 * buffer[ buffer_offset + 5 ] )
				    + ( 10 * buffer[ buffer_offset + 6 ] )
				    + ( 9 * buffer[ buffer_offset + 7 ] )
				    + ( 8 * buffer[ buffer_offset + 8 ] )
				    + ( 7 * buffer[ buffer_offset + 9 ] )
				    + ( 6 * buffer[ buffer_offset + 10 ] )
				    + ( 5 * buffer[ buffer_offset + 11 ] )
				    + ( 4 * buffer[ buffer_offset + 12 ] )
				    + ( 3 * buffer[ buffer_offset + 13 ] )
				    + ( 2 * buffer[ buffer_offset + 14 ] )
				    + buffer[ buffer_offset + 15 ];

			lower_word += buffer[ buffer_offset ]
				    + buffer[ buffer_offset + 1 ]
				    + buffer[ buffer_offset + 2 ]
				    + buffer[ buffer_offset + 3 ]
				    + buffer[ buffer_offset + 4 ]
				    + buffer[ buffer_offset + 5 ]
				    + buffer[ buffer_offset + 6 ]
				    + buffer[ buffer_offset + 7 ]
				    + buffer[ buffer_offset + 8 ]
				    + buffer[ buffer_offset + 9 ]
				    + buffer[ buffer_offset + 10 ]
				    + buffer[ buffer_offset + 11 ]
				    + buffer[ buffer_offset + 12 ]
				    + buffer[ buffer_offset + 13 ]
				    + buffer[ buffer_offset + 14 ]
				    + buffer[ buffer_offset + 15 ];

			buffer_offset += 16;
		}
		lower_word %= 0xfff1;
		upper_word %= 0xfff1;

		size -= 0x15b0;
	}
	if( size > 0 )
	{
		while( size > 16 )
		{
			upper_word += ( 16 * lower_word )
				    + ( 16 * buffer[ buffer_offset ] )
				    + ( 15 * buffer[ buffer_offset + 1 ] )
				    + ( 14 * buffer[ buffer_offset + 2 ] )
				    + ( 13 * buffer[ buffer_offset + 3 ] )
				    + ( 12 * buffer[ buffer_offset + 4 ] )
				    + ( 11 * buffer[ buffer_offset + 5 ] )
				    + ( 10 * buffer[ buffer_offset + 6 ] )
				    + ( 9 * buffer[ buffer_offset + 7 ] )
				    + ( 8 * buffer[ buffer_offset + 8 ] )
				    + ( 7 * buffer[ buffer_offset + 9 ] )
				    + ( 6 * buffer[ buffer_offset + 10 ] )
				    + ( 5 * buffer[ buffer_offset + 11 ] )
				    + ( 4 * buffer[ buffer_offset + 12 ] )
				    + ( 3 * buffer[ buffer_offset + 13 ] )
				    + ( 2 * buffer[ buffer_offset + 14 ] )
				    + buffer[ buffer_offset + 15 ];

			lower_word += buffer[ buffer_offset ]
				    + buffer[ buffer_offset + 1 ]
				    + buffer[ buffer_offset + 2 ]
				    + buffer[ buffer_offset + 3 ]
				    + buffer[ buffer_offset + 4 ]
				    + buffer[ buffer_offset + 5 ]
				    + buffer[ buffer_offset + 6 ]
				    + buffer[ buffer_offset + 7 ]
				    + buffer[ buffer_offset + 8 ]
				    + buffer[ buffer_offset + 9 ]
				    + buffer[ buffer_offset + 10 ]
				    + buffer[ buffer_offset + 11 ]
				    + buffer[ buffer_offset + 12 ]
				    + buffer[ buffer_offset + 13 ]
				    + buffer[ buffer_offset + 14 ]
				    + buffer[ buffer_offset + 15 ];

			buffer_offset += 16;
			size          -= 16;
		}
		while( size > 0 )
		{
			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			size--;
		}
		lower_word %= 0xfff1;
		upper_word %= 0xfff1;
	}
	*checksum_value = ( upper_word << 16 ) | lower_word;

	return( 1 );
}

/* Calculates the Adler-32 of a buffer
 * Use a previous key of 0 to calculate a new Adler-32
 * Returns 1 if successful or -1 on error
 */
int checksum_calculate_adler32_unfolded16_2(
     uint32_t *checksum_value,
     uint8_t *buffer,
     size_t size,
     uint32_t initial_value,
     libcerror_error_t **error )
{
	static char *function = "checksum_calculate_adler32_unfolded16_2";
	size_t buffer_offset  = 0;
	uint32_t lower_word   = 0;
	uint32_t upper_word   = 0;
	int block_index       = 0;

	if( checksum_value == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid checksum value.",
		 function );

		return( -1 );
	}
	if( buffer == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid buffer.",
		 function );

		return( -1 );
	}
	if( size > (size_t) SSIZE_MAX )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_EXCEEDS_MAXIMUM,
		 "%s: invalid size value exceeds maximum.",
		 function );

		return( -1 );
	}
	lower_word = initial_value & 0xffff;
	upper_word = ( initial_value >> 16 ) & 0xffff;

	while( size >= 0x15b0 )
	{
		/* The modulo calculation is needed per 5552 (0x15b0) bytes
		 * 5552 / 16 = 347
		 */
		for( block_index = 0;
		     block_index < 347;
		     block_index++ )
		{
			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;
		}
		lower_word %= 0xfff1;
		upper_word %= 0xfff1;

		size -= 0x15b0;
	}
	if( size > 0 )
	{
		while( size > 16 )
		{
			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			size          -= 16;
		}
		while( size > 0 )
		{
			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			size--;
		}
		lower_word %= 0xfff1;
		upper_word %= 0xfff1;
	}
	*checksum_value = ( upper_word << 16 ) | lower_word;

	return( 1 );
}

/* Calculates the Adler-32 of a buffer
 * Use a previous key of 0 to calculate a new Adler-32
 * Returns 1 if successful or -1 on error
 */
int checksum_calculate_adler32_unfolded16_3(
     uint32_t *checksum_value,
     uint8_t *buffer,
     size_t size,
     uint32_t initial_value,
     libcerror_error_t **error )
{
	static char *function = "checksum_calculate_adler32_unfolded16_3";
	size_t buffer_offset  = 0;
	uint32_t lower_word   = 0;
	uint32_t upper_word   = 0;
	int block_index       = 0;

	if( checksum_value == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid checksum value.",
		 function );

		return( -1 );
	}
	if( buffer == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid buffer.",
		 function );

		return( -1 );
	}
	if( size > (size_t) SSIZE_MAX )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_EXCEEDS_MAXIMUM,
		 "%s: invalid size value exceeds maximum.",
		 function );

		return( -1 );
	}
	lower_word = initial_value & 0xffff;
	upper_word = ( initial_value >> 16 ) & 0xffff;

	while( size >= 0x15b0 )
	{
		/* The modulo calculation is needed per 5552 (0x15b0) bytes
		 */
		for( block_index = 0;
		     block_index < 0x15b0;
		     block_index++ )
		{
			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;
		}
		lower_word %= 0xfff1;
		upper_word %= 0xfff1;

		size -= 0x15b0;
	}
	if( size > 0 )
	{
		while( size > 16 )
		{
			for( block_index = 0;
			     block_index < 16;
			     block_index++ )
			{
				lower_word += buffer[ buffer_offset++ ];
				upper_word += lower_word;
			}
			size -= 16;
		}
		while( size > 0 )
		{
			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			size--;
		}
		lower_word %= 0xfff1;
		upper_word %= 0xfff1;
	}
	*checksum_value = ( upper_word << 16 ) | lower_word;

	return( 1 );
}

/* Calculates the Adler-32 of a buffer
 * Use a previous key of 0 to calculate a new Adler-32
 * Returns 1 if successful or -1 on error
 */
int checksum_calculate_adler32_unfolded16_4(
     uint32_t *checksum_value,
     uint8_t *buffer,
     size_t size,
     uint32_t initial_value,
     libcerror_error_t **error )
{
	static char *function = "checksum_calculate_adler32_unfolded16_4";
	size_t buffer_offset  = 0;
	uint32_t lower_word   = 0;
	uint32_t upper_word   = 0;
	uint32_t value_32bit  = 0;
	int block_index       = 0;

	if( checksum_value == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid checksum value.",
		 function );

		return( -1 );
	}
	if( buffer == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid buffer.",
		 function );

		return( -1 );
	}
	if( size > (size_t) SSIZE_MAX )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_EXCEEDS_MAXIMUM,
		 "%s: invalid size value exceeds maximum.",
		 function );

		return( -1 );
	}
	lower_word = initial_value & 0xffff;
	upper_word = ( initial_value >> 16 ) & 0xffff;

	while( size >= 0x15b0 )
	{
		/* The modulo calculation is needed per 5552 (0x15b0) bytes
		 * 5552 / 16 = 347
		 */
		for( block_index = 0;
		     block_index < 347;
		     block_index++ )
		{
			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;
		}
		/* Optimized equivalent of:
		 * lower_word %= 0xfff1
		 */
		value_32bit = lower_word >> 16;
		lower_word &= 0x0000ffffUL;
		lower_word += ( value_32bit << 4 ) - value_32bit;

		if( lower_word > 65521 )
		{
			value_32bit = lower_word >> 16;
			lower_word &= 0x0000ffffUL;
			lower_word += ( value_32bit << 4 ) - value_32bit;
		}
		if( lower_word >= 65521 )
		{
			lower_word -= 65521;
		}
		/* Optimized equivalent of:
		 * upper_word %= 0xfff1
		 */
		value_32bit = upper_word >> 16;
		upper_word &= 0x0000ffffUL;
		upper_word += ( value_32bit << 4 ) - value_32bit;

		if( upper_word > 65521 )
		{
			value_32bit = upper_word >> 16;
			upper_word &= 0x0000ffffUL;
			upper_word += ( value_32bit << 4 ) - value_32bit;
		}
		if( upper_word >= 65521 )
		{
			upper_word -= 65521;
		}
		size -= 0x15b0;
	}
	if( size > 0 )
	{
		while( size > 16 )
		{
			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			size -= 16;
		}
		while( size > 0 )
		{
			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			size--;
		}
		/* Optimized equivalent of:
		 * lower_word %= 0xfff1
		 */
		value_32bit = lower_word >> 16;
		lower_word &= 0x0000ffffUL;
		lower_word += ( value_32bit << 4 ) - value_32bit;

		if( lower_word > 65521 )
		{
			value_32bit = lower_word >> 16;
			lower_word &= 0x0000ffffUL;
			lower_word += ( value_32bit << 4 ) - value_32bit;
		}
		if( lower_word >= 65521 )
		{
			lower_word -= 65521;
		}
		/* Optimized equivalent of:
		 * upper_word %= 0xfff1
		 */
		value_32bit = upper_word >> 16;
		upper_word &= 0x0000ffffUL;
		upper_word += ( value_32bit << 4 ) - value_32bit;

		if( upper_word > 65521 )
		{
			value_32bit = upper_word >> 16;
			upper_word &= 0x0000ffffUL;
			upper_word += ( value_32bit << 4 ) - value_32bit;
		}
		if( upper_word >= 65521 )
		{
			upper_word -= 65521;
		}
	}
	*checksum_value = ( upper_word << 16 ) | lower_word;

	return( 1 );
}

/* Calculates the Adler-32 of a buffer
 * It uses the initial value to calculate a new Adler-32
 * Returns 1 if successful or -1 on error
 */
int checksum_calculate_adler32_cpu_aligned(
     uint32_t *checksum_value,
     const uint8_t *buffer,
     size_t size,
     uint32_t initial_value,
     libcerror_error_t **error )
{
	adler32_aligned_t *aligned_buffer_index = NULL;
	uint8_t *buffer_index                   = NULL;
	static char *function                   = "checksum_calculate_adler32_cpu_aligned";
	size_t buffer_offset                    = 0;
	uint32_t lower_word                     = 0;
	uint32_t upper_word                     = 0;
	uint32_t value_32bit                    = 0;
	uint8_t alignment_count                 = 0;
	uint8_t alignment_size                  = 0;
	uint8_t byte_count                      = 0;
	uint8_t byte_order                      = 0;
	int block_index                         = 0;
	int number_of_blocks                    = 0;

	if( checksum_value == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid checksum value.",
		 function );

		return( -1 );
	}
	if( buffer == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid buffer.",
		 function );

		return( -1 );
	}
	if( size > (size_t) SSIZE_MAX )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_EXCEEDS_MAXIMUM,
		 "%s: invalid size value exceeds maximum.",
		 function );

		return( -1 );
	}
	lower_word = initial_value & 0xffff;
	upper_word = ( initial_value >> 16 ) & 0xffff;

	buffer_index = (uint8_t *) buffer;

	while( size >= 0x15b0 )
	{
		/* The modulo calculation is needed per 5552 (0x15b0) bytes
		 * 5552 / 16 = 347
		 */
		number_of_blocks = 347;

		/* Align the buffer iterator
		 */
		alignment_size = (uint8_t) ( (intptr_t) buffer_index % sizeof( adler32_aligned_t ) );

		if( alignment_size > 0 )
		{
			byte_count = 0;

			while( byte_count < alignment_size )
			{
				lower_word += buffer[ buffer_offset++ ];
				upper_word += lower_word;

				byte_count++;
			}
			number_of_blocks--;
		}
		aligned_buffer_index = (adler32_aligned_t *) &( buffer[ buffer_offset ] );

		if( byte_order == 0 )
		{
			buffer_index = (uint8_t *) &( buffer[ buffer_offset ] );

			if( *buffer_index != (uint8_t) ( *aligned_buffer_index & 0xff ) )
			{
				byte_order = _BYTE_STREAM_ENDIAN_BIG;
			}
			else
			{
				byte_order = _BYTE_STREAM_ENDIAN_LITTLE;
			}
		}
		alignment_count   = 16 / sizeof( adler32_aligned_t );
		number_of_blocks *= alignment_count;

		for( block_index = 0;
		     block_index < number_of_blocks;
		     block_index++ )
		{
			alignment_count = sizeof( adler32_aligned_t );

			while( alignment_count > 0 )
			{
				lower_word += buffer[ buffer_offset++ ];
				upper_word += lower_word;

				alignment_count--;
			}
		}
		/* Re-align the buffer iterator
		 */
		buffer_index = (uint8_t *) &( buffer[ buffer_offset ] );

		if( alignment_size > 0 )
		{
			alignment_count = 16 - alignment_size;

			while( alignment_count > 0 )
			{
				lower_word += buffer[ buffer_offset++ ];
				upper_word += lower_word;

				alignment_count--;
			}
		}
		/* Optimized equivalent of:
		 * lower_word %= 0xfff1
		 */
		value_32bit = lower_word >> 16;
		lower_word &= 0x0000ffffUL;
		lower_word += ( value_32bit << 4 ) - value_32bit;

		if( lower_word > 65521 )
		{
			value_32bit = lower_word >> 16;
			lower_word &= 0x0000ffffUL;
			lower_word += ( value_32bit << 4 ) - value_32bit;
		}
		if( lower_word >= 65521 )
		{
			lower_word -= 65521;
		}
		/* Optimized equivalent of:
		 * upper_word %= 0xfff1
		 */
		value_32bit = upper_word >> 16;
		upper_word &= 0x0000ffffUL;
		upper_word += ( value_32bit << 4 ) - value_32bit;

		if( upper_word > 65521 )
		{
			value_32bit = upper_word >> 16;
			upper_word &= 0x0000ffffUL;
			upper_word += ( value_32bit << 4 ) - value_32bit;
		}
		if( upper_word >= 65521 )
		{
			upper_word -= 65521;
		}
		size -= 0x15b0;
	}
	if( size > 0 )
	{
		while( size > 16 )
		{
			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			size -= 16;
		}
		while( size > 0 )
		{
			lower_word += buffer[ buffer_offset ];
			upper_word += lower_word;

			buffer_offset++;
			size--;
		}
		/* Optimized equivalent of:
		 * lower_word %= 0xfff1
		 */
		value_32bit = lower_word >> 16;
		lower_word &= 0x0000ffffUL;
		lower_word += ( value_32bit << 4 ) - value_32bit;

		if( lower_word > 65521 )
		{
			value_32bit = lower_word >> 16;
			lower_word &= 0x0000ffffUL;
			lower_word += ( value_32bit << 4 ) - value_32bit;
		}
		if( lower_word >= 65521 )
		{
			lower_word -= 65521;
		}
		/* Optimized equivalent of:
		 * upper_word %= 0xfff1
		 */
		value_32bit = upper_word >> 16;
		upper_word &= 0x0000ffffUL;
		upper_word += ( value_32bit << 4 ) - value_32bit;

		if( upper_word > 65521 )
		{
			value_32bit = upper_word >> 16;
			upper_word &= 0x0000ffffUL;
			upper_word += ( value_32bit << 4 ) - value_32bit;
		}
		if( upper_word >= 65521 )
		{
			upper_word -= 65521;
		}
	}
	*checksum_value = ( upper_word << 16 ) | lower_word;

	return( 1 );
}

/* Calculates the Adler-32 of a buffer
 * It uses the initial value to calculate a new Adler-32
 * Returns 1 if successful or -1 on error
 */
int checksum_calculate_adler32_simd(
     uint32_t *checksum_value,
     const uint8_t *buffer,
     size_t size,
     uint32_t initial_value,
     libcerror_error_t **error )
{
	adler32_8byte_vector_t value_8byte;
	adler32_8byte_vector_t upper_word_8byte_multiplier;
	adler32_8byte_vector_t upper_word_8byte_value;

	static char *function = "checksum_calculate_adler32_simd";
	size_t buffer_offset  = 0;
	uint32_t lower_word   = 0;
	uint32_t upper_word   = 0;
	int block_index       = 0;
	int number_of_blocks  = 0;

	if( checksum_value == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid checksum value.",
		 function );

		return( -1 );
	}
	if( buffer == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid buffer.",
		 function );

		return( -1 );
	}
	if( size > (size_t) SSIZE_MAX )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_EXCEEDS_MAXIMUM,
		 "%s: invalid size value exceeds maximum.",
		 function );

		return( -1 );
	}
	lower_word = initial_value & 0xffff;
	upper_word = ( initial_value >> 16 ) & 0xffff;

	upper_word_8byte_multiplier.integer[ 0 ] = 8;
	upper_word_8byte_multiplier.integer[ 1 ] = 7;
	upper_word_8byte_multiplier.integer[ 2 ] = 6;
	upper_word_8byte_multiplier.integer[ 3 ] = 5;
	upper_word_8byte_multiplier.integer[ 4 ] = 4;
	upper_word_8byte_multiplier.integer[ 5 ] = 3;
	upper_word_8byte_multiplier.integer[ 6 ] = 2;
	upper_word_8byte_multiplier.integer[ 7 ] = 1;

	upper_word_8byte_value.integer[ 0 ] = 0;
	upper_word_8byte_value.integer[ 1 ] = 0;
	upper_word_8byte_value.integer[ 2 ] = 0;
	upper_word_8byte_value.integer[ 3 ] = 0;
	upper_word_8byte_value.integer[ 4 ] = 0;
	upper_word_8byte_value.integer[ 5 ] = 0;
	upper_word_8byte_value.integer[ 6 ] = 0;
	upper_word_8byte_value.integer[ 7 ] = 0;

	while( size >= 0x15b0 )
	{
		/* The modulo calculation is needed per 5552 (0x15b0) bytes
		 * 5552 / 16 = 347
		 */
		number_of_blocks = 347 * 2;

		for( block_index = 0;
		     block_index < number_of_blocks;
		     block_index++ )
		{
			value_8byte.integer[ 0 ] = buffer[ buffer_offset++ ];
			value_8byte.integer[ 1 ] = buffer[ buffer_offset++ ];
			value_8byte.integer[ 2 ] = buffer[ buffer_offset++ ];
			value_8byte.integer[ 3 ] = buffer[ buffer_offset++ ];
			value_8byte.integer[ 4 ] = buffer[ buffer_offset++ ];
			value_8byte.integer[ 5 ] = buffer[ buffer_offset++ ];
			value_8byte.integer[ 6 ] = buffer[ buffer_offset++ ];
			value_8byte.integer[ 7 ] = buffer[ buffer_offset++ ];

/* TODO
			upper_word_8byte_value.vector = __builtin_mulv8qi(
			                                 value_8byte.vector,
			                                 upper_word_8byte_multiplier.vector );
*/

			upper_word += 8 * lower_word
			            + upper_word_8byte_value.integer[ 0 ]
			            + upper_word_8byte_value.integer[ 1 ]
			            + upper_word_8byte_value.integer[ 2 ]
			            + upper_word_8byte_value.integer[ 3 ]
			            + upper_word_8byte_value.integer[ 4 ]
			            + upper_word_8byte_value.integer[ 5 ]
			            + upper_word_8byte_value.integer[ 6 ]
			            + upper_word_8byte_value.integer[ 7 ];

			lower_word += value_8byte.integer[ 0 ]
			            + value_8byte.integer[ 1 ]
			            + value_8byte.integer[ 2 ]
			            + value_8byte.integer[ 3 ]
			            + value_8byte.integer[ 4 ]
			            + value_8byte.integer[ 5 ]
			            + value_8byte.integer[ 6 ]
			            + value_8byte.integer[ 7 ];

		}
		lower_word %= 0xfff1;
		upper_word %= 0xfff1;

		size -= 0x15b0;
	}
	if( size > 0 )
	{
		while( size > 16 )
		{
			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			size          -= 16;
		}
		while( size > 0 )
		{
			lower_word += buffer[ buffer_offset++ ];
			upper_word += lower_word;

			size--;
		}
		lower_word %= 0xfff1;
		upper_word %= 0xfff1;
	}
	*checksum_value = ( upper_word << 16 ) | lower_word;

	return( 1 );
}

