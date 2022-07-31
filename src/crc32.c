/*
 * CRC-32 functions
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
#include <types.h>

#include "assorted_libcerror.h"
#include "crc32.h"

/* Polynomials
 *
 * RFC 1952
 * normal:                0x04c11db7
 * reversed:              0xedb88320
 * reverse of reciprocal: 0x82608edb
 *
 * Castagnoli
 * normal:                0x1edc6f41
 * reversed:              0x82f63b78
 * reverse of reciprocal: 0x8f6e37a0
 *
 * Koopmans
 * normal:                0x741b8cd7
 * reversed:              0xeb31d82e
 * reverse of reciprocal: 0xba0dc66b
 */

/* Table of the CRC-32 of all 8-bit messages.
 */
uint32_t crc32_table[ 256 ];

/* Value to indicate the CRC-32 table been computed
 */
int crc32_table_computed = 0;

/* Initializes the internal CRC-32 table
 * The table speeds up the CRC-32 calculation
 * Use the reversed polynomial
 */
void initialize_crc32_table(
      uint32_t polynomial )
{
	uint32_t crc32             = 0;
	uint16_t crc32_table_index = 0;
	uint8_t bit_iterator       = 0;

	for( crc32_table_index = 0;
	     crc32_table_index < 256;
	     crc32_table_index++ )
	{
		crc32 = (uint32_t) crc32_table_index;

		for( bit_iterator = 0;
		     bit_iterator < 8;
		     bit_iterator++ )
		{
			if( crc32 & 1 )
			{
				crc32 = polynomial ^ ( crc32 >> 1 );
			}
			else
			{
				crc32 = crc32 >> 1;
			}
		}
		crc32_table[ crc32_table_index ] = crc32;
	}
	crc32_table_computed = 1;
}

/* Calculates the CRC-32 of a buffer
 * Uses modulo 2 caluculations, instead of a lookup table
 * The polynomial used is: 0x04c11db7UL
 *
 * Use a previous key of 0 to calculate a new CRC-32
 *
 * Returns 1 if successful or -1 on error
 */
int crc32_calculate_modulo2(
     uint32_t *crc32,
     const uint8_t *buffer,
     size_t size,
     uint32_t initial_value,
     uint8_t weak_crc,
     libcerror_error_t **error )
{
	static char *function = "crc32_calculate_modulo2";
	size_t buffer_offset  = 0;
	uint32_t mirror_value = 0;
	uint32_t safe_crc32   = 0;
	uint8_t bit_index     = 0;
	uint8_t byte_value    = 0;

	if( crc32 == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid CRC-32.",
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
	safe_crc32 = initial_value;

	if( weak_crc == 0 )
	{
		safe_crc32 ^= (uint32_t) 0xffffffffUL;
	}
	/* Perform a byte for byte modulo-2 division
	 */
        for( buffer_offset = 0;
	     buffer_offset < size;
	     buffer_offset++ )
	{
		byte_value   = buffer[ buffer_offset ];
		mirror_value = 0;

		/* Mirror the bit order of the byte value from the center
		 */
		for( bit_index = 0;
		     bit_index < 8;
		     bit_index++ )
		{
			if( ( byte_value & 0x01 ) != 0 )
			{
				mirror_value |= ( 1 << ( 7 - bit_index ) );
			}
			byte_value = byte_value >> 1;
		}
		safe_crc32 ^= mirror_value << 24;

		/* Perform a bit for bit modulo-2 division
		*/
		for( bit_index = 0;
		     bit_index < 8;
		     bit_index++ )
		{
			if( ( safe_crc32 & 0x80000000UL ) != 0 )
			{
				safe_crc32 <<= 1;
				safe_crc32  ^= 0x04c11db7UL;
			}
			else
			{
				safe_crc32 <<= 1;
			}
		}
	}
	/* Mirror the bit order of the CRC-32 value from the center
	 */
	for( bit_index = 0;
	     bit_index < 32;
	     bit_index++ )
	{
		if( ( safe_crc32 & 0x00000001UL ) != 0 )
		{
			mirror_value |= ( 1 << ( 31 - bit_index ) );
		}
		safe_crc32 = safe_crc32 >> 1;
	}
	safe_crc32 = mirror_value;

	if( weak_crc == 0 )
	{
		safe_crc32 ^= (uint32_t) 0xffffffffUL;
	}
	*crc32 = safe_crc32;

	return( 1 );
}

/* Calculates the CRC-32 of a buffer
 * Use a previous key of 0 to calculate a new CRC-32
 * Returns 1 if successful or -1 on error
 */
int crc32_calculate(
     uint32_t *crc32,
     const uint8_t *buffer,
     size_t size,
     uint32_t initial_value,
     uint8_t weak_crc,
     libcerror_error_t **error )
{
	static char *function      = "crc32_calculate";
	size_t buffer_offset       = 0;
	uint32_t crc32_table_index = 0;
	uint32_t safe_crc32        = 0;

	if( crc32 == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid CRC-32.",
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
        if( crc32_table_computed == 0 )
	{
		initialize_crc32_table(
		 0xedb88320UL );
	}
	safe_crc32 = initial_value;

	if( weak_crc == 0 )
	{
		safe_crc32 ^= (uint32_t) 0xffffffffUL;
	}
        for( buffer_offset = 0;
	     buffer_offset < size;
	     buffer_offset++ )
	{
		crc32_table_index = ( safe_crc32 ^ buffer[ buffer_offset ] ) & 0x000000ffUL;

		safe_crc32 = crc32_table[ crc32_table_index ] ^ ( safe_crc32 >> 8 );
        }
	if( weak_crc == 0 )
	{
		safe_crc32 ^= 0xffffffffUL;
	}
	*crc32 = safe_crc32;

	return( 1 );
}

/* Check the CRC-32 checksum for single-bit errors
 * Returns 1 if successful, 0 if no error was found or -1 on error
 */
int crc32_validate(
     uint32_t crc32,
     uint32_t calculated_crc32,
     uint8_t *bit_index,
     libcerror_error_t **error )
{
	static char *function      = "crc32_validate";
	uint32_t crc32_xor_pattern = 0;
	uint8_t safe_bit_index     = 0;
	
	if( bit_index == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid bit index.",
		 function );

		return( -1 );
	}
	crc32 ^= calculated_crc32;

	crc32_xor_pattern = 1;

        for( safe_bit_index = 0;
	     safe_bit_index < 32;
	     safe_bit_index += 1 )
	{
		if( crc32_xor_pattern == crc32 )
		{
			*bit_index = safe_bit_index;

			return( 1 );
		}
		crc32_xor_pattern = ( crc32_xor_pattern << 1 ) ^ ( 0x04c11db7UL & ( crc32_xor_pattern >> 31 ) );
	}
	return( 0 );
}

/* Tries to locate the error offset using a CRC-32
 * Returns 1 if successful, 0 if no error was found or -1 on error
 */
int crc32_locate_error_offset(
     uint32_t crc32,
     uint32_t calculated_crc32,
     const uint8_t *buffer,
     size_t size,
     uint32_t initial_value,
     libcerror_error_t **error )
{
	static char *function      = "crc32_locate_error_offset";
	size_t buffer_offset       = 0;
	uint32_t crc32_xor_pattern = 0;
	uint32_t mirror_value      = 0;
	uint8_t bit_index          = 0;
	uint8_t byte_value         = 0;

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
	crc32_xor_pattern = crc32 ^ calculated_crc32;

	calculated_crc32 = initial_value ^ (uint32_t) 0xffffffffUL;

	/* Perform a byte for byte modulo-2 division
	 */
        for( buffer_offset = 0;
	     buffer_offset < size;
	     buffer_offset++ )
	{
		byte_value   = buffer[ buffer_offset ];
		mirror_value = 0;

		/* Mirror the bit order of the byte value from the center
		 */
		for( bit_index = 0;
		     bit_index < 8;
		     bit_index++ )
		{
			if( ( byte_value & 0x01 ) != 0 )
			{
				mirror_value |= ( 1 << ( 7 - bit_index ) );
			}
			byte_value = byte_value >> 1;
		}
		calculated_crc32 ^= mirror_value << 24;

		/* Perform a bit for bit modulo-2 division
		*/
		for( bit_index = 0;
		     bit_index < 8;
		     bit_index++ )
		{
			if( ( calculated_crc32 & 0x80000000UL ) != 0 )
			{
				calculated_crc32 <<= 1;
				calculated_crc32  ^= 0x04c11db7UL;

				crc32_xor_pattern <<= 1;
				crc32_xor_pattern  ^= 0x04c11db7UL;
			}
			else
			{
				calculated_crc32 <<= 1;

				crc32_xor_pattern <<= 1;
			}
			crc32_xor_pattern <<= 1;
		}
	}
	/* Mirror the bit order of the CRC-32 value from the center
	 */
	for( bit_index = 0;
	     bit_index < 32;
	     bit_index++ )
	{
		if( ( calculated_crc32 & 0x00000001UL ) != 0 )
		{
			mirror_value |= ( 1 << ( 31 - bit_index ) );
		}
		calculated_crc32 = calculated_crc32 >> 1;
	}
	calculated_crc32 = mirror_value ^ (uint32_t) 0xffffffffUL;

	return( 0 );
}

