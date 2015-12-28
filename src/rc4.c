/*
 * RC4 (de/en)crypt functions
 *
 * Copyright (c) 2008-2015, Joachim Metz <joachim.metz@gmail.com>
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
#include <memory.h>
#include <types.h>

#include "assorted_libcerror.h"
#include "rc4.h"

/* Creates a context
 * Make sure the value context is referencing, is set to NULL
 * Returns 1 if successful or -1 on error
 */
int rc4_context_initialize(
     rc4_context_t **context,
     libcerror_error_t **error )
{
	static char *function = "rc4_context_initialize";

	if( context == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid context.",
		 function );

		return( -1 );
	}
	if( *context != NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_ALREADY_SET,
		 "%s: invalid context value already set.",
		 function );

		return( -1 );
	}
	*context = memory_allocate_structure(
	            rc4_context_t );

	if( *context == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
		 "%s: unable to create context.",
		 function );

		goto on_error;
	}
	if( memory_set(
	     *context,
	     0,
	     sizeof( rc4_context_t ) ) == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_SET_FAILED,
		 "%s: unable to clear context.",
		 function );

		goto on_error;
	}
	return( 1 );

on_error:
	if( *context != NULL )
	{
		memory_free(
		 *context );

		*context = NULL;
	}
	return( -1 );
}

/* Frees a context
 * Returns 1 if successful or -1 on error
 */
int rc4_context_free(
     rc4_context_t **context,
     libcerror_error_t **error )
{
	static char *function = "rc4_context_free";
	int result            = 1;

	if( context == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid context.",
		 function );

		return( -1 );
	}
	if( *context != NULL )
	{
		if( memory_set(
		     *context,
		     0,
		     sizeof( rc4_context_t ) ) == NULL )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_MEMORY,
			 LIBCERROR_MEMORY_ERROR_SET_FAILED,
			 "%s: unable to clear context.",
			 function );

			result = -1;
		}
		memory_free(
		 *context );

		*context = NULL;
	}
	return( result );
}

/* Sets the key
 * Returns 1 if successful or -1 on error
 */
int rc4_context_set_key(
     rc4_context_t *context,
     const uint8_t *key,
     size_t key_bit_size,
     libcerror_error_t **error )
{
	static char *function     = "rc4_context_set_key";
	size_t key_byte_index     = 0;
	size_t key_byte_size      = 0;
	uint16_t byte_value       = 0;
	uint8_t permutation_value = 0;
	uint8_t values_index      = 0;

	if( context == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid context.",
		 function );

		return( -1 );
	}
	if( key == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid key.",
		 function );

		return( -1 );
	}
	if( ( key_bit_size == 0 )
	 || ( ( key_bit_size % 8 ) != 0 ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
		 "%s: unsupported key bit size.",
		 function );

		return( -1 );
	}
	key_byte_size = key_bit_size / 8;

	/* Also referred to as: Key Scheduling Algorithm (KSA)
	 */
	for( byte_value = 0;
	     byte_value < 256;
	     byte_value++ )
	{
		context->permutations[ byte_value ] = (uint8_t) byte_value;
	}
	for( byte_value = 0;
	     byte_value < 256;
	     byte_value++ )
	{
		key_byte_index = byte_value % key_byte_size;

		/* Note that the following operations are implicitly modulus 256
		 */
		values_index += context->permutations[ byte_value ];
		values_index += key[ key_byte_index ];

		permutation_value = context->permutations[ byte_value ];
		context->permutations[ byte_value ] = context->permutations[ values_index ];
		context->permutations[ values_index ] = permutation_value;
	}
	context->index[ 0 ] = 0;
	context->index[ 1 ] = 0;

	return( 1 );
}

/* De- or encrypts a buffer of data using RC4
 * Returns 1 if successful or -1 on error
 */
int rc4_crypt(
     rc4_context_t *context,
     const uint8_t *input_data,
     size_t input_data_size,
     uint8_t *output_data,
     size_t output_data_size,
     libcerror_error_t **error )
{
	static char *function     = "rc4_crypt";
	size_t data_offset        = 0;
	uint8_t permutation_value = 0;
	uint8_t values_index1     = 0;
	uint8_t values_index2     = 0;

	if( context == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid context.",
		 function );

		return( -1 );
	}
	if( input_data == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid input data.",
		 function );

		return( -1 );
	}
	if( input_data_size > (size_t) SSIZE_MAX )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_EXCEEDS_MAXIMUM,
		 "%s: invalid input data size value exceeds maximum.",
		 function );

		return( -1 );
	}
	if( output_data == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid output data.",
		 function );

		return( -1 );
	}
	if( output_data_size > (size_t) SSIZE_MAX )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_EXCEEDS_MAXIMUM,
		 "%s: invalid output data size value exceeds maximum.",
		 function );

		return( -1 );
	}
	if( output_data_size < input_data_size )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_OUT_OF_BOUNDS,
		 "%s: invalid ouput data size smaller than input data size.",
		 function );

		return( -1 );
	}
	/* Also referred to as: Pseudo-Random Generator Algorithm (PRGA)
	 */
	values_index1 = context->index[ 0 ];
	values_index2 = context->index[ 1 ];

	while( data_offset < input_data_size )
	{
		/* Note that the following operations are implicitly modulus 256
		 */
		values_index1 += 1;
		values_index2 += context->permutations[ values_index1 ];

		permutation_value = context->permutations[ values_index1 ];
		context->permutations[ values_index1 ] = context->permutations[ values_index2 ];
		context->permutations[ values_index2 ] = permutation_value;

		permutation_value += context->permutations[ values_index1 ];

		output_data[ data_offset ] = input_data[ data_offset ] ^ context->permutations[ permutation_value ];

		data_offset++;
	}
	context->index[ 0 ] = values_index1;
	context->index[ 1 ] = values_index2;

	return( 1 );
}

