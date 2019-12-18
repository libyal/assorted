/*
 * Decompression handle
 *
 * Copyright (C) 2008-2019, Joachim Metz <joachim.metz@gmail.com>
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
#include <file_stream.h>
#include <memory.h>
#include <narrow_string.h>
#include <system_string.h>
#include <types.h>
#include <wide_string.h>

#include "assorted_libcerror.h"
#include "assorted_libcfile.h"
#include "assorted_libcnotify.h"
#include "decompression_handle.h"

#define DECOMPRESSION_HANDLE_NOTIFY_STREAM	stdout

/* Copies a string of a decimal value to a 64-bit value
 * Returns 1 if successful or -1 on error
 */
int assorted_system_string_copy_from_64_bit_in_decimal(
     const system_character_t *string,
     size_t string_size,
     uint64_t *value_64bit,
     libcerror_error_t **error )
{
	static char *function              = "assorted_system_string_copy_from_64_bit_in_decimal";
	size_t string_index                = 0;
	system_character_t character_value = 0;
	uint8_t maximum_string_index       = 20;
	int8_t sign                        = 1;

	if( string == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid string.",
		 function );

		return( -1 );
	}
	if( string_size > (size_t) SSIZE_MAX )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_EXCEEDS_MAXIMUM,
		 "%s: invalid string size value exceeds maximum.",
		 function );

		return( -1 );
	}
	if( value_64bit == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid value 64-bit.",
		 function );

		return( -1 );
	}
	*value_64bit = 0;

	if( string[ string_index ] == (system_character_t) '-' )
	{
		string_index++;
		maximum_string_index++;

		sign = -1;
	}
	else if( string[ string_index ] == (system_character_t) '+' )
	{
		string_index++;
		maximum_string_index++;
	}
	while( string_index < string_size )
	{
		if( string[ string_index ] == 0 )
		{
			break;
		}
		if( string_index > (size_t) maximum_string_index )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
			 LIBCERROR_ARGUMENT_ERROR_VALUE_TOO_LARGE,
			 "%s: string too large.",
			 function );

			return( -1 );
		}
		*value_64bit *= 10;

		if( ( string[ string_index ] >= (system_character_t) '0' )
		 && ( string[ string_index ] <= (system_character_t) '9' ) )
		{
			character_value = (system_character_t) ( string[ string_index ] - (system_character_t) '0' );
		}
		else
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_UNSUPPORTED_VALUE,
			 "%s: unsupported character value: %" PRIc_SYSTEM " at index: %d.",
			 function,
			 string[ string_index ],
			 string_index );

			return( -1 );
		}
		*value_64bit += character_value;

		string_index++;
	}
	if( sign == -1 )
	{
		*value_64bit *= (uint64_t) -1;
	}
	return( 1 );
}

/* Creates an decompression handle
 * Make sure the value decompression_handle is referencing, is set to NULL
 * Returns 1 if successful or -1 on error
 */
int decompression_handle_initialize(
     decompression_handle_t **decompression_handle,
     libcerror_error_t **error )
{
	static char *function = "decompression_handle_initialize";

	if( decompression_handle == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid decompression handle.",
		 function );

		return( -1 );
	}
	if( *decompression_handle != NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_ALREADY_SET,
		 "%s: invalid decompression handle value already set.",
		 function );

		return( -1 );
	}
	*decompression_handle = memory_allocate_structure(
	                         decompression_handle_t );

	if( *decompression_handle == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
		 "%s: unable to create decompression handle.",
		 function );

		goto on_error;
	}
	if( memory_set(
	     *decompression_handle,
	     0,
	     sizeof( decompression_handle_t ) ) == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_SET_FAILED,
		 "%s: unable to clear decompression handle.",
		 function );

		memory_free(
		 *decompression_handle );

		*decompression_handle = NULL;

		return( -1 );
	}
	if( libcfile_file_initialize(
	     &( ( *decompression_handle )->input_file ),
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
		 "%s: unable to create input file.",
		 function );

		goto on_error;
	}
	( *decompression_handle )->notify_stream = DECOMPRESSION_HANDLE_NOTIFY_STREAM;

	return( 1 );

on_error:
	if( *decompression_handle != NULL )
	{
		memory_free(
		 *decompression_handle );

		*decompression_handle = NULL;
	}
	return( -1 );
}

/* Frees an decompression handle
 * Returns 1 if successful or -1 on error
 */
int decompression_handle_free(
     decompression_handle_t **decompression_handle,
     libcerror_error_t **error )
{
	static char *function = "decompression_handle_free";
	int result            = 1;

	if( decompression_handle == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid decompression handle.",
		 function );

		return( -1 );
	}
	if( *decompression_handle != NULL )
	{
		if( libcfile_file_free(
		     &( ( *decompression_handle )->input_file ),
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_FINALIZE_FAILED,
			 "%s: unable to free input file.",
			 function );

			result = -1;
		}
		memory_free(
		 *decompression_handle );

		*decompression_handle = NULL;
	}
	return( result );
}

/* Signals the decompression handle to abort
 * Returns 1 if successful or -1 on error
 */
int decompression_handle_signal_abort(
     decompression_handle_t *decompression_handle,
     libcerror_error_t **error )
{
	static char *function = "decompression_handle_signal_abort";

	if( decompression_handle == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid decompression handle.",
		 function );

		return( -1 );
	}
	decompression_handle->abort = 1;

	return( 1 );
}

/* Sets the input offset
 * Returns 1 if successful or -1 on error
 */
int decompression_handle_set_input_offset(
     decompression_handle_t *decompression_handle,
     const system_character_t *string,
     libcerror_error_t **error )
{
	static char *function = "decompression_handle_set_input_offset";
	size_t string_length  = 0;
	uint64_t value_64bit  = 0;

	if( decompression_handle == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid decompression handle.",
		 function );

		return( -1 );
	}
	string_length = system_string_length(
	                 string );

	if( assorted_system_string_copy_from_64_bit_in_decimal(
	     string,
	     string_length + 1,
	     &value_64bit,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_COPY_FAILED,
		 "%s: unable to copy string to 64-bit decimal.",
		 function );

		return( -1 );
	}
	decompression_handle->input_offset = (off64_t) value_64bit;

	return( 1 );
}

/* Sets the input size
 * Returns 1 if successful or -1 on error
 */
int decompression_handle_set_input_size(
     decompression_handle_t *decompression_handle,
     const system_character_t *string,
     libcerror_error_t **error )
{
	static char *function = "decompression_handle_set_input_size";
	size_t string_length  = 0;
	uint64_t value_64bit  = 0;

	if( decompression_handle == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid decompression handle.",
		 function );

		return( -1 );
	}
	string_length = system_string_length(
	                 string );

	if( assorted_system_string_copy_from_64_bit_in_decimal(
	     string,
	     string_length + 1,
	     &value_64bit,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_COPY_FAILED,
		 "%s: unable to copy string to 64-bit decimal.",
		 function );

		return( -1 );
	}
	decompression_handle->input_size = (size64_t) value_64bit;

	return( 1 );
}

/* Opens the input
 * Returns 1 if successful or -1 on error
 */
int decompression_handle_open_input(
     decompression_handle_t *decompression_handle,
     const system_character_t *filename,
     libcerror_error_t **error )
{
	static char *function = "decompression_handle_open_input";
	int result            = 0;

	if( decompression_handle == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid decompression handle.",
		 function );

		return( -1 );
	}
#if defined( HAVE_WIDE_SYSTEM_CHARACTER )
	result = libcfile_file_open_wide(
	          decompression_handle->input_file,
	          filename,
	          LIBCFILE_OPEN_READ,
	          error );
#else
	result = libcfile_file_open(
	          decompression_handle->input_file,
	          filename,
	          LIBCFILE_OPEN_READ,
	          error );
#endif
 	if( result != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_IO,
		 LIBCERROR_IO_ERROR_OPEN_FAILED,
		 "%s: unable to open input file.",
		 function );

		return( -1 );
	}
	if( decompression_handle->input_size == 0 )
	{
		if( libcfile_file_get_size(
		     decompression_handle->input_file,
		     &( decompression_handle->input_size ),
		     error ) == -1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
			 "%s: unable to retrieve size of input file.",
			 function );

			return( -1 );
		}
		if( (size64_t) decompression_handle->input_offset >= decompression_handle->input_size )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_VALUE_OUT_OF_BOUNDS,
			 "%s: invalid input offset value out of bounds.",
			 function );

			return( -1 );
		}
		decompression_handle->input_size -= decompression_handle->input_offset;
	}
	return( 1 );
}

/* Closes the input
 * Returns the 0 if succesful or -1 on error
 */
int decompression_handle_close_input(
     decompression_handle_t *decompression_handle,
     libcerror_error_t **error )
{
	static char *function = "decompression_handle_close_input";

	if( decompression_handle == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid info handle.",
		 function );

		return( -1 );
	}
	if( libcfile_file_close(
	     decompression_handle->input_file,
	     error ) != 0 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_IO,
		 LIBCERROR_IO_ERROR_CLOSE_FAILED,
		 "%s: unable to close input file.",
		 function );

		return( -1 );
	}
	return( 0 );
}

/* Reads compressed data
 * Returns 1 if successful or -1 on error
 */
int decompression_handle_read_data(
     decompression_handle_t *decompression_handle,
     uint8_t *compressed_data,
     size_t compressed_data_size,
     libcerror_error_t **error )
{
	static char *function = "decompression_handle_read_data";
	ssize_t read_count    = 0;

	if( decompression_handle == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid info handle.",
		 function );

		return( -1 );
	}
	if( libcfile_file_seek_offset(
	     decompression_handle->input_file,
	     decompression_handle->input_offset,
	     SEEK_SET,
	     error ) == -1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_IO,
		 LIBCERROR_IO_ERROR_SEEK_FAILED,
		 "%s: unable to seek in input file.",
		 function );

		return( -1 );
	}
	read_count = libcfile_file_read_buffer(
	              decompression_handle->input_file,
		      compressed_data,
		      compressed_data_size,
	              error );

	if( read_count != (ssize_t) compressed_data_size )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_IO,
		 LIBCERROR_IO_ERROR_READ_FAILED,
		 "%s: unable to read from input file.",
		 function );

		return( -1 );
	}
	return( 1 );
}

/* Writes uncompressed data
 * Returns 1 if successful or -1 on error
 */
int decompression_handle_write_data(
     decompression_handle_t *decompression_handle,
     const system_character_t *output_filename,
     const uint8_t *uncompressed_data,
     size_t uncompressed_data_size,
     libcerror_error_t **error )
{
	libcfile_file_t *output_file = NULL;
	static char *function        = "decompression_handle_write_data";
	ssize_t write_count          = 0;
	int result                   = 0;

	if( decompression_handle == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid info handle.",
		 function );

		return( -1 );
	}
	if( output_filename == NULL )
	{
		fprintf(
		 decompression_handle->notify_stream,
		 "Uncompressed data:\n" );

		libcnotify_print_data(
		 uncompressed_data,
		 uncompressed_data_size,
		 LIBCNOTIFY_PRINT_DATA_FLAG_GROUP_DATA );

		return( 1 );
	}
	if( libcfile_file_initialize(
	     &output_file,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
		 "%s: unable to create output file.",
		 function );

		goto on_error;
	}
#if defined( HAVE_WIDE_SYSTEM_CHARACTER )
	result = libcfile_file_open_wide(
	          output_file,
	          output_filename,
	          LIBCFILE_OPEN_WRITE,
	          error );
#else
	result = libcfile_file_open(
	          output_file,
	          output_filename,
	          LIBCFILE_OPEN_WRITE,
	          error );
#endif
 	if( result != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_IO,
		 LIBCERROR_IO_ERROR_OPEN_FAILED,
		 "%s: unable to open output file.",
		 function );

		goto on_error;
	}
	write_count = libcfile_file_write_buffer(
		       output_file,
		       uncompressed_data,
		       uncompressed_data_size,
		       error );

	if( write_count != (ssize_t) uncompressed_data_size )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_IO,
		 LIBCERROR_IO_ERROR_WRITE_FAILED,
		 "%s: unable to write to output file.",
		 function );

		goto on_error;
	}
	if( libcfile_file_close(
	     output_file,
	     error ) != 0 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_IO,
		 LIBCERROR_IO_ERROR_CLOSE_FAILED,
		 "%s: unable to close output file.",
		 function );

		goto on_error;
	}
	if( libcfile_file_free(
	     &output_file,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_FINALIZE_FAILED,
		 "%s: unable to free output file.",
		 function );

		goto on_error;
	}
	return( 1 );

on_error:
	if( output_file != NULL )
	{
		libcfile_file_free(
		 &output_file,
		 NULL );
	}
	return( -1 );
}

