/*
 * De- or encrypts data using Serpent
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
#include <file_stream.h>
#include <memory.h>
#include <narrow_string.h>
#include <system_string.h>
#include <types.h>
#include <wide_string.h>

#if defined( HAVE_STDLIB_H )
#include <stdlib.h>
#endif

#include "assorted_getopt.h"
#include "assorted_libcerror.h"
#include "assorted_libcfile.h"
#include "assorted_libcnotify.h"
#include "assorted_libfcrypto.h"
#include "assorted_libuna.h"
#include "assorted_output.h"

/* Sets the keys
 * Returns 1 if successful or -1 on error
 */
int serpentcrypt_set_keys(
     const system_character_t *string,
     uint8_t **key_data,
     size_t *key_data_size,
     libcerror_error_t **error )
{
	static char *function   = "serpentcrypt_set_keys";
	size_t string_length    = 0;
	uint32_t base16_variant = 0;

	string_length = system_string_length(
	                 string );

	*key_data_size = string_length / 2;

	*key_data = (uint8_t *) memory_allocate(
	                         sizeof( uint8_t ) * *key_data_size );

	if( *key_data == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
		 "%s: unable to create key data.",
		 function );

		goto on_error;
	}
	if( memory_set(
	     *key_data,
	     0,
	     *key_data_size ) == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_SET_FAILED,
		 "%s: unable to clear key data.",
		 function );

		goto on_error;
	}
	base16_variant = LIBUNA_BASE16_VARIANT_RFC4648;

#if defined( HAVE_WIDE_SYSTEM_CHARACTER )
	if( _BYTE_STREAM_HOST_IS_ENDIAN_BIG )
	{
		base16_variant |= LIBUNA_BASE16_VARIANT_ENCODING_UTF16_BIG_ENDIAN;
	}
	else
	{
		base16_variant |= LIBUNA_BASE16_VARIANT_ENCODING_UTF16_LITTLE_ENDIAN;
	}
#endif
	if( libuna_base16_stream_copy_to_byte_stream(
	     (uint8_t *) string,
	     string_length,
	     *key_data,
	     *key_data_size,
	     base16_variant,
	     0,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_COPY_FAILED,
		 "%s: unable to copy key data.",
		 function );

		goto on_error;
	}
	return( 1 );

on_error:
	if( *key_data != NULL )
	{
		memory_set(
		 *key_data,
		 0,
		 *key_data_size );

		memory_free(
		 *key_data );

		*key_data      = NULL;
		*key_data_size = 0;
	}
	return( -1 );
}

/* Prints the executable usage information
 */
void usage_fprint(
      FILE *stream )
{
	if( stream == NULL )
	{
		return;
	}
	fprintf( stream, "Use serpentcrypt to de- or encrypt data using Serpent.\n\n" );

	fprintf( stream, "Usage: serpentcrypt [ -k key ] [ -o offset ] [ -s size ]\n"
	                 "                    [ -t target ] [ -hvV ] source\n\n" );

	fprintf( stream, "\tsource: the source file\n\n" );

	fprintf( stream, "\t-h:     shows this help\n" );
	fprintf( stream, "\t-k:     the key formatted in base16\n" );
	fprintf( stream, "\t-o:     data offset (default is 0)\n" );
	fprintf( stream, "\t-s:     size of data (default is the file size)\n" );
	fprintf( stream, "\t-t:     specify the target file to write the output data,\n"
	                 "\t        by default the data will be written to stdout in\n"
	                 "\t        hexadecimal representation\n" );
	fprintf( stream, "\t-v:     verbose output to stderr\n" );
	fprintf( stream, "\t-V:     print version\n" );
	fprintf( stream, "\n" );
}

/* The main program
 */
#if defined( HAVE_WIDE_SYSTEM_CHARACTER )
int wmain( int argc, wchar_t * const argv[] )
#else
int main( int argc, char * const argv[] )
#endif
{
	libcerror_error_t *error               = NULL;
	libcfile_file_t *destination_file      = NULL;
	libcfile_file_t *source_file           = NULL;
	libfcrypto_serpent_context_t *context  = NULL;
	system_character_t *option_keys        = NULL;
	system_character_t *option_target_path = NULL;
	system_character_t *source             = NULL;
	uint8_t *buffer                        = NULL;
	uint8_t *decrypted_data                = NULL;
	uint8_t *key_data                      = NULL;
	char *program                          = "serpentcrypt";
	system_integer_t option                = 0;
	size64_t source_size                   = 0;
	size_t buffer_size                     = 0;
	size_t decrypted_data_size             = 0;
	size_t key_data_size                   = 0;
	ssize_t read_count                     = 0;
	ssize_t write_count                    = 0;
	off_t source_offset                    = 0;
	int result                             = 0;
	int verbose                            = 0;

	libcnotify_stream_set(
	 stderr,
	 NULL );
	libcnotify_verbose_set(
	 1 );

	assorted_output_version_fprint(
	 stdout,
	 program );

	while( ( option = assorted_getopt(
	                   argc,
	                   argv,
	                   _SYSTEM_STRING( "hk:o:s:t:vV" ) ) ) != (system_integer_t) -1 )
	{
		switch( option )
		{
			case (system_integer_t) '?':
			default:
				fprintf(
				 stderr,
				 "Invalid argument: %" PRIs_SYSTEM "\n",
				 argv[ optind ] );

				usage_fprint(
				 stdout );

				return( EXIT_FAILURE );

			case (system_integer_t) 'h':
				usage_fprint(
				 stdout );

				return( EXIT_SUCCESS );

			case (system_integer_t) 'k':
				option_keys = optarg;

				break;

			case (system_integer_t) 'o':
#if defined( HAVE_WIDE_SYSTEM_CHARACTER )
				source_offset = _wtol( optarg );
#else
				source_offset = atol( optarg );
#endif
				break;

			case (system_integer_t) 's':
#if defined( HAVE_WIDE_SYSTEM_CHARACTER )
				source_size = _wtol( optarg );
#else
				source_size = atol( optarg );
#endif
				break;

			case (system_integer_t) 't':
				option_target_path = optarg;

				break;

			case (system_integer_t) 'v':
				verbose = 1;

				break;

			case (system_integer_t) 'V':
				assorted_output_copyright_fprint(
				 stdout );

				return( EXIT_SUCCESS );
		}
	}
	if( optind == argc )
	{
		fprintf(
		 stderr,
		 "Missing source file.\n" );

		usage_fprint(
		 stdout );

		return( EXIT_FAILURE );
	}
	source = argv[ optind ];

	if( option_keys == NULL )
	{
		fprintf(
		 stderr,
		 "Missing key.\n" );

		usage_fprint(
		 stdout );

		return( EXIT_FAILURE );
	}
	libcnotify_stream_set(
	 stderr,
	 NULL );
	libcnotify_verbose_set(
	 verbose );

	/* Open the source file
	 */
	if( libcfile_file_initialize(
	     &source_file,
	     &error ) != 1 )
	{
		fprintf(
		 stderr,
		 "Unable to create source file.\n" );

		goto on_error;
	}
#if defined( HAVE_WIDE_SYSTEM_CHARACTER )
	result = libcfile_file_open_wide(
	          source_file,
	          source,
	          LIBCFILE_OPEN_READ,
	          &error );
#else
	result = libcfile_file_open(
	          source_file,
	          source,
	          LIBCFILE_OPEN_READ,
	          &error );
#endif
 	if( result != 1 )
	{
		fprintf(
		 stderr,
		 "Unable to open source file.\n" );

		goto on_error;
	}
	if( source_size == 0 )
	{
		if( libcfile_file_get_size(
		     source_file,
		     &source_size,
		     &error ) == -1 )
		{
			fprintf(
			 stderr,
			 "Unable to determine size of source file.\n" );

			goto on_error;
		}
	}
	if( source_size == 0 )
	{
		fprintf(
		 stderr,
		 "Invalid source size value is zero.\n" );

		return( EXIT_FAILURE );
	}
	if( source_size > (size_t) SSIZE_MAX )
	{
		fprintf(
		 stderr,
		 "Invalid source size value exceeds maximum.\n" );

		return( EXIT_FAILURE );
	}
	/* Create the input buffer
	 */
	buffer_size = source_size;

	buffer = (uint8_t *) memory_allocate(
	                      sizeof( uint8_t ) * buffer_size );

	if( buffer == NULL )
	{
		fprintf(
		 stderr,
		 "Unable to create buffer.\n" );

		return( EXIT_FAILURE );
	}
	decrypted_data_size = source_size;

	decrypted_data = (uint8_t *) memory_allocate(
	                              sizeof( uint8_t ) * decrypted_data_size );

	if( decrypted_data == NULL )
	{
		fprintf(
		 stderr,
		 "Unable to create decrypted data buffer.\n" );

		goto on_error;
	}
	/* Position the source file at the right offset
	 */
	if( libcfile_file_seek_offset(
	     source_file,
	     source_offset,
	     SEEK_SET,
	     &error ) == -1 )
	{
		fprintf(
		 stderr,
		 "Unable to seek offset in source file.\n" );

		goto on_error;
	}
	if( libfcrypto_serpent_context_initialize(
	     &context,
	     &error ) != 1 )
	{
		fprintf(
		 stderr,
		 "Unable to create Serpent context.\n" );

		goto on_error;
	}
	fprintf(
	 stdout,
	 "Starting Serpent decrypting data of: %" PRIs_SYSTEM " at offset: %" PRIjd " (0x%08" PRIjx ").\n",
	 source,
	 source_offset,
	 source_offset );

	read_count = libcfile_file_read_buffer(
		      source_file,
		      buffer,
		      source_size,
	              &error );

	if( read_count != (ssize_t) source_size )
	{
		fprintf(
		 stderr,
		 "Unable to read from source file.\n" );

		goto on_error;
	}
	/* Decrypts the data
	 */
	if( serpentcrypt_set_keys(
	     option_keys,
	     &key_data,
	     &key_data_size,
	     &error ) != 1 )
	{
		fprintf(
		 stderr,
		 "Unable to retrieve key data from argument.\n" );

		goto on_error;
	}
	if( libfcrypto_serpent_context_set_key(
	     context,
	     key_data,
	     key_data_size * 8,
	     &error ) != 1 )
	{
		fprintf(
		 stderr,
		 "Unable to set key in context.\n" );

		goto on_error;
	}
	if( memory_set(
	     key_data,
	     0,
	     key_data_size ) == NULL )
	{
		fprintf(
		 stderr,
		 "Unable to clear key data.\n" );

		goto on_error;
	}
	memory_free(
	 key_data );

	key_data = NULL;

	if( option_target_path == NULL )
	{
		fprintf(
		 stderr,
		 "Encrypted data:\n" );

		libcnotify_print_data(
		 buffer,
		 source_size,
		 0 );
	}
	if( libfcrypto_serpent_crypt_ecb(
	     context,
	     LIBFCRYPTO_SERPENT_CRYPT_MODE_DECRYPT,
	     buffer,
	     source_size,
	     decrypted_data,
	     decrypted_data_size,
	     &error ) != 1 )
	{
		fprintf(
		 stderr,
		 "Unable to decode data.\n" );

		goto on_error;
	}
	if( option_target_path == NULL )
	{
		fprintf(
		 stderr,
		 "Decrypted data:\n" );

		libcnotify_print_data(
		 decrypted_data,
		 decrypted_data_size,
		 0 );
	}
	else
	{
		if( libcfile_file_initialize(
		     &destination_file,
		     &error ) != 1 )
		{
			fprintf(
			 stderr,
			 "Unable to create destination file.\n" );

			goto on_error;
		}
#if defined( HAVE_WIDE_SYSTEM_CHARACTER )
		result = libcfile_file_open_wide(
		          destination_file,
		          option_target_path,
		          LIBCFILE_OPEN_WRITE,
		          &error );
#else
		result = libcfile_file_open(
		          destination_file,
		          option_target_path,
		          LIBCFILE_OPEN_WRITE,
		          &error );
#endif
	 	if( result != 1 )
		{
			fprintf(
			 stderr,
			 "Unable to open destination file.\n" );

			goto on_error;
		}
		write_count = libcfile_file_write_buffer(
			       destination_file,
			       decrypted_data,
			       decrypted_data_size,
			       &error );

		if( write_count != (ssize_t) decrypted_data_size )
		{
			fprintf(
			 stderr,
			 "Unable to write to destination file.\n" );

			goto on_error;
		}
		if( libcfile_file_close(
		     destination_file,
		     &error ) != 0 )
		{
			fprintf(
			 stderr,
			 "Unable to close destination file.\n" );

			goto on_error;
		}
		if( libcfile_file_free(
		     &destination_file,
		     &error ) != 1 )
		{
			fprintf(
			 stderr,
			 "Unable to free destination file.\n" );

			goto on_error;
		}
	}
	/* Clean up
	 */
	if( libfcrypto_serpent_context_free(
	     &context,
	     &error ) != 1 )
	{
		fprintf(
		 stderr,
		 "Unable to free Serpent context.\n" );

		goto on_error;
	}
	if( libcfile_file_close(
	     source_file,
	     &error ) != 0 )
	{
		fprintf(
		 stderr,
		 "Unable to close source file.\n" );

		goto on_error;
	}
	if( libcfile_file_free(
	     &source_file,
	     &error ) != 1 )
	{
		fprintf(
		 stderr,
		 "Unable to free source file.\n" );

		goto on_error;
	}
	if( decrypted_data != NULL )
	{
		memory_free(
		 decrypted_data );
	}
	if( buffer != NULL )
	{
		memory_free(
		 buffer );
	}
	fprintf(
	 stdout,
	 "Serpent decryption:\tSUCCESS\n" );

	return( EXIT_SUCCESS );

on_error:
	if( error != NULL )
	{
		libcnotify_print_error_backtrace(
		 error );
		libcerror_error_free(
		 &error );
	}
	if( destination_file != NULL )
	{
		libcfile_file_free(
		 &destination_file,
		 NULL );
	}
	if( decrypted_data != NULL )
	{
		memory_free(
		 decrypted_data );
	}
	if( key_data != NULL )
	{
		memory_set(
		 key_data,
		 0,
		 key_data_size );

		memory_free(
		 key_data );
	}
	if( context != NULL )
	{
		libfcrypto_serpent_context_free(
		 &context,
		 NULL );
	}
	if( buffer != NULL )
	{
		memory_free(
		 buffer );
	}
	if( source_file != NULL )
	{
		libcfile_file_free(
		 &source_file,
		 NULL );
	}
	fprintf(
	 stdout,
	 "Serpent decryption:\tFAILURE\n" );

	return( EXIT_FAILURE );
}

