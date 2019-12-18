/*
 * Decompresses LZX compressed data
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
#include <system_string.h>
#include <types.h>

#if defined( HAVE_STDLIB_H )
#include <stdlib.h>
#endif

#include "assorted_getopt.h"
#include "assorted_libcerror.h"
#include "assorted_libcfile.h"
#include "assorted_libcnotify.h"
#include "assorted_libfwnt.h"
#include "assorted_output.h"
#include "assorted_signal.h"
#include "assorted_unused.h"
#include "decompression_handle.h"

decompression_handle_t *lzxdecompress_decompression_handle = NULL;
int lzxdecompress_abort                                    = 0;

/* Prints the executable usage information
 */
void usage_fprint(
      FILE *stream )
{
	if( stream == NULL )
	{
		return;
	}
	fprintf( stream, "Use lzxdecompress to decompress LZX compressed data.\n\n" );

	fprintf( stream, "Usage: lzxdecompress [ -d size ] [ -o offset ] [ -s size ]\n"
	                 "                     [ -t target ] [ -hvV ] source\n\n" );

	fprintf( stream, "\tsource: the source file\n\n" );

	fprintf( stream, "\t-d:     size of the decompressed data (default is 65536).\n" );
	fprintf( stream, "\t-h:     shows this help\n" );
	fprintf( stream, "\t-o:     data offset (default is 0)\n" );
	fprintf( stream, "\t-s:     size of data (default is the file size)\n" );
	fprintf( stream, "\t-t:     specify the target file to write the output data,\n"
	                 "\t        by default the data will be written to stdout in\n"
	                 "\t        hexadecimal representation\n" );
	fprintf( stream, "\t-v:     verbose output to stderr\n" );
	fprintf( stream, "\t-V:     print version\n" );
	fprintf( stream, "\n" );
}

/* Signal handler for lzxdecompress
 */
void lzxdecompress_signal_handler(
      assorted_signal_t signal ASSORTED_ATTRIBUTE_UNUSED )
{
	libcerror_error_t *error = NULL;
	static char *function    = "lzxdecompress_signal_handler";

	ASSORTED_UNREFERENCED_PARAMETER( signal )

	lzxdecompress_abort = 1;

	if( lzxdecompress_decompression_handle != NULL )
	{
		if( decompression_handle_signal_abort(
		     lzxdecompress_decompression_handle,
		     &error ) != 1 )
		{
			libcnotify_printf(
			 "%s: unable to signal decompression handle to abort.\n",
			 function );

			libcnotify_print_error_backtrace(
			 error );
			libcerror_error_free(
			 &error );
		}
	}
	/* Force stdin to close otherwise any function reading it will remain blocked
	 */
#if defined( WINAPI ) && !defined( __CYGWIN__ )
	if( _close(
	     0 ) != 0 )
#else
	if( close(
	     0 ) != 0 )
#endif
	{
		libcnotify_printf(
		 "%s: unable to close stdin.\n",
		 function );
	}
}

/* The main program
 */
#if defined( HAVE_WIDE_SYSTEM_CHARACTER )
int wmain( int argc, wchar_t * const argv[] )
#else
int main( int argc, char * const argv[] )
#endif
{
	libcerror_error_t *error                 = NULL;
	system_character_t *option_source_offset = NULL;
	system_character_t *option_source_size   = NULL;
	system_character_t *option_target_path   = NULL;
	system_character_t *options_string       = NULL;
	system_character_t *source               = NULL;
	uint8_t *buffer                          = NULL;
	uint8_t *uncompressed_data               = NULL;
	char *program                            = "lzxdecompress";
	system_integer_t option                  = 0;
	size_t buffer_size                       = 0;
	size_t uncompressed_data_size            = 0;
	int result                               = 0;
	int verbose                              = 0;

	assorted_output_version_fprint(
	 stdout,
	 program );

	options_string = _SYSTEM_STRING( "d:ho:s:t:vV" );

	while( ( option = assorted_getopt(
	                   argc,
	                   argv,
	                   options_string ) ) != (system_integer_t) -1 )
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

			case (system_integer_t) 'd':
#if defined( HAVE_WIDE_SYSTEM_CHARACTER )
				uncompressed_data_size = _wtol( optarg );
#else
				uncompressed_data_size = atol( optarg );
#endif
				break;

			case (system_integer_t) 'h':
				usage_fprint(
				 stdout );

				return( EXIT_SUCCESS );

			case (system_integer_t) 'o':
				option_source_offset = optarg;

				break;

			case (system_integer_t) 's':
				option_source_size = optarg;

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

	libcnotify_stream_set(
	 stderr,
	 NULL );
	libcnotify_verbose_set(
	 verbose );

	if( decompression_handle_initialize(
	     &lzxdecompress_decompression_handle,
	     &error ) != 1 )
	{
		fprintf(
		 stderr,
		 "Unable to initialize decompression handle.\n" );

		goto on_error;
	}
	if( option_source_offset != NULL )
	{
		if( decompression_handle_set_input_offset(
		     lzxdecompress_decompression_handle,
		     option_source_offset,
		     &error ) != 1 )
		{
			fprintf(
			 stderr,
			 "Unable to set source offset.\n" );

			goto on_error;
		}
	}
	if( option_source_size != NULL )
	{
		if( decompression_handle_set_input_size(
		     lzxdecompress_decompression_handle,
		     option_source_size,
		     &error ) != 1 )
		{
			fprintf(
			 stderr,
			 "Unable to set source size.\n" );

			goto on_error;
		}
	}
	if( decompression_handle_open_input(
	     lzxdecompress_decompression_handle,
	     source,
	     &error ) != 1 )
	{
		fprintf(
		 stderr,
		 "Unable to open: %" PRIs_SYSTEM ".\n",
		 source );

		goto on_error;
	}
	if( lzxdecompress_decompression_handle->input_size == 0 )
	{
		fprintf(
		 stderr,
		 "Invalid source size value is zero.\n" );

		goto on_error;
	}
	if( lzxdecompress_decompression_handle->input_size > (size_t) SSIZE_MAX )
	{
		fprintf(
		 stderr,
		 "Invalid source size value exceeds maximum.\n" );

		goto on_error;
	}
	/* Create the input buffer
	 */
	buffer_size = lzxdecompress_decompression_handle->input_size;

	buffer = (uint8_t *) memory_allocate(
	                      sizeof( uint8_t ) * buffer_size );

	if( buffer == NULL )
	{
		fprintf(
		 stderr,
		 "Unable to create buffer.\n" );

		goto on_error;
	}
	if( uncompressed_data_size == 0 )
	{
		uncompressed_data_size = 32768;
	}
	uncompressed_data = (uint8_t *) memory_allocate(
	                                 sizeof( uint8_t ) * uncompressed_data_size );

	if( uncompressed_data == NULL )
	{
		fprintf(
		 stderr,
		 "Unable to create uncompressed data buffer.\n" );

		goto on_error;
	}
	if( memory_set(
             uncompressed_data,
	     0,
	     uncompressed_data_size ) == NULL )
	{
		fprintf(
		 stderr,
		 "Unable to clear uncompressed data buffer.\n" );

		goto on_error;
	}
	fprintf(
	 stdout,
	 "Starting LZX decompression of: %" PRIs_SYSTEM " at offset: %" PRIjd " (0x%08" PRIjx ").\n",
	 source,
	 lzxdecompress_decompression_handle->input_offset,
	 lzxdecompress_decompression_handle->input_offset );

	if( decompression_handle_read_data(
	     lzxdecompress_decompression_handle,
	     buffer,
	     lzxdecompress_decompression_handle->input_size,
	     &error ) != 1 )
	{
		fprintf(
		 stderr,
		 "Unable to read from source file.\n" );

		goto on_error;
	}
	/* Decompress the data
	 */
	if( option_target_path == NULL )
	{
		fprintf(
		 stderr,
		 "Compressed data:\n" );

		libcnotify_print_data(
		 buffer,
		 lzxdecompress_decompression_handle->input_size,
		 LIBCNOTIFY_PRINT_DATA_FLAG_GROUP_DATA );
	}
	result = libfwnt_lzx_decompress(
	          buffer,
	          (size_t) lzxdecompress_decompression_handle->input_size,
	          uncompressed_data,
	          &uncompressed_data_size,
	          &error );

	if( result == -1 )
	{
		fprintf(
		 stderr,
		 "Unable to decompress data.\n" );

		libcnotify_print_data(
		 uncompressed_data,
		 uncompressed_data_size,
		 LIBCNOTIFY_PRINT_DATA_FLAG_GROUP_DATA );

		goto on_error;
	}
	if( decompression_handle_write_data(
	     lzxdecompress_decompression_handle,
	     option_target_path,
	     uncompressed_data,
	     uncompressed_data_size,
	     &error ) != 1 )
	{
		fprintf(
		 stderr,
		 "Unable to write data.\n" );

		goto on_error;
	}
	/* Clean up
	 */
	memory_free(
	 uncompressed_data );

	uncompressed_data = NULL;

	memory_free(
	 buffer );

	buffer = NULL;

	if( decompression_handle_close_input(
	     lzxdecompress_decompression_handle,
	     &error ) != 0 )
	{
		fprintf(
		 stderr,
		 "Unable to close source file.\n" );

		goto on_error;
	}
	if( decompression_handle_free(
	     &lzxdecompress_decompression_handle,
	     &error ) != 1 )
	{
		fprintf(
		 stderr,
		 "Unable to free decompression handle.\n" );

		goto on_error;
	}
	fprintf(
	 stdout,
	 "LZX decompression:\tSUCCESS\n" );

	return( EXIT_SUCCESS );

on_error:
	if( error != NULL )
	{
		libcnotify_print_error_backtrace(
		 error );
		libcerror_error_free(
		 &error );
	}
	if( uncompressed_data != NULL )
	{
		memory_free(
		 uncompressed_data );
	}
	if( buffer != NULL )
	{
		memory_free(
		 buffer );
	}
	if( lzxdecompress_decompression_handle != NULL )
	{
		decompression_handle_free(
		 &lzxdecompress_decompression_handle,
		 NULL );
	}
	fprintf(
	 stdout,
	 "LZX decompression:\tFAILURE\n" );

	return( EXIT_FAILURE );
}

