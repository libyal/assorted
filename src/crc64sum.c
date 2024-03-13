/*
 * Calculates a CRC-64 of file data
 *
 * Copyright (C) 2008-2024, Joachim Metz <joachim.metz@gmail.com>
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

#include "assorted_crc64.h"
#include "assorted_getopt.h"
#include "assorted_libcerror.h"
#include "assorted_libcfile.h"
#include "assorted_libcnotify.h"
#include "assorted_output.h"
#include "assorted_system_string.h"

/* Prints the executable usage information
 */
void usage_fprint(
      FILE *stream )
{
	if( stream == NULL )
	{
		return;
	}
/* TODO add [ -p polynomial ] support */
	fprintf( stream, "Use crc64sum to calculate a CRC-64 of file data.\n\n" );

	fprintf( stream, "Usage: crc64sum [ -i initial_value ] [ -o offset ]\n"
	                 "                [ -s size ] [ -12hvV ] source\n\n" );

	fprintf( stream, "\tsource: the source file\n\n" );

	fprintf( stream, "\t-1:     use the table lookup calculation method (default)\n" );
	fprintf( stream, "\t-2:     method 2\n" );
	fprintf( stream, "\t-h:     shows this help\n" );
	fprintf( stream, "\t-i:     initial CRC-64 (default is 0)\n" );
	fprintf( stream, "\t-o:     data offset (default is 0)\n" );
	fprintf( stream, "\t-s:     size of data (default is the file size)\n" );
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
	libcerror_error_t *error     = NULL;
	libcfile_file_t *source_file = NULL;
	system_character_t *source   = NULL;
	uint8_t *buffer              = NULL;
	char *program                = "crc64sum";
	system_integer_t option      = 0;
	size64_t source_size         = 0;
	ssize_t read_count           = 0;
	off_t source_offset          = 0;
	uint64_t calculated_crc64    = 0;
	uint64_t initial_value       = 0;
	int calculation_method       = 1;
	int result                   = 0;
	int verbose                  = 0;

	assorted_output_version_fprint(
	 stdout,
	 program );

	while( ( option = assorted_getopt(
	                   argc,
	                   argv,
	                   _SYSTEM_STRING( "12hi:o:s:vV" ) ) ) != (system_integer_t) -1 )
	{
		switch( option )
		{
			case '?':
			default:
				fprintf(
				 stderr,
				 "Invalid argument: %" PRIs_SYSTEM "\n",
				 argv[ optind ] );

				usage_fprint(
				 stdout );

				return( EXIT_FAILURE );

			case '1':
				calculation_method = 1;

				break;

			case '2':
				calculation_method = 2;

				break;

			case 'h':
				usage_fprint(
				 stdout );

				return( EXIT_SUCCESS );

			case 'i':
				initial_value = system_string_copy_to_long( optarg );

				break;

			case 'o':
				source_offset = system_string_copy_to_long( optarg );

				break;

			case 's':
				source_size = system_string_copy_to_long( optarg );

				break;

			case 'v':
				verbose = 1;

				break;

			case 'V':
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

		goto on_error;
	}
	if( source_size > (size_t) SSIZE_MAX )
	{
		fprintf(
		 stderr,
		 "Invalid source size value exceeds maximum.\n" );

		goto on_error;
	}
	buffer = (uint8_t *) memory_allocate(
	                      sizeof( uint8_t ) * source_size );

	if( buffer == NULL )
	{
		fprintf(
		 stderr,
		 "Unable to create buffer.\n" );

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
	/* Clean up
	 */
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
	if( calculation_method == 1 )
	{
		result = assorted_crc64_calculate_1(
			  &calculated_crc64,
			  buffer,
			  source_size,
			  initial_value,
			  &error );
	}
	else if( calculation_method == 2 )
	{
		result = assorted_crc64_calculate_2(
			  &calculated_crc64,
			  buffer,
			  source_size,
			  initial_value,
			  &error );
	}
	if( result != 1 )
	{
		fprintf(
		 stderr,
		 "Unable to calculate CRC-64.\n" );

		goto on_error;
	}
	if( libcnotify_verbose != 0 )
	{
		libcnotify_print_data(
		 buffer,
		 source_size,
		 0 );
	}
	fprintf(
	 stdout,
	 "Calculated CRC-64: %" PRIu64 " (0x%08" PRIx64 ")\n",
	 calculated_crc64,
	 calculated_crc64 );

	memory_free(
	 buffer );

	return( EXIT_SUCCESS );

on_error:
	if( error != NULL )
	{
		libcnotify_print_error_backtrace(
		 error );
		libcerror_error_free(
		 &error );
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
	return( EXIT_FAILURE );
}

