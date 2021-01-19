/*
 * Calculates an Adler-32 of file data
 *
 * Copyright (C) 2008-2021, Joachim Metz <joachim.metz@gmail.com>
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
#include <file_stream.h>
#include <memory.h>
#include <system_string.h>
#include <types.h>

#if defined( HAVE_STDLIB_H )
#include <stdlib.h>
#endif

#if defined( HAVE_ZLIB ) || defined( ZLIB_DLL )
#include <zlib.h>
#endif

#include "adler32.h"
#include "assorted_getopt.h"
#include "assorted_libcerror.h"
#include "assorted_libcfile.h"
#include "assorted_libcnotify.h"
#include "assorted_output.h"

/* Prints the executable usage information
 */
void usage_fprint(
      FILE *stream )
{
	if( stream == NULL )
	{
		return;
	}
	fprintf( stream, "Use adler32sum to calculate an Adler-32 of file data.\n\n" );

	fprintf( stream, "Usage: adler32sum [ -i initial_value ] [ -o offset ] [ -s size ]\n"
	                 "                  [ -12345hvV ] source\n\n" );

	fprintf( stream, "\tsource: the source file\n\n" );

	fprintf( stream, "\t-1:     use the basic calculation method\n" );
	fprintf( stream, "\t-2:     use the unfolded calculation method (default)\n" );
	fprintf( stream, "\t-3:     use the cpu-aligned calculation method\n" );
	fprintf( stream, "\t-4:     use the SIMD calculation method\n" );
	fprintf( stream, "\t-5:     use the zlib calculation method\n" );
	fprintf( stream, "\t-h:     shows this help\n" );
	fprintf( stream, "\t-i:     initial Adler-32 (default is 0)\n" );
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
	char *program                = "adler32sum";
	system_integer_t option      = 0;
	size64_t source_size         = 0;
	ssize_t read_count           = 0;
	off_t source_offset          = 0;
	uint32_t checksum_value      = 0;
	uint32_t initial_value       = 0;
	int calculation_method       = 2;
	int result                   = 0;
	int verbose                  = 0;

	assorted_output_version_fprint(
	 stdout,
	 program );

	while( ( option = assorted_getopt(
	                   argc,
	                   argv,
	                   _SYSTEM_STRING( "12345hi:o:s:vV" ) ) ) != (system_integer_t) -1 )
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

			case '3':
				calculation_method = 3;

				break;

			case '4':
				calculation_method = 4;

				break;

			case '5':
				calculation_method = 5;

				break;

			case 'h':
				usage_fprint(
				 stdout );

				return( EXIT_SUCCESS );

			case 'i':
#if defined( HAVE_WIDE_SYSTEM_CHARACTER )
				initial_value = _wtol( optarg );
#else
				initial_value = atol( optarg );
#endif
				break;

			case 'o':
#if defined( HAVE_WIDE_SYSTEM_CHARACTER )
				source_offset = _wtol( optarg );
#else
				source_offset = atol( optarg );
#endif
				break;

			case 's':
#if defined( HAVE_WIDE_SYSTEM_CHARACTER )
				source_size = _wtol( optarg );
#else
				source_size = atol( optarg );
#endif
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
	if( source_size > (size64_t) SSIZE_MAX )
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
		result = adler32_calculate_checksum_basic2(
		          &checksum_value,
		          buffer,
		          source_size,
		          initial_value,
		          &error );
	}
	else if( calculation_method == 2 )
	{
		/* The unfolded4_2 variant is slower than the unfolded4_1 variant
		 */
		/* Fastest to slowest variant
		 * - adler32_calculate_checksum_unfolded16_4
		 * - adler32_calculate_checksum_unfolded16_2
		 * - adler32_calculate_checksum_unfolded16_1
		 * - adler32_calculate_checksum_unfolded16_3
		 */
		result = adler32_calculate_checksum_unfolded16_4(
		          &checksum_value,
		          buffer,
		          source_size,
		          initial_value,
		          &error );
	}
	else if( calculation_method == 3 )
	{
		/* The unfolded variants seems to be faster then the CPU aligned
		 */
		result = adler32_calculate_checksum_cpu_aligned(
		          &checksum_value,
		          buffer,
		          source_size,
		          initial_value,
		          &error );
	}
	else if( calculation_method == 4 )
	{
/* TODO experimental */
		result = adler32_calculate_checksum_simd(
		          &checksum_value,
		          buffer,
		          source_size,
		          initial_value,
		          &error );
	}
	else if( calculation_method == 5 )
	{
#if !defined( HAVE_ZLIB_ADLER32 )
		fprintf(
		 stderr,
		 "Missing zlib Adler-32 support.\n" );

		goto on_error;
#else
		checksum_value = adler32(
		                  initial_value,
		                  buffer,
		                  source_size );

		result = 1;
#endif
	}
	if( result != 1 )
	{
		fprintf(
		 stderr,
		 "Unable to calculate Adler-32.\n" );

		goto on_error;
	}
	if( libcnotify_verbose != 0 )
	{
		libcnotify_print_data(
		 buffer,
		 source_size,
		 0 );
	}
	memory_free(
	 buffer );

	fprintf(
	 stdout,
	 "Calculated Adler-32: %" PRIu32 " (0x%08" PRIx32 ")\n",
	 checksum_value,
	 checksum_value );

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

