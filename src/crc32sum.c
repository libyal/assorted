/*
 * Calculates a CRC-32 of file data
 *
 * Copyright (C) 2008-2017, Joachim Metz <joachim.metz@gmail.com>
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
#include "assorted_output.h"
#include "crc32.h"

/* Prints the executable usage information
 */
void usage_fprint(
      FILE *stream )
{
	if( stream == NULL )
	{
		return;
	}
	fprintf( stream, "Use crc32sum to calculate a CRC-32 of file data.\n\n" );

	fprintf( stream, "Usage: crc32sum [ -c crc ] [ -i initial_value ] [ -o offset ]\n"
	                 "                [ -p polynomial ] [ -s size ] [ -12hvVw ] source\n\n" );

	fprintf( stream, "\tsource: the source file\n\n" );

	fprintf( stream, "\t-1:     use the modulo-2 calculation method\n" );
	fprintf( stream, "\t-2:     use the table lookup calculation method (default)\n" );
	fprintf( stream, "\t-c:     check the calculated CRC-32 with the one provided.\n"
	                 "\t        On a mismatch crc32 will try to locate the error.\n" );
	fprintf( stream, "\t-h:     shows this help\n" );
	fprintf( stream, "\t-i:     initial value (default is 0)\n" );
	fprintf( stream, "\t-o:     data offset (default is 0)\n" );
	fprintf( stream, "\t-p:     polynomial (default is 0xedb88320)\n" );
	fprintf( stream, "\t-s:     size of data (default is the file size)\n" );
	fprintf( stream, "\t-v:     verbose output to stderr\n" );
	fprintf( stream, "\t-V:     print version\n" );
	fprintf( stream, "\t-w:     use weak CRC calculation, without the initial and\n"
	                 "\t        final XOR with -1\n" );
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
	char *program                = "crc32sum";
	system_integer_t option      = 0;
	size64_t source_size         = 0;
	ssize_t read_count           = 0;
	off_t source_offset          = 0;
	uint32_t calculated_crc32    = 0;
	uint32_t crc32               = 0;
	uint32_t initial_value       = 0;
	uint32_t polynomial          = 0xedb88320UL;
	uint8_t bit_index            = 0;
	uint8_t weak_crc             = 0;
	int calculation_method       = 2;
	int result                   = 0;
	int validate_crc             = 0;
	int verbose                  = 0;

	assorted_output_version_fprint(
	 stdout,
	 program );

	while( ( option = assorted_getopt(
	                   argc,
	                   argv,
	                   _SYSTEM_STRING( "12c:hi:o:p:s:vVw" ) ) ) != (system_integer_t) -1 )
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

			case 'c':
				crc32 = atol( optarg );

				validate_crc = 1;

				break;

			case 'h':
				usage_fprint(
				 stdout );

				return( EXIT_SUCCESS );

			case 'i':
				initial_value = atol( optarg );

				break;

			case 'o':
				source_offset = atol( optarg );

				break;

			case 'p':
				polynomial = atol( optarg );

				break;

			case 's':
				source_size = atol( optarg );

				break;

			case 'v':
				verbose = 1;

				break;

			case 'V':
				assorted_output_copyright_fprint(
				 stdout );

				return( EXIT_SUCCESS );

			case 'w':
				weak_crc = 1;

				break;
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
	if( libcfile_file_open(
	     source_file,
	     source,
	     LIBCFILE_OPEN_READ,
	     &error ) != 1 )
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
		result = crc32_calculate_modulo2(
			  &calculated_crc32,
			  buffer,
			  source_size,
			  initial_value,
			  weak_crc,
			  &error );
	}
	else if( calculation_method == 2 )
	{
                initialize_crc32_table(
                 polynomial );

		result = crc32_calculate(
			  &calculated_crc32,
			  buffer,
			  source_size,
			  initial_value,
			  weak_crc,
			  &error );
	}
	if( result != 1 )
	{
		fprintf(
		 stderr,
		 "Unable to calculate CRC-32.\n" );

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
	 "Calculated CRC-32: %" PRIu32 " (0x%08" PRIx32 ")\n",
	 calculated_crc32,
	 calculated_crc32 );

	if( validate_crc != 0 )
	{
		if( calculated_crc32 != crc32 )
		{
			fprintf(
			 stdout,
			 "Mismatch between CRC-32: %" PRIu32 " and calculated CRC-32: %" PRIu32 "\n",
			 crc32,
			 calculated_crc32 );

			result = crc32_validate(
			          crc32,
			          calculated_crc32,
			          &bit_index,
			          &error );

			if( result == -1 )
			{
				fprintf(
				 stderr,
				 "Unable to locate error.\n" );

				goto on_error;
			}
			else if( result != 0 )
			{
				fprintf(
				 stdout,
				 "Single bit-error in bit: %" PRIu8 " of CRC-32\n",
				 bit_index );
			}
			result = crc32_locate_error_offset(
			          crc32,
			          calculated_crc32,
			          buffer,
			          source_size,
			          initial_value,
			          &error );

			if( result == -1 )
			{
				fprintf(
				 stderr,
				 "Unable to locate error.\n" );

				goto on_error;
			}
		}
		else
		{
			fprintf(
			 stdout,
			 "Match between CRC-32: %" PRIu32 " and calculated CRC-32: %" PRIu32 "\n",
			 crc32,
			 calculated_crc32 );
		}
	}
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

