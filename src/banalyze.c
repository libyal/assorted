/*
 * Block analyzer.
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

#if defined( HAVE_STDLIB_H )
#include <stdlib.h>
#endif

#include <math.h>

#include "assorted_getopt.h"
#include "assorted_libcerror.h"
#include "assorted_libcfile.h"
#include "assorted_libcnotify.h"
#include "assorted_libhmac.h"
#include "assorted_output.h"
#include "digest_hash.h"

#define DIGEST_HASH_STRING_SIZE_MD5	33

/* Prints the executable usage information
 */
void usage_fprint(
      FILE *stream )
{
	if( stream == NULL )
	{
		return;
	}
	fprintf( stream, "Use banalyze to analyze blocks of data.\n\n" );

	fprintf( stream, "Usage: banalyze [-b block_size] [ -o offset ] [ -s size ] [-12hrvV] source\n\n" );

	fprintf( stream, "\tsource: the source file\n\n" );

	fprintf( stream, "\t-1:     calculate block entropy (default)\n" );
	fprintf( stream, "\t-2:     calculate block message digest hashes\n" );
	fprintf( stream, "\t-b:     specify the block size (default is: 512)\n" );
	fprintf( stream, "\t-h:     shows this usage information\n" );
	fprintf( stream, "\t-o:     data offset (default is 0)\n" );
	fprintf( stream, "\t-r:     output the offset relative from the data offset instead of the data\n"
	                 "\t        offset.\n" );
	fprintf( stream, "\t-s:     size of data (default is the file size)\n" );
	fprintf( stream, "\t-v:     verbose output to stderr\n" );
	fprintf( stream, "\t-V:     print version\n" );
	fprintf( stream, "\n" );
}

/* Determines the byte distribution (frequency)
 * Returns 1 if successful or -1 on error
 */
int banalyze_determine_byte_distribution(
     const uint8_t *block_buffer,
     size_t block_size,
     uint64_t distribution_table[ 256 ],
     libcerror_error_t **error )
{
	static char *function = "banalyze_determine_byte_distribution";
	size_t block_offset   = 0;
	uint8_t byte_value    = 0;

	if( block_buffer == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid block buffer.",
		 function );

		return( -1 );
	}
	if( distribution_table == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid distribution table.",
		 function );

		return( -1 );
	}
	if( memory_set(
	     distribution_table,
	     0,
	     sizeof( uint64_t ) * 256 ) == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_SET_FAILED,
		 "%s: unable to clear distribution table.",
		 function );

		return( -1 );
	}
	for( block_offset = 0;
	     block_offset < block_size;
	     block_offset++ )
	{
		byte_value = block_buffer[ block_offset ];

		distribution_table[ byte_value ] += 1;
	}
	return( 1 );
}

/* Calculates the byte entropy value
 * Returns 1 if successful or -1 on error
 */
int banalyze_calculate_byte_entropy(
     size_t block_size,
     uint64_t distribution_table[ 256 ],
     double_t *byte_entropy,
     libcerror_error_t **error )
{
	static char *function = "banalyze_calculate_byte_entropy";
	uint16_t byte_value   = 0;
	double entropy        = 0.0;
	double probability    = 0.0;

	if( distribution_table == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid distribution table.",
		 function );

		return( -1 );
	}
	if( byte_entropy == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid byte entropy.",
		 function );

		return( -1 );
	}
	for( byte_value = 0;
	     byte_value < 256;
	     byte_value++ )
	{
		if( distribution_table[ byte_value ] > 0 )
		{
			probability = (double) distribution_table[ byte_value ] / (double) block_size;
			entropy    += probability * ( log( probability ) / log( 2 ) );
		}
	}
	if( entropy < 0.0 )
	{
		entropy *= -1.0;
	}
	*byte_entropy = entropy;

	return( 1 );
}

/* Analyzes a block
 * Returns 1 if successful or -1 on error
 */
int banalyze_analyze_block(
     int analysis_method,
     const uint8_t *block_buffer,
     size_t block_size,
     off64_t block_offset,
     libcerror_error_t **error )
{
	uint64_t distribution_table[ 256 ];
	uint8_t md5_hash[ LIBHMAC_MD5_HASH_SIZE ];
	system_character_t md5_hash_string[ DIGEST_HASH_STRING_SIZE_MD5 ];

	static char *function = "banalyze_analyze_block";
	double entropy        = 0.0;

	switch( analysis_method )
	{
		case 1:
			if( banalyze_determine_byte_distribution(
			     block_buffer,
			     block_size,
			     distribution_table,
			     error ) != 1 )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_RUNTIME,
				 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
				 "%s: unable to determine byte distribution.",
				 function );

				return( -1 );
			}
			if( banalyze_calculate_byte_entropy(
			     block_size,
			     distribution_table,
			     &entropy,
			     error ) != 1 )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_RUNTIME,
				 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
				 "%s: unable to calculate byte entropy.",
				 function );

				return( -1 );
			}
			fprintf(
			 stdout,
			 "block 0x%08" PRIx64 " - 0x%08" PRIx64 ": byte entropy: %f\n",
			 block_offset,
			 block_offset + block_size,
			 entropy );

			break;

		case 2:
			if( libhmac_md5_calculate(
			     block_buffer,
			     block_size,
			     md5_hash,
			     LIBHMAC_MD5_HASH_SIZE,
			     error ) != 1 )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_RUNTIME,
				 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
				 "%s: unable to calculate MD5.",
				 function );

				return( -1 );
			}
			if( digest_hash_copy_to_string(
			     md5_hash,
			     LIBHMAC_MD5_HASH_SIZE,
			     md5_hash_string,
			     DIGEST_HASH_STRING_SIZE_MD5,
			     error ) != 1 )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_RUNTIME,
				 LIBCERROR_RUNTIME_ERROR_SET_FAILED,
				 "%s: unable to set MD5 hash string.",
				 function );

				return( -1 );
			}
			fprintf(
			 stdout,
			 "block 0x%08" PRIx64 " - 0x%08" PRIx64 ": MD5: %" PRIs_SYSTEM "\n",
			 block_offset,
			 block_offset + block_size,
			 md5_hash_string );

			break;

		default:
			break;
	}
	return( 1 );
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
	char *program                = "banalyze";
	system_integer_t option      = 0;
	size64_t block_size          = 512;
	size64_t source_size         = 0;
	size_t buffer_size           = 0;
	size_t read_size             = 0;
	ssize_t read_count           = 0;
	off64_t block_offset         = 0;
	off64_t source_offset        = 0;
	int analysis_method          = 1;
	int output_relative_offset   = 0;
	int result                   = 0;
	int verbose                  = 0;

	assorted_output_version_fprint(
	 stdout,
	 program );

	while( ( option = assorted_getopt(
	                   argc,
	                   argv,
	                   _SYSTEM_STRING( "12b:ho:rs:vV" ) ) ) != (system_integer_t) -1 )
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
				analysis_method = 1;

				break;

			case '2':
				analysis_method = 2;

				break;

			case 'b':
#if defined( HAVE_WIDE_SYSTEM_CHARACTER )
				block_size = _wtol( optarg );
#else
				block_size = atol( optarg );
#endif
				break;

			case 'h':
				usage_fprint(
				 stdout );

				return( EXIT_SUCCESS );

			case 'o':
#if defined( HAVE_WIDE_SYSTEM_CHARACTER )
				source_offset = _wtol( optarg );
#else
				source_offset = atol( optarg );
#endif
				break;

			case 'r':
				output_relative_offset = 1;

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
	if( source_size > (size_t) SSIZE_MAX )
	{
		fprintf(
		 stderr,
		 "Invalid source size value exceeds maximum.\n" );

		goto on_error;
	}
	/* Create the input buffer
	 */
	if( block_size > (size_t) SSIZE_MAX )
	{
		fprintf(
		 stderr,
		 "Invalid block size value exceeds maximum.\n" );

		goto on_error;
	}
	buffer_size = block_size;

	buffer = (uint8_t *) memory_allocate(
	                      sizeof( uint8_t ) * buffer_size );

	if( buffer == NULL )
	{
		fprintf(
		 stderr,
		 "Unable to create buffer.\n" );

		return( EXIT_FAILURE );
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
	fprintf(
	 stdout,
	 "Starting block analysis of: %" PRIs_SYSTEM " at offset: %" PRIi64 " (0x%08" PRIx64 ").\n",
	 source,
	 source_offset,
	 source_offset );

	while( (size64_t) block_offset < source_size )
	{
		/* Clear buffer before read since in some cases like volsnap.sys
		 * read will return successful without actually filling the buffer
		 */
		if( memory_set(
		     buffer,
		     0,
		     buffer_size ) == NULL )
		{
			fprintf(
			 stderr,
			 "Unable to clear read buffer.\n" );

			goto on_error;
		}
		read_size = buffer_size;

		if( read_size > ( source_size - block_offset ) )
		{
			read_size = (size_t) ( source_size - block_offset );
		}
		read_count = libcfile_file_read_buffer(
			      source_file,
			      buffer,
			      read_size,
		              &error );

		if( read_count != (ssize_t) read_size )
		{
			fprintf(
			 stderr,
			 "Unable to read block from source file.\n" );

			goto on_error;
		}
		if( output_relative_offset != 0 )
		{
			result = banalyze_analyze_block(
			          analysis_method,
			          buffer,
			          read_size,
			          block_offset,
			          &error );
		}
		else
		{
			result = banalyze_analyze_block(
			          analysis_method,
			          buffer,
			          read_size,
			          source_offset + block_offset,
			          &error );
		}
		if( result != 1 )
		{
			fprintf(
			 stderr,
			 "Unable to analyze block at offset: %" PRIi64 " (0x%08" PRIx64 ").\n",
			 source_offset + block_offset,
			 source_offset + block_offset );

			goto on_error;
		}
		block_offset += read_size;
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

