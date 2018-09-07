/*
 * mssearchdecode decodes MS Search encoded data
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
#include "assorted_libuna.h"
#include "assorted_output.h"
#include "mssearch.h"

/* Prints the executable usage information
 */
void usage_fprint(
      FILE *stream )
{
	if( stream == NULL )
	{
		return;
	}
	fprintf( stream, "Use mssearchdecode to decode MS Search encoded data.\n\n" );

	fprintf( stream, "Usage: mssearchdecode [ -o offset ] [ -s size ] [ -hvV ] source\n\n" );

	fprintf( stream, "\tsource: the source file\n\n" );

	fprintf( stream, "\t-h:     shows this help\n" );
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
	char destination[ 128 ];

	libcerror_error_t *error         = NULL;
	libcfile_file_t *source_file     = NULL;
	system_character_t *source       = NULL;
	system_character_t *value_string = NULL;
	uint8_t *buffer                  = NULL;
	uint8_t *decoded_data            = NULL;
	uint8_t *narrow_value_string     = NULL;
	uint8_t *uncompressed_data       = NULL;
	uint8_t *value_utf16_stream      = NULL;
	static char *function            = "main";
	char *program                    = "mssearchdecode";
	system_integer_t option          = 0;
	size64_t source_size             = 0;
	size_t buffer_size               = 0;
	size_t decoded_data_size         = 0;
	size_t narrow_value_string_size  = 0;
	size_t uncompressed_data_size    = 0;
	size_t value_string_size         = 0;
	size_t value_utf16_stream_size   = 0;
	ssize_t read_count               = 0;
	off_t source_offset              = 0;
	uint8_t compression_type         = 0;
	int ascii_codepage               = LIBUNA_CODEPAGE_WINDOWS_1252;
	int print_count                  = 0;
	int result                       = 0;
	int verbose                      = 0;

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
	                   _SYSTEM_STRING( "ho:s:vV" ) ) ) != (system_integer_t) -1 )
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

			case 'h':
				usage_fprint(
				 stdout );

				return( EXIT_SUCCESS );

			case 'o':
				source_offset = atol( optarg );

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
	decoded_data_size = source_size;

	decoded_data = (uint8_t *) memory_allocate(
	                            sizeof( uint8_t ) * decoded_data_size );

	if( decoded_data == NULL )
	{
		fprintf(
		 stderr,
		 "Unable to create decoded data buffer.\n" );

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
	print_count = narrow_string_snprintf(
	               destination,
	               128,
	               "%s.mssearch.decoded",
	               source );

	if( ( print_count < 0 )
	 || ( print_count > 128 ) )
	{
		
		fprintf(
		 stderr,
		 "Unable to set destination filename.\n" );

		goto on_error;
	}
	fprintf(
	 stdout,
	 "Starting MS Search decoding data of: %" PRIs_SYSTEM " at offset: %" PRIjd " (0x%08" PRIjx ").\n",
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
	/* Decodes the data
	 */
	fprintf(
	 stderr,
	 "Encoded data:\n" );

	libcnotify_print_data(
	 buffer,
	 source_size,
	 0 );

	if( mssearch_decode(
	     decoded_data,
	     decoded_data_size,
	     buffer,
	     source_size,
	     &error ) != 1 )
	{
		fprintf(
		 stderr,
		 "Unable to decode data.\n" );

		goto on_error;
	}
	fprintf(
	 stderr,
	 "Decoded data:\n" );

	libcnotify_print_data(
	 decoded_data,
	 decoded_data_size,
	 0 );

	source_offset += source_size;
	source_size   -= source_size;

	fprintf(
	 stderr,
	 "Compression type:\t0x%02" PRIx8 "\n",
	 decoded_data[ 0 ] );
	fprintf(
	 stderr,
	 "\n" );

	compression_type = decoded_data[ 0 ];

	/* Byte-index compressed data
	 */
	if( ( compression_type & 0x02 ) != 0 )
	{
		if( mssearch_get_byte_index_uncompressed_data_size(
		     &( decoded_data[ 1 ] ),
		     decoded_data_size - 1,
		     &uncompressed_data_size,
		     &error ) != 1 )
		{
			libcerror_error_set(
			 &error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
			 "%s: unable to retrieve byte-index compressed data size.",
			 function );

			goto on_error;
		}
		uncompressed_data_size += 1;

		uncompressed_data = (uint8_t *) memory_allocate(
		                                 sizeof( uint8_t ) * uncompressed_data_size );

		if( uncompressed_data == NULL )
		{
			libcerror_error_set(
			 &error,
			 LIBCERROR_ERROR_DOMAIN_MEMORY,
			 LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
			 "%s: unable to create uncompressed data.",
			 function );

			goto on_error;
		}
		/* Add the first byte of the decoded data - 2 to have the
		 * decompressed data look like decoded data for chained decompression
		 */
		uncompressed_data[ 0 ] = decoded_data[ 0 ] - 2;

		result = mssearch_decompress_byte_indexed_compressed_data(
		          &( uncompressed_data[ 1 ] ),
		          uncompressed_data_size - 1,
		          &( decoded_data[ 1 ] ),
		          decoded_data_size - 1,
		          &error );

		if( result != 1 )
		{
			fprintf(
			 stderr,
			 "Unable to decompress byte-index compressed data." );

			goto on_error;
		}
		libcnotify_printf(
		 "%s: decompressed data:\n",
		 function );
		libcnotify_print_data(
		 uncompressed_data,
		 uncompressed_data_size,
		 0 );

		memory_free(
		 decoded_data );

		decoded_data      = uncompressed_data;
		decoded_data_size = uncompressed_data_size;

		uncompressed_data = NULL;

		compression_type &= ~( 0x02 );
	}
	/* Run-length compressed UTF-16 little-endian string
	 */
	if( compression_type == 0 )
	{
		if( mssearch_get_run_length_uncompressed_utf16_string_size(
		     &( decoded_data[ 1 ] ),
		     decoded_data_size - 1,
		     &value_utf16_stream_size,
		     &error ) != 1 )
		{
			libcerror_error_set(
			 &error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
			 "%s: unable to retrieve run-length uncompressed UTF-16 string size.",
			 function );

			if( error != NULL )
			{
				libcnotify_print_error_backtrace(
				 error );
			}
			libcerror_error_free(
			 &error );

			memory_free(
			 decoded_data );
		}
		if( value_utf16_stream_size > 0 )
		{
			value_utf16_stream = (uint8_t *) memory_allocate(
							  sizeof( uint8_t ) * value_utf16_stream_size );

			if( value_utf16_stream == NULL )
			{
				libcerror_error_set(
				 &error,
				 LIBCERROR_ERROR_DOMAIN_MEMORY,
				 LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
				 "%s: unable to create value UTF-16 stream.",
				 function );

				goto on_error;
			}
			if( mssearch_decompress_run_length_compressed_utf16_string(
			     value_utf16_stream,
			     value_utf16_stream_size,
			     &( decoded_data[ 1 ] ),
			     decoded_data_size - 1,
			     &error ) != 1 )
			{
				libcerror_error_set(
				 &error,
				 LIBCERROR_ERROR_DOMAIN_RUNTIME,
				 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
				 "%s: unable to decompress run-length compressed UTF-16 string.",
				 function );

				goto on_error;
			}
#if defined( HAVE_DEBUG_OUTPUT ) && defined( HAVE_EXTRA_DEBUG_OUTPUT )
			if( libcnotify_verbose != 0 )
			{
				libcnotify_printf(
				 "%s: decompressed data:\n",
				 function );
				libcnotify_print_data(
				 value_utf16_stream,
				 value_utf16_stream_size,
				 0 );
			}
#endif
			/* Sometimes the UTF-16 stream is cut-off in the surrogate high range
			 * The last 2 bytes are ignored otherwise libuna will not convert
			 * the stream to a string
			 */
			if( ( ( value_utf16_stream[ value_utf16_stream_size - 1 ] ) >= 0xd8 )
			 && ( ( value_utf16_stream[ value_utf16_stream_size - 1 ] ) <= 0xdb ) )
			{
				value_utf16_stream_size -= 2;
			}
			memory_free(
			 decoded_data );

			decoded_data = NULL;

#if defined( HAVE_WIDE_SYSTEM_CHARACTER )
			result = libuna_utf16_string_size_from_utf16_stream(
				  value_utf16_stream,
				  value_utf16_stream_size,
				  LIBUNA_ENDIAN_LITTLE,
				  &value_string_size,
				  &error );
#else
			result = libuna_utf8_string_size_from_utf16_stream(
				  value_utf16_stream,
				  value_utf16_stream_size,
				  LIBUNA_ENDIAN_LITTLE,
				  &value_string_size,
				  &error );
#endif
			if( result != 1 )
			{
				libcerror_error_set(
				 &error,
				 LIBCERROR_ERROR_DOMAIN_RUNTIME,
				 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
				 "%s: unable to determine size of value UTF-16 stream.",
				 function );

				goto on_error;
			}
			value_string = system_string_allocate(
					value_string_size );

			if( value_string == NULL )
			{
				libcerror_error_set(
				 &error,
				 LIBCERROR_ERROR_DOMAIN_MEMORY,
				 LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
				 "%s: unable to create value string.",
				 function );

				goto on_error;
			}
#if defined( HAVE_WIDE_SYSTEM_CHARACTER )
			result = libuna_utf16_string_copy_from_utf16_stream(
				  (uint16_t *) value_string,
				  value_string_size,
				  value_utf16_stream,
				  value_utf16_stream_size,
				  LIBUNA_ENDIAN_LITTLE,
				  &error );
#else
			result = libuna_utf8_string_copy_from_utf16_stream(
				  (uint8_t *) value_string,
				  value_string_size,
				  value_utf16_stream,
				  value_utf16_stream_size,
				  LIBUNA_ENDIAN_LITTLE,
				  &error );
#endif
			if( result != 1 )
			{
				libcerror_error_set(
				 &error,
				 LIBCERROR_ERROR_DOMAIN_RUNTIME,
				 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
				 "%s: unable to retrieve value string.",
				 function );

				goto on_error;
			}
			memory_free(
			 value_utf16_stream );

			value_utf16_stream = NULL;

			libcnotify_printf(
			 "%s: decompressed data: %" PRIs_SYSTEM "\n",
			 function,
			 value_string );

			memory_free(
			 value_string );

			value_string = NULL;
		}
	}
	/* 8-bit compressed UTF-16 little-endian string
	 */
	else if( compression_type == 1 )
	{
		if( libuna_utf8_string_size_from_byte_stream(
		     &( decoded_data[ 1 ] ),
		     decoded_data_size - 1,
		     ascii_codepage,
		     &value_string_size,
		     &error ) != 1 )
		{
			libcerror_error_set(
			 &error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
			 "%s: unable to determine size of value string.",
			 function );

			goto on_error;
		}
		narrow_value_string = (uint8_t *) memory_allocate(
		                                   sizeof( uint8_t ) * value_string_size );

		if( narrow_value_string == NULL )
		{
			libcerror_error_set(
			 &error,
			 LIBCERROR_ERROR_DOMAIN_MEMORY,
			 LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
			 "%s: unable to create value string.",
			 function );

			goto on_error;
		}
		if( libuna_utf8_string_copy_from_byte_stream(
		     narrow_value_string,
		     value_string_size,
		     &( decoded_data[ 1 ] ),
		     decoded_data_size - 1,
		     ascii_codepage,
		     &error ) != 1 )
		{
			libcerror_error_set(
			 &error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
			 "%s: unable to retrieve value string.",
			 function );

			goto on_error;
		}
		memory_free(
		 decoded_data );

		decoded_data = NULL;

		libcnotify_printf(
		 "%s: decompressed data:\n",
		 function );
		libcnotify_print_data(
		 narrow_value_string,
		 narrow_value_string_size,
		 0 );

		memory_free(
		 narrow_value_string );

		narrow_value_string = NULL;
	}
	/* uncompressed data
	 */
	else if( compression_type == 4 )
	{
		libcnotify_printf(
		 "%s: decompressed data:\n",
		 function );
		libcnotify_print_data(
		 &( decoded_data[ 1 ] ),
		 decoded_data_size - 1,
		 0 );
	}
	else
	{
		fprintf(
		 stderr,
		 "Unsupported compression type: 0x%02" PRIx8 "\n",
		 compression_type );

		goto on_error;
	}
#ifdef NOWRITE
	libcfile_file_t *destination_file = NULL;
	ssize_t write_count               = 0;

	if( destination_file == NULL )
	{
		/* Open the destination file
		 */
		if( libcfile_file_initialize(
		     &destination_file,
		     &error ) != 1 )
		{
			fprintf(
			 stderr,
			 "Unable to create destination file.\n" );

			goto on_error;
		}
		if( libcfile_file_open(
		     destination_file,
		     destination,
		     LIBCFILE_OPEN_WRITE,
		     &error ) != 1 )
		{
			fprintf(
			 stderr,
			 "Unable to open destination file.\n" );

			goto on_error;
		}
	}
	write_count = libcfile_file_write_buffer(
		       destination_file,
		       decoded_data,
		       decoded_data_size,
		       &error );

	if( write_count != (ssize_t) decoded_data_size )
	{
		fprintf(
		 stderr,
		 "Unable to write to destination file.\n" );

		goto on_error;
	}
	/* Clean up
	 */
	if( destination_file != NULL )
	{
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
#endif
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
/* TODO fix to remove safe guard */
	if( uncompressed_data != NULL )
	{
		memory_free(
		 uncompressed_data );
	}
	if( decoded_data != NULL )
	{
		memory_free(
		 decoded_data );
	}
	if( buffer != NULL )
	{
		memory_free(
		 buffer );
	}
	if( result == -1 )
	{
		fprintf(
		 stdout,
		 "MS Search decoding:\tFAILURE\n" );

		return( EXIT_FAILURE );
	}
	fprintf(
	 stdout,
	 "MS Search decoding:\tSUCCESS\n" );

	return( EXIT_SUCCESS );

on_error:
	if( error != NULL )
	{
		libcnotify_print_error_backtrace(
		 error );
		libcerror_error_free(
		 &error );
	}
#ifdef NOWRITE
	if( destination_file != NULL )
	{
		libcfile_file_free(
		 &destination_file,
		 NULL );
	}
#endif
	if( uncompressed_data != NULL )
	{
		memory_free(
		 uncompressed_data );
	}
	if( decoded_data != NULL )
	{
		memory_free(
		 decoded_data );
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

