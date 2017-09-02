/*
 * zcompress compresses zlib compressed data
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
#include <narrow_string.h>
#include <system_string.h>
#include <types.h>

#if defined( HAVE_STDLIB_H )
#include <stdlib.h>
#endif

#if defined( HAVE_ZLIB ) || defined( ZLIB_DLL )
#include <zlib.h>
#endif

#include "assorted_libcerror.h"
#include "assorted_libcfile.h"
#include "assorted_libcnotify.h"
#include "assorted_libcsystem.h"
#include "assorted_output.h"
#include "deflate.h"

/* Prints the executable usage information
 */
void usage_fprint(
      FILE *stream )
{
	if( stream == NULL )
	{
		return;
	}
	fprintf( stream, "Use zcompress to compress data as zlib compressed data.\n\n" );

	fprintf( stream, "Usage: zcompress [ -l compression_level ] [ -o offset ]\n"
	                 "                 [ -s size ] [ -12hvV ] source\n\n" );

	fprintf( stream, "\tsource: the source file\n\n" );

	fprintf( stream, "\t-1:     use the zlib compression method\n" );
	fprintf( stream, "\t-2:     use the internal compression method (default)\n" );
	fprintf( stream, "\t-h:     shows this help\n" );
	fprintf( stream, "\t-l:     compression level (default is -1)\n" );
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

	libcerror_error_t *error          = NULL;
	libcfile_file_t *destination_file = NULL;
	libcfile_file_t *source_file      = NULL;
	system_character_t *source        = NULL;
	uint8_t *buffer                   = NULL;
	uint8_t *compressed_data          = NULL;
	char *program                     = "zcompress";
	system_integer_t option           = 0;
	size64_t source_size              = 0;
	size_t compressed_data_size       = 0;
	ssize_t read_count                = 0;
	ssize_t write_count               = 0;
	off_t source_offset               = 0;
	int compression_method            = 2;
	int print_count                   = 0;
	int result                        = 0;
	int verbose                       = 0;

#if !defined( HAVE_ZLIB ) && !defined( ZLIB_DLL )
	int compression_level             = -1;

#else
	int compression_level             = Z_DEFAULT_COMPRESSION;

#if defined( USE_COMPRESS2 )
	uLongf zlib_compressed_data_size  = 0;

#else
	z_stream zlib_stream;

	int zlib_flush                    = Z_FINISH;

#if !defined( USE_DEFLATE_INIT )
	int zlib_memLevel                 = 8;
	int zlib_method                   = Z_DEFLATED;
	int zlib_strategy                 = Z_DEFAULT_STRATEGY;
	int zlib_windowBits               = 15;

#endif /* !defined( USE_DEFLATE_INIT ) */
#endif /* defined( USE_COMPRESS2 ) */
#endif /* !defined( HAVE_ZLIB ) && !defined( ZLIB_DLL ) */

	assorted_output_version_fprint(
	 stdout,
	 program );

	while( ( option = libcsystem_getopt(
	                   argc,
	                   argv,
	                   _SYSTEM_STRING( "12hl:o:s:vV" ) ) ) != (system_integer_t) -1 )
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
				compression_method = 1;

				break;

			case '2':
				compression_method = 2;

				break;

			case 'h':
				usage_fprint(
				 stdout );

				return( EXIT_SUCCESS );

			case 'l':
				compression_level = atol( optarg );

				break;

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
	compressed_data_size = source_size * 2;

	compressed_data = (uint8_t *) memory_allocate(
	                               sizeof( uint8_t ) * compressed_data_size );

	if( compressed_data == NULL )
	{
		fprintf(
		 stderr,
		 "Unable to create compressed data buffer.\n" );

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
	               "%s.zcompressed",
	               source );

	if( ( print_count < 0 )
	 || ( print_count > 128 ) )
	{
		fprintf(
		 stderr,
		 "Unable to set destination filename.\n" );

		goto on_error;
	}
	/* Read and compress the data
	 */
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
	if( compression_method == 1 )
	{
#if !defined( HAVE_ZLIB ) && !defined( ZLIB_DLL )
		fprintf(
		 stderr,
		 "Missing zlib support.\n" );

		goto on_error;

#elif defined( USE_COMPRESS2 )
		zlib_compressed_data_size = (uLongf) compressed_data_size;

		if( compress2(
		     (Bytef *) compressed_data,
		     &zlib_compressed_data_size,
		     (Bytef *) buffer,
		     (uLong) source_size,
		     compression_level ) != Z_OK )
		{
			fprintf(
			 stderr,
			 "Unable to compress data.\n" );

			goto on_error;
		}
		compressed_data_size = (size_t) zlib_compressed_data_size;

#else
		zlib_stream.opaque = Z_NULL;
		zlib_stream.zalloc = Z_NULL;
		zlib_stream.zfree  = Z_NULL;

#if defined( USE_DEFLATE_INIT )
		if( deflateInit(
		     &zlib_stream,
		     compression_level ) != Z_OK )

#else
		if( deflateInit2(
		     &zlib_stream,
		     compression_level,
		     zlib_method,
		     zlib_windowBits,
		     zlib_memLevel,
		     zlib_strategy ) != Z_OK )

#endif /* defined( USE_DEFLATE_INIT ) */
		{
			fprintf(
			 stderr,
			 "Unable to compress data - deflateInit2.\n" );

			goto on_error;
		}
		zlib_stream.avail_in  = (uInt) source_size;
		zlib_stream.next_in   = (Bytef *) buffer;
		zlib_stream.avail_out = (uInt) compressed_data_size;
		zlib_stream.next_out  = (Bytef *) compressed_data;

		result = deflate(
			  &zlib_stream,
			  zlib_flush );

		if( result < 0 )
		{
			fprintf(
			 stderr,
			 "Unable to compress data - deflate (%d, %s).\n",
			 result,
			 zlib_stream.msg );

			goto on_error;
		}
		result = deflateEnd(
		          &zlib_stream );

		if( result != Z_OK )
		{
			fprintf(
			 stderr,
			 "Unable to compress data - deflateEnd (%d, %s).\n",
			 result,
			 zlib_stream.msg );

			goto on_error;
		}
		compressed_data_size = zlib_stream.total_out;

#endif /* !defined( HAVE_ZLIB ) && !defined( ZLIB_DLL ) */
	}
	else if( compression_method == 2 )
	{
		if( deflate_compress(
		     buffer,
		     source_size,
		     compression_level,
		     compressed_data,
		     &compressed_data_size,
		     &error ) != 1 )
		{
			fprintf(
			 stderr,
			 "Unable to compress data.\n" );

			goto on_error;
		}
	}
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
	write_count = libcfile_file_write_buffer(
		       destination_file,
		       compressed_data,
		       compressed_data_size,
		       &error );

	if( write_count != (ssize_t) compressed_data_size )
	{
		fprintf(
		 stderr,
		 "Unable to write to destination file.\n" );

		goto on_error;
	}
	/* Clean up
	 */
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
	 compressed_data );

	memory_free(
	 buffer );

	if( result == -1 )
	{
		fprintf(
		 stdout,
		 "Z compression:\tFAILURE\n" );

		return( EXIT_FAILURE );
	}
	fprintf(
	 stdout,
	 "Z compression:\tSUCCESS\n" );

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
	if( compressed_data != NULL )
	{
		memory_free(
		 compressed_data );
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

