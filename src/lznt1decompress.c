/*
 * Decompresses LZNT1 compressed data
 *
 * Copyright (C) 2008-2016, Joachim Metz <joachim.metz@gmail.com>
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
#include <types.h>

#if defined( HAVE_STDLIB_H )
#include <stdlib.h>
#endif

#include "assorted_libcerror.h"
#include "assorted_libcfile.h"
#include "assorted_libcnotify.h"
#include "assorted_libcstring.h"
#include "assorted_libcsystem.h"
#include "assorted_libfwnt.h"
#include "assorted_output.h"

#if defined( WINAPI )

/* Cross Windows safe version of RtlDecompressBuffer
 * Returns 0 if successful or an error code on error
 */
NTSTATUS lznt1compress_RtlDecompressBuffer(
          unsigned short CompressionFormat,
          unsigned char *UncompressedBuffer,
          unsigned long UncompressedBufferSize,
          unsigned char *CompressedBuffer,
          unsigned long CompressedBufferSize,
          unsigned long *FinalUncompressedSize )
{
	FARPROC function       = NULL;
	HMODULE library_handle = NULL;
	NTSTATUS result        = 0;

	library_handle = LoadLibrary(
	                  _LIBCSTRING_SYSTEM_STRING( "ntdll.dll" ) );

	if( library_handle == NULL )
	{
		return( 1 );
	}
	function = GetProcAddress(
	            library_handle,
	            (LPCSTR) "RtlDecompressBuffer");

	if( function != NULL )
	{
		result = function(
		          CompressionFormat,
		          UncompressedBuffer,
		          UncompressedBufferSize,
		          CompressedBuffer,
		          CompressedBufferSize,
		          FinalUncompressedSize );
	}
	/* This call should be after using the function
	 * in most cases ntdll.dll will still be available after free
	 */
	if( FreeLibrary(
	     library_handle) != TRUE )
	{
		result = 1;
	}
	return( result );
}

#endif /* defined( WINAPI ) */

/* Prints the executable usage information
 */
void usage_fprint(
      FILE *stream )
{
	if( stream == NULL )
	{
		return;
	}
	fprintf( stream, "Use lznt1decompress to decompress LZNT1 compressed data.\n\n" );

#if defined( WINAPI )
	fprintf( stream, "Usage: lznt1decompress [ -d size ] [ -o offset ] [ -s size ]\n"
	                 "                       [ -t target ] [ -12hvV ] source\n\n" );
#else
	fprintf( stream, "Usage: lznt1decompress [ -d size ] [ -o offset ] [ -s size ]\n"
	                 "                       [ -t target ] [ -1hvV ] source\n\n" );
#endif

	fprintf( stream, "\tsource: the source file\n\n" );

	fprintf( stream, "\t-1:     use the LZNT1 decompression method (default)\n" );
#if defined( WINAPI )
	fprintf( stream, "\t-2:     use the WINAPI LZNT1 decompression method\n" );
#endif
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

/* The main program
 */
#if defined( LIBCSTRING_HAVE_WIDE_SYSTEM_CHARACTER )
int wmain( int argc, wchar_t * const argv[] )
#else
int main( int argc, char * const argv[] )
#endif
{
	libcerror_error_t *error                          = NULL;
	libcfile_file_t *destination_file                 = NULL;
	libcfile_file_t *source_file                      = NULL;
	libcstring_system_character_t *option_target_path = NULL;
	libcstring_system_character_t *source             = NULL;
	uint8_t *buffer                                   = NULL;
	uint8_t *uncompressed_data                        = NULL;
	char *program                                     = "lznt1decompress";
	libcstring_system_integer_t option                = 0;
	size64_t source_size                              = 0;
	off_t source_offset                               = 0;
	size_t buffer_size                                = 0;
	size_t uncompressed_data_size                     = 0;
	ssize_t read_count                                = 0;
	ssize_t write_count                               = 0;
	int decompression_method                          = 1;
	int result                                        = 0;
	int verbose                                       = 0;

#if defined( WINAPI )
	unsigned short winapi_compression_method          = 0;
#endif

	assorted_output_version_fprint(
	 stdout,
	 program );

#if defined( WINAPI )
	while( ( option = libcsystem_getopt(
	                   argc,
	                   argv,
	                   _LIBCSTRING_SYSTEM_STRING( "d:ho:s:t:vV12" ) ) ) != (libcstring_system_integer_t) -1 )
#else
	while( ( option = libcsystem_getopt(
	                   argc,
	                   argv,
	                   _LIBCSTRING_SYSTEM_STRING( "d:ho:s:t:vV1" ) ) ) != (libcstring_system_integer_t) -1 )
#endif
	{
		switch( option )
		{
			case (libcstring_system_integer_t) '?':
			default:
				fprintf(
				 stderr,
				 "Invalid argument: %" PRIs_LIBCSTRING_SYSTEM "\n",
				 argv[ optind ] );

				usage_fprint(
				 stdout );

				return( EXIT_FAILURE );

			case (libcstring_system_integer_t) '1':
				decompression_method = 1;

				break;

#if defined( WINAPI )
			case (libcstring_system_integer_t) '2':
				decompression_method = 2;

				break;

#endif
			case (libcstring_system_integer_t) 'd':
				uncompressed_data_size = atol( optarg );

				break;

			case (libcstring_system_integer_t) 'h':
				usage_fprint(
				 stdout );

				return( EXIT_SUCCESS );

			case (libcstring_system_integer_t) 'o':
				source_offset = atol( optarg );

				break;

			case (libcstring_system_integer_t) 's':
				source_size = atol( optarg );

				break;

			case (libcstring_system_integer_t) 't':
				option_target_path = optarg;

				break;

			case (libcstring_system_integer_t) 'v':
				verbose = 1;

				break;

			case (libcstring_system_integer_t) 'V':
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
#if defined( LIBCSTRING_HAVE_WIDE_SYSTEM_CHARACTER )
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
		if( source_size <= source_offset )
		{
			fprintf(
			 stderr,
			 "Invalid source size value is less equal than source offset.\n" );

			goto on_error;
		}
		source_size -= source_offset;
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
	buffer_size = source_size;

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
		uncompressed_data_size = 65536;
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
	 "Starting LZNT1 decompression of: %" PRIs_LIBCSTRING_SYSTEM " at offset: %" PRIjd " (0x%08" PRIjx ").\n",
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
	/* Decompress the data
	 */
	if( option_target_path == NULL )
	{
		fprintf(
		 stderr,
		 "Compressed data:\n" );

		libcnotify_print_data(
		 buffer,
		 source_size,
		 LIBCNOTIFY_PRINT_DATA_FLAG_GROUP_DATA );
	}
	if( decompression_method == 1 )
	{
		result = libfwnt_lznt1_decompress(
		          buffer,
		          (size_t) source_size,
		          uncompressed_data,
		          &uncompressed_data_size,
		          &error );
	}
#if defined( WINAPI )
	else if( decompression_method == 2 )
	{
		result = lznt1compress_RtlDecompressBuffer(
		          COMPRESSION_FORMAT_LZNT1,
		          (unsigned char *) uncompressed_data,
		          (unsigned long) uncompressed_data_size,
		          (unsigned char *) buffer,
		          (unsigned long) source_size,
		          (unsigned long *) &uncompressed_data_size );

		if( result != 0 )
		{
			result = -1;
		}
		else
		{
			result = 1;
		}
	}
#endif
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
	if( option_target_path == NULL )
	{
		fprintf(
		 stderr,
		 "Uncompressed data:\n" );

		libcnotify_print_data(
		 uncompressed_data,
		 uncompressed_data_size,
		 LIBCNOTIFY_PRINT_DATA_FLAG_GROUP_DATA );
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
#if defined( LIBCSTRING_HAVE_WIDE_SYSTEM_CHARACTER )
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
			       uncompressed_data,
			       uncompressed_data_size,
			       &error );

		if( write_count != (ssize_t) uncompressed_data_size )
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
	 uncompressed_data );

	uncompressed_data = NULL;

	memory_free(
	 buffer );

	buffer = NULL;

	fprintf(
	 stdout,
	 "LZNT1 decompression:\tSUCCESS\n" );

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
	if( source_file != NULL )
	{
		libcfile_file_free(
		 &source_file,
		 NULL );
	}
	fprintf(
	 stdout,
	 "LZNT1 decompression:\tFAILURE\n" );

	return( EXIT_FAILURE );
}

