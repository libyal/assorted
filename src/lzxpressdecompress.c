/*
 * Decompresses LZXPRESS compressed data
 *
 * Copyright (C) 2008-2023, Joachim Metz <joachim.metz@gmail.com>
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

#if defined( WINAPI )

#if !defined( STATUS_SUCCESS )
#define STATUS_SUCCESS	0x00000000
#endif

#if !defined( STATUS_INVALID_PARAMETER )
#define STATUS_INVALID_PARAMETER	0xc000000d
#endif

#if !defined( STATUS_UNSUPPORTED_COMPRESSION )
#define STATUS_UNSUPPORTED_COMPRESSION	0xc000025f
#endif

#if !defined( STATUS_BAD_COMPRESSION_BUFFER )
#define STATUS_BAD_COMPRESSION_BUFFER	0xc0000242
#endif

/* Cross Windows safe version of RtlDecompressBufferEx
 * Returns 0 if successful or an error code on error
 */
NTSTATUS lzxpresscompress_RtlDecompressBufferEx(
          unsigned short CompressionFormat,
          unsigned char *UncompressedBuffer,
          unsigned long UncompressedBufferSize,
          unsigned char *CompressedBuffer,
          unsigned long CompressedBufferSize,
          unsigned long *FinalUncompressedSize,
          void *WorkSpace )
{
	FARPROC function       = NULL;
	HMODULE library_handle = NULL;
	NTSTATUS result        = 0;

	library_handle = LoadLibrary(
	                  _SYSTEM_STRING( "ntdll.dll" ) );

	if( library_handle == NULL )
	{
		return( 1 );
	}
	function = GetProcAddress(
	            library_handle,
	            (LPCSTR) "RtlDecompressBufferEx");

	if( function != NULL )
	{
		result = function(
		          CompressionFormat,
		          UncompressedBuffer,
		          UncompressedBufferSize,
		          CompressedBuffer,
		          CompressedBufferSize,
		          FinalUncompressedSize,
		          WorkSpace );
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
	fprintf( stream, "Use lzxpressdecompress to decompress LZXPRESS compressed data.\n\n" );

#if defined( WINAPI )
	fprintf( stream, "Usage: lzxpressdecompress [ -d size ] [ -o offset ] [ -s size ]\n"
	                 "                          [ -t target ] [ -1234hvV ] source\n\n" );
#else
	fprintf( stream, "Usage: lzxpressdecompress [ -d size ] [ -o offset ] [ -s size ]\n"
	                 "                          [ -t target ] [ -12hvV ] source\n\n" );
#endif

	fprintf( stream, "\tsource: the source file\n\n" );

	fprintf( stream, "\t-1:     use the LZ77 + DIRECT2 decompression method (default)\n" );
	fprintf( stream, "\t-2:     use the Huffman decompression method\n" );
#if defined( WINAPI )
	fprintf( stream, "\t-3:     use the WINAPI LZ77 + DIRECT2 decompression method\n" );
	fprintf( stream, "\t-4:     use the WINAPI Huffman decompression method\n" );
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
#if defined( HAVE_WIDE_SYSTEM_CHARACTER )
int wmain( int argc, wchar_t * const argv[] )
#else
int main( int argc, char * const argv[] )
#endif
{
	libcerror_error_t *error                 = NULL;
	libcfile_file_t *destination_file        = NULL;
	libcfile_file_t *source_file             = NULL;
	system_character_t *option_target_path   = NULL;
	system_character_t *options_string       = NULL;
	system_character_t *source               = NULL;
	uint8_t *buffer                          = NULL;
	uint8_t *uncompressed_data               = NULL;
	char *program                            = "lzxpressdecompress";
	system_integer_t option                  = 0;
	size64_t source_size                     = 0;
	size_t buffer_size                       = 0;
	size_t uncompressed_data_size            = 0;
	ssize_t read_count                       = 0;
	ssize_t write_count                      = 0;
	off_t source_offset                      = 0;
	int decompression_method                 = 1;
	int result                               = 0;
	int verbose                              = 0;

#if defined( WINAPI )
	void *workspace                          = NULL;
	unsigned short winapi_compression_method = 0;
#endif

	assorted_output_version_fprint(
	 stdout,
	 program );

#if defined( WINAPI )
	options_string = _SYSTEM_STRING( "d:ho:s:t:vV1234" );
#else
	options_string = _SYSTEM_STRING( "d:ho:s:t:vV12" );
#endif
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

			case (system_integer_t) '1':
				decompression_method = 1;

				break;

			case (system_integer_t) '2':
				decompression_method = 2;

				break;

#if defined( WINAPI )
			case (system_integer_t) '3':
				decompression_method = 3;

				break;

			case (system_integer_t) '4':
				decompression_method = 4;

				break;

#endif
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
		if( source_size <= (size64_t) source_offset )
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
	 "Starting LZXPRESS decompression of: %" PRIs_SYSTEM " at offset: %" PRIjd " (0x%08" PRIjx ").\n",
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
		result = libfwnt_lzxpress_decompress(
		          buffer,
		          (size_t) source_size,
		          uncompressed_data,
		          &uncompressed_data_size,
		          &error );
	}
	else if( decompression_method == 2 )
	{
		result = libfwnt_lzxpress_huffman_decompress(
		          buffer,
		          (size_t) source_size,
		          uncompressed_data,
		          &uncompressed_data_size,
		          &error );
	}
#if defined( WINAPI )
	else if( ( decompression_method == 3 )
	      || ( decompression_method == 4 ) )
	{
		if( decompression_method == 3 )
		{
			winapi_compression_method = COMPRESSION_FORMAT_XPRESS;
		}
		else if( decompression_method == 4 )
		{
			winapi_compression_method = COMPRESSION_FORMAT_XPRESS_HUFF;
		}
/* TODO: determine workspace size: RtlGetCompressionWorkSpaceSize */
		workspace = (void *) memory_allocate(
		                      16 * 1024 * 1024 );

		if( workspace == NULL )
		{
			fprintf(
			 stderr,
			 "Unable to create workspace.\n" );

			goto on_error;
		}
		result = lzxpresscompress_RtlDecompressBufferEx(
		          winapi_compression_method,
		          (unsigned char *) uncompressed_data,
		          (unsigned long) uncompressed_data_size,
		          (unsigned char *) buffer,
		          (unsigned long) source_size,
		          (unsigned long *) &uncompressed_data_size,
		          workspace );

		memory_free(
		 workspace );

		if( result == STATUS_SUCCESS )
		{
			result = 1;
		}
		else
		{
			switch( result )
			{
				case STATUS_INVALID_PARAMETER:
					fprintf(
					 stderr,
					 "Invalid parameter.\n" );

					break;

				case STATUS_UNSUPPORTED_COMPRESSION:
					fprintf(
					 stderr,
					 "Unsupported compression.\n" );

					break;

				case STATUS_BAD_COMPRESSION_BUFFER:
					fprintf(
					 stderr,
					 "Bad compression buffer.\n" );

					break;

				default:
					fprintf(
					 stderr,
					 "Unknown error: 0x%08x.\n",
					 result );

					break;
			}
			result = -1;
		}
	}
#endif /* defined( WINAPI ) */

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
	 "LZXPRESS decompression:\tSUCCESS\n" );

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
	 "LZXPRESS decompression:\tFAILURE\n" );

	return( EXIT_FAILURE );
}

