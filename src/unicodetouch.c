/*
 * Creates an empty file (touch) with a specific Unicode character
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
#include <byte_stream.h>
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
#include "assorted_libuna.h"
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
	fprintf( stream, "Use unicodetouch to create a file with a specific Unicode character.\n\n" );

	fprintf( stream, "Usage: unicodetouch [ -hvV ] character\n\n" );

	fprintf( stream, "\tcharacter: numeric character value\n\n" );

	fprintf( stream, "\t-h:        shows this help\n" );
	fprintf( stream, "\t-v:        verbose output to stderr\n" );
	fprintf( stream, "\t-V:        print version\n" );
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
	system_character_t character_string[ 8 ];
	system_character_t target[ 256 ];

	libcerror_error_t *error      = NULL;
	libcfile_file_t *target_file  = NULL;
	char *program                 = "unicodetouch";
	long character_value          = 0;
	system_integer_t option       = 0;
	size_t character_string_index = 0;
	ssize_t print_count           = 0;
	int result                    = 0;
	int verbose                   = 0;

	assorted_output_version_fprint(
	 stdout,
	 program );

	while( ( option = assorted_getopt(
	                   argc,
	                   argv,
	                   _SYSTEM_STRING( "hvV" ) ) ) != (system_integer_t) -1 )
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
		 "Missing character value.\n" );

		usage_fprint(
		 stdout );

		return( EXIT_FAILURE );
	}
	character_value = system_string_copy_to_long( argv[ optind ] );

	libcnotify_stream_set(
	 stderr,
	 NULL );
	libcnotify_verbose_set(
	 verbose );

	if( memory_set(
	     character_string,
	     0,
	     8 * sizeof( system_character_t ) ) == NULL )
	{
		fprintf(
		 stderr,
		 "Unable to clear character string.\n" );

		goto on_error;
	}
#if defined( HAVE_WIDE_SYSTEM_CHARACTER )
	/* Using UCS-2 to support unpaired UTF-16 surrogates
	 */
	result = libuna_unicode_character_copy_to_ucs2(
	          character_value,
	          (libuna_utf16_character_t *) character_string,
	          8,
	          &character_string_index,
	          &error );
#else
	/* Using RFC 2279 UTF-8 to support unpaired UTF-16 surrogates
	 */
	result = libuna_unicode_character_copy_to_utf8_rfc2279(
	          character_value,
	          (libuna_utf8_character_t *) character_string,
	          8,
	          &character_string_index,
	          &error );
#endif
	if( result != 1 )
	{
		fprintf(
		 stderr,
		 "Unable to create Unicode character string.\n" );

		goto on_error;
	}
	if( memory_set(
	     target,
	     0,
	     256 * sizeof( system_character_t ) ) == NULL )
	{
		fprintf(
		 stderr,
		 "Unable to clear target file name.\n" );

		goto on_error;
	}
	print_count = system_string_sprintf(
	               target,
	               256,
	               _SYSTEM_STRING( "unicode_U+%08lx_%s" ),
	               character_value,
	               character_string ) ;

	if( ( print_count < 0 )
	 || ( (size_t) print_count > 256 ) )
	{
		fprintf(
		 stderr,
		 "Unable to create target file name.\n" );

		goto on_error;
	}
	/* Open the target file
	 */
	if( libcfile_file_initialize(
	     &target_file,
	     &error ) != 1 )
	{
		fprintf(
		 stderr,
		 "Unable to create target file.\n" );

		goto on_error;
	}
#if defined( HAVE_WIDE_SYSTEM_CHARACTER )
	result = libcfile_file_open_wide(
	          target_file,
	          target,
	          LIBCFILE_OPEN_WRITE,
	          &error );
#else
	result = libcfile_file_open(
	          target_file,
	          target,
	          LIBCFILE_OPEN_WRITE,
	          &error );
#endif
 	if( result != 1 )
	{
		fprintf(
		 stderr,
		 "Unable to open target file.\n" );

		goto on_error;
	}
	/* Clean up
	 */
	if( libcfile_file_close(
	     target_file,
	     &error ) != 0 )
	{
		fprintf(
		 stderr,
		 "Unable to close target file.\n" );

		goto on_error;
	}
	if( libcfile_file_free(
	     &target_file,
	     &error ) != 1 )
	{
		fprintf(
		 stderr,
		 "Unable to free target file.\n" );

		goto on_error;
	}
	return( EXIT_SUCCESS );

on_error:
	if( error != NULL )
	{
		libcnotify_print_error_backtrace(
		 error );
		libcerror_error_free(
		 &error );
	}
	if( target_file != NULL )
	{
		libcfile_file_free(
		 &target_file,
		 NULL );
	}
	return( EXIT_FAILURE );
}

