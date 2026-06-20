/*
 * De/Encodes data from/to different base encodings
 *
 * Copyright (C) 2008-2026, Joachim Metz <joachim.metz@gmail.com>
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
#include <wide_string.h>

#if defined( HAVE_FCNTL_H ) || defined( WINAPI )
#include <fcntl.h>
#endif

#if defined( HAVE_IO_H ) || defined( WINAPI )
#include <io.h>
#endif

#if defined( HAVE_STDLIB_H ) || defined( WINAPI )
#include <stdlib.h>
#endif

#if defined( HAVE_UNISTD_H )
#include <unistd.h>
#endif

#include "assorted_getopt.h"
#include "assorted_libcerror.h"
#include "assorted_libclocale.h"
#include "assorted_libcnotify.h"
#include "assorted_libuna.h"
#include "assorted_output.h"
#include "assorted_signal.h"
#include "assorted_unused.h"
#include "unacommon.h"
#include "unaexport_handle.h"

export_handle_t *unabase_export_handle = NULL;
int unabase_abort                      = 0;

/* Prints the executable usage information
 */
void usage_fprint(
      FILE *stream )
{
	if( stream == NULL )
	{
		return;
	}
	fprintf( stream, "Use unabase to de/encode data form/to different base\n"
	                 "encodings\n\n" );

	fprintf( stream, "Usage: unabase [ -e encoding ] [ -m mode ] [ -hqvV ] source\n"
	                 "               destination\n\n" );

	fprintf( stream, "\tsource:      the source file\n" );
	fprintf( stream, "\tdestination: the destination file\n\n" );

	fprintf( stream, "\t-e:          encoding, options: base16, base32, base32hex,\n"
	                 "\t             base64 (default), base64url\n" );
	fprintf( stream, "\t-m:          encoding mode, options: decode, encode (default)\n" );
	fprintf( stream, "\t-h:          shows this help\n" );
	fprintf( stream, "\t-q:          quiet shows no status information\n" );
	fprintf( stream, "\t-v:          verbose output to stderr\n" );
	fprintf( stream, "\t-V:          print version\n" );
}

/* Signal handler for unabase
 */
void unabase_signal_handler(
      assorted_signal_t signal ASSORTED_ATTRIBUTE_UNUSED )
{
	libcerror_error_t *error = NULL;
	static char *function   = "unabase_signal_handler";

	ASSORTED_UNREFERENCED_PARAMETER( signal )

	unabase_abort = 1;

	if( unabase_export_handle != NULL )
	{
		if( export_handle_signal_abort(
		     unabase_export_handle,
		     &error ) != 1 )
		{
			libcnotify_printf(
			 "%s: unable to signal export handle to abort.\n",
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
	system_character_t *destination_filename = NULL;
	system_character_t *option_encoding      = NULL;
	system_character_t *option_encoding_mode = NULL;
	system_character_t *source_filename      = NULL;
	char *program                            = "unabase";
	system_integer_t option                  = 0;
	uint8_t print_status_information         = 1;
	int result                               = 0;
	int verbose                              = 0;

#if defined( __MINGW32__ ) && defined( HAVE_MINGW_BINMODE )
	_setmode( _fileno( stdout ), _O_BINARY );
	_setmode( _fileno( stderr ), _O_BINARY );
#endif

	libcnotify_stream_set(
	 stderr,
	 NULL );
	libcnotify_verbose_set(
	 1 );

	if( libclocale_initialize(
	     "assorted",
	     &error ) != 1 )
	{
		fprintf(
		 stderr,
		 "Unable to initialize locale values.\n" );

		goto on_error;
	}
	if( assorted_output_initialize(
	     _IONBF,
	     &error ) != 1 )
	{
		fprintf(
		 stderr,
		 "Unable to initialize output settings.\n" );

		goto on_error;
	}
	assorted_output_version_fprint(
	 stdout,
	 program );

	while( ( option = assorted_getopt(
	                   argc,
	                   argv,
	                   _SYSTEM_STRING( "e:hm:qvV" ) ) ) != (system_integer_t) -1 )
	{
		switch( option )
		{
			case (system_integer_t) '?':
			default:
				fprintf(
				 stderr,
				 "Invalid argument: %" PRIs_SYSTEM "\n",
				 argv[ optind - 1 ] );

				usage_fprint(
				 stdout );

				goto on_error;

			case (system_integer_t) 'h':
				usage_fprint(
				 stdout );

				return( EXIT_SUCCESS );

			case (system_integer_t) 'e':
				option_encoding = optarg;

				break;

			case (system_integer_t) 'm':
				option_encoding_mode = optarg;

				break;

			case (system_integer_t) 'q':
				print_status_information = 0;

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
		 "Missing source.\n" );

		usage_fprint(
		 stdout );

		return( EXIT_FAILURE );
	}
	source_filename = argv[ optind++ ];

	if( optind == argc )
	{
		fprintf(
		 stderr,
		 "Missing destination.\n" );

		usage_fprint(
		 stdout );

		return( EXIT_FAILURE );
	}
	destination_filename = argv[ optind++ ];

	libcnotify_verbose_set(
	 verbose );

	if( export_handle_initialize(
	     &unabase_export_handle,
	     UNAEXPORT_HANDLE_MODE_BASE_ENCODING,
	     &error ) != 1 )
	{
		fprintf(
		 stderr,
		 "Unable to create export handle.\n" );

		goto on_error;
	}
	if( assorted_signal_attach(
	     unabase_signal_handler,
	     &error ) != 1 )
	{
		fprintf(
		 stderr,
		 "Unable to attach signal handler.\n" );

		libcnotify_print_error_backtrace(
		 error );
		libcerror_error_free(
		 &error );
	}
	if( export_handle_set_string(
	     unabase_export_handle,
	     source_filename,
	     &( unabase_export_handle->source_filename ),
	     &( unabase_export_handle->source_filename_size ),
	     &error ) != 1 )
	{
		fprintf(
		 stderr,
		 "Unable to set source filename.\n" );

		goto on_error;
	}
	if( export_handle_set_string(
	     unabase_export_handle,
	     destination_filename,
	     &( unabase_export_handle->destination_filename ),
	     &( unabase_export_handle->destination_filename_size ),
	     &error ) != 1 )
	{
		fprintf(
		 stderr,
		 "Unable to set destination filename.\n" );

		goto on_error;
	}
	if( option_encoding != NULL )
	{
		result = export_handle_set_encoding(
			  unabase_export_handle,
			  option_encoding,
			  &error );

		if( result == -1 )
		{
			fprintf(
			 stderr,
			 "Unable to set encoding.\n" );

			goto on_error;
		}
		else if( result == 0 )
		{
			fprintf(
			 stderr,
			 "Unsupported encoding defaulting to: base64.\n" );
		}
	}
	if( option_encoding_mode != NULL )
	{
		result = export_handle_set_encoding_mode(
			  unabase_export_handle,
			  option_encoding_mode,
			  &error );

		if( result == -1 )
		{
			fprintf(
			 stderr,
			 "Unable to set encoding mode.\n" );

			goto on_error;
		}
		else if( result == 0 )
		{
			fprintf(
			 stderr,
			 "Unsupported encoding mode defaulting to: encode.\n" );
		}
	}
	if( export_handle_print_parameters(
	     unabase_export_handle,
	     &error ) != 1 )
	{
		fprintf(
		 stderr,
		 "Unable to print export parameters.\n" );

		goto on_error;
	}
	if( export_handle_open_input(
	     unabase_export_handle,
	     &error ) != 1 )
	{
		fprintf(
		 stderr,
		 "Unable to open source file.\n" );

		goto on_error;
	}
	if( export_handle_open_output(
	     unabase_export_handle,
	     &error ) != 1 )
	{
		fprintf(
		 stderr,
		 "Unable to open destination file.\n" );

		goto on_error;
	}
	result = export_handle_export_input(
		  unabase_export_handle,
		  print_status_information,
		  &error );

	if( result != 1 )
	{
		fprintf(
		 stderr,
		 "Unable to export input.\n" );

		libcnotify_print_error_backtrace(
		 error );
		libcerror_error_free(
		 &error );
	}
	if( export_handle_close(
	     unabase_export_handle,
	     &error ) != 0 )
	{
		fprintf(
		 stderr,
		 "Unable to close export handle.\n" );

		goto on_error;
	}
	if( assorted_signal_detach(
	     &error ) != 1 )
	{
		fprintf(
		 stderr,
		 "Unable to detach signal handler.\n" );

		libcnotify_print_error_backtrace(
		 error );
		libcerror_error_free(
		 &error );
	}
	if( export_handle_free(
	     &unabase_export_handle,
	     &error ) != 1 )
	{
		fprintf(
		 stderr,
		 "Unable to free export handle.\n" );

		goto on_error;
	}
	if( unabase_abort != 0 )
	{
		fprintf(
		 stdout,
		 "%" PRIs_SYSTEM ": ABORTED\n",
		 program );

		return( EXIT_FAILURE );
	}
	if( result != 1 )
	{
		fprintf(
		 stdout,
		 "%" PRIs_SYSTEM ": FAILURE\n",
		 program );

		return( EXIT_FAILURE );
	}
	fprintf(
	 stdout,
	 "%" PRIs_SYSTEM ": SUCCESS\n",
	 program );

	return( EXIT_SUCCESS );

on_error:
	if( error != NULL )
	{
		libcnotify_print_error_backtrace(
		 error );
		libcerror_error_free(
		 &error );
	}
	if( unabase_export_handle != NULL )
	{
		export_handle_close(
		 unabase_export_handle,
		 NULL );
		export_handle_free(
		 &unabase_export_handle,
		 NULL );
	}
	return( EXIT_FAILURE );
}

