/*
 * Exports Unicode and ASCII (byte stream) text
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

export_handle_t *unaexport_export_handle = NULL;
int unaexport_abort                      = 0;

/* Prints the executable usage information
 */
void usage_fprint(
      FILE *stream )
{
	if( stream == NULL )
	{
		return;
	}
	fprintf( stream, "Use unaexport to export text in one encoding to another.\n\n" );

	fprintf( stream, "Usage: unaexport [ -c codepage ] [ -i input_format ] [ -n newline_conversion ]\n"
	                 "                 [ -o output_format ] [ -BhlqvV ] source destination\n\n" );

	fprintf( stream, "\tsource:      the source file\n" );
	fprintf( stream, "\tdestination: the destination file\n\n" );

	fprintf( stream, "\t-B:          do not export a byte order mark (BOM)\n" );
	fprintf( stream, "\t-c:          codepage of byte-stream, options: ascii (default),\n"
	                 "\t             iso-8559-1, iso-8559-2, iso-8559-3, iso-8559-4,\n"
	                 "\t             iso-8559-5, iso-8559-6, iso-8559-7, iso-8559-8,\n"
	                 "\t             iso-8559-9, iso-8559-10, iso-8559-11, iso-8559-13,\n"
	                 "\t             iso-8559-14, iso-8559-15, iso-8559-16, koi8-r, koi8-u,\n"
	                 "\t             windows-874, windows-1250, windows-1251, windows-1252,\n"
	                 "\t             windows-1253, windows-1254, windows-1255, windows-1256\n"
	                 "\t             windows-1257 or windows-1258\n" );
	fprintf( stream, "\t-h:          shows this help\n" );
	fprintf( stream, "\t-i:          input format, options: auto-detect (default), byte-stream,\n"
	                 "\t             utf7, utf8, utf16be, utf16le, utf32be or utf32le\n" );
	fprintf( stream, "\t-l:          list information about the codepages\n" );
	fprintf( stream, "\t-n:          convert newline characters, options: none (default), cr,\n"
	                 "\t             crlf or lf\n" );
	fprintf( stream, "\t-o:          output format, options: byte-stream, utf7, utf8 (default),\n"
	                 "\t             utf16be, utf16le, utf32be or utf32le\n" );
	fprintf( stream, "\t-q:          quiet shows no status information\n" );
	fprintf( stream, "\t-v:          verbose output to stderr\n" );
	fprintf( stream, "\t-V:          print version\n" );
}

/* Signal handler for unaexport
 */
void unaexport_signal_handler(
      assorted_signal_t signal ASSORTED_ATTRIBUTE_UNUSED )
{
	libcerror_error_t *error = NULL;
	static char *function   = "unaexport_signal_handler";

	ASSORTED_UNREFERENCED_PARAMETER( signal )

	unaexport_abort = 1;

	if( unaexport_export_handle != NULL )
	{
		if( export_handle_signal_abort(
		     unaexport_export_handle,
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
	libcerror_error_t *error                        = NULL;
	system_character_t *destination_filename        = NULL;
	system_character_t *option_byte_stream_codepage = NULL;
	system_character_t *option_input_format         = NULL;
	system_character_t *option_newline_conversion   = NULL;
	system_character_t *option_output_format        = NULL;
	system_character_t *source_filename             = NULL;
	char *program                                   = "unaexport";
	system_integer_t option                         = 0;
	uint8_t export_byte_order_mark                  = 1;
	uint8_t print_status_information                = 1;
	int verbose                                     = 0;
	int result                                      = 0;

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
	                   _SYSTEM_STRING( "Bc:hi:ln:o:qvV" ) ) ) != (system_integer_t) -1 )
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

			case (system_integer_t) 'B':
				export_byte_order_mark = 0;

				break;

			case (system_integer_t) 'c':
				option_byte_stream_codepage = optarg;

				break;

			case (system_integer_t) 'h':
				usage_fprint(
				 stdout );

				return( EXIT_SUCCESS );

			case (system_integer_t) 'i':
				option_input_format = optarg;

				break;

			case (system_integer_t) 'l':
				export_handle_codepages_fprint(
				 stdout );

				return( EXIT_SUCCESS );

			case (system_integer_t) 'n':
				option_newline_conversion = optarg;

				break;

			case (system_integer_t) 'o':
				option_output_format = optarg;

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
	     &unaexport_export_handle,
	     UNAEXPORT_HANDLE_MODE_TEXT_ENCODING,
	     &error ) != 1 )
	{
		fprintf(
		 stderr,
		 "Unable to create export handle.\n" );

		goto on_error;
	}
	if( unaexport_export_handle == NULL )
	{
		fprintf(
		 stderr,
		 "Unable to create export handle.\n" );

		goto on_error;
	}
	if( assorted_signal_attach(
	     unaexport_signal_handler,
	     &error ) != 1 )
	{
		fprintf(
		 stderr,
		 "Unable to attach signal handler.\n" );

		goto on_error;
	}
	if( export_handle_set_string(
	     unaexport_export_handle,
	     source_filename,
	     &( unaexport_export_handle->source_filename ),
	     &( unaexport_export_handle->source_filename_size ),
	     &error ) != 1 )
	{
		fprintf(
		 stderr,
		 "Unable to set source filename.\n" );

		goto on_error;
	}
	if( export_handle_set_string(
	     unaexport_export_handle,
	     destination_filename,
	     &( unaexport_export_handle->destination_filename ),
	     &( unaexport_export_handle->destination_filename_size ),
	     &error ) != 1 )
	{
		fprintf(
		 stderr,
		 "Unable to set destination filename.\n" );

		goto on_error;
	}
	if( option_input_format != NULL )
	{
		result = export_handle_set_input_format(
			  unaexport_export_handle,
			  option_input_format,
			  &error );

		if( result == -1 )
		{
			fprintf(
			 stderr,
			 "Unable to set input format.\n" );

			goto on_error;
		}
		else if( result == 0 )
		{
			fprintf(
			 stderr,
			 "Unsupported input format defaulting to: auto-detect.\n" );
		}
	}
	if( option_output_format != NULL )
	{
		result = export_handle_set_output_format(
			  unaexport_export_handle,
			  option_output_format,
			  &error );

		if( result == -1 )
		{
			fprintf(
			 stderr,
			 "Unable to set output format.\n" );

			goto on_error;
		}
		else if( result == 0 )
		{
			fprintf(
			 stderr,
			 "Unsupported output format defaulting to: utf8.\n" );
		}
	}
	if( option_newline_conversion != NULL )
	{
		result = export_handle_set_newline_conversion(
			  unaexport_export_handle,
			  option_newline_conversion,
			  &error );

		if( result == -1 )
		{
			fprintf(
			 stderr,
			 "Unable to set newline conversion.\n" );

			goto on_error;
		}
		else if( result == 0 )
		{
			fprintf(
			 stderr,
			 "Unsupported newline conversion defaulting to: none.\n" );
		}
	}
	unaexport_export_handle->text_export_byte_order_mark = export_byte_order_mark;

	if( option_byte_stream_codepage != NULL )
	{
		result = export_handle_set_byte_stream_codepage(
			  unaexport_export_handle,
		          option_byte_stream_codepage,
			  &error );

		if( result == -1 )
		{
			fprintf(
			 stderr,
			 "Unable to set byte stream codepage.\n" );

			goto on_error;
		}
		else if( result == 0 )
		{
			fprintf(
			 stderr,
			 "Unsupported byte stream codepage defaulting to: ascii.\n" );
		}
	}
	if( export_handle_print_parameters(
	     unaexport_export_handle,
	     &error ) != 1 )
	{
		fprintf(
		 stderr,
		 "Unable to print export parameters.\n" );

		goto on_error;
	}
	if( export_handle_open_input(
	     unaexport_export_handle,
	     &error ) != 1 )
	{
		fprintf(
		 stderr,
		 "Unable to open source file.\n" );

		goto on_error;
	}
	if( export_handle_open_output(
	     unaexport_export_handle,
	     &error ) != 1 )
	{
		fprintf(
		 stderr,
		 "Unable to open destination file.\n" );

		goto on_error;
	}
	result = export_handle_export_input(
		  unaexport_export_handle,
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
	     unaexport_export_handle,
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

		goto on_error;
	}
	if( export_handle_free(
	     &unaexport_export_handle,
	     &error ) != 1 )
	{
		fprintf(
		 stderr,
		 "Unable to free export handle.\n" );

		goto on_error;
	}
	if( unaexport_abort != 0 )
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
	if( unaexport_export_handle != NULL )
	{
		export_handle_close(
		 unaexport_export_handle,
		 NULL );
		export_handle_free(
		 &unaexport_export_handle,
		 NULL );
	}
	return( EXIT_FAILURE );
}

