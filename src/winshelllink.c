/*
 * Determines a Windows Shell Link from a path
 *
 * Copyright (C) 2008-2024, Joachim Metz <joachim.metz@gmail.com>
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

#if defined( WINAPI )
#include <windows.h>
#include <winnls.h>
#include <shobjidl.h>
#include <objbase.h>
#include <objidl.h>
#include <shlguid.h>
#endif

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
	fprintf( stream, "Use winshelllink to determine a Shell Link from a path.\n\n" );

	fprintf( stream, "Usage: winshelllink [ -12hvV ] path\n\n" );

	fprintf( stream, "\tpath: the path to determine the shell link of.\n" );

	fprintf( stream, "\t-h:   shows this help\n" );
	fprintf( stream, "\t-v:   verbose output to stderr\n" );
	fprintf( stream, "\t-V:   print version\n" );
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
	libcerror_error_t *error           = NULL;
	system_character_t *options_string = NULL;
	system_character_t *path           = NULL;
	char *program                      = "winshelllink";
	system_integer_t option            = 0;
	int verbose                        = 0;

#if defined( WINAPI )
	IPersistFile *persist_file         = NULL;
	IShellLink *shell_link             = NULL;
	HRESULT result                     = 0;
#endif

	assorted_output_version_fprint(
	 stdout,
	 program );

	options_string = _SYSTEM_STRING( "hvV" );

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

			case (system_integer_t) 'h':
				usage_fprint(
				 stdout );

				return( EXIT_SUCCESS );

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
		 "Missing path.\n" );

		usage_fprint(
		 stdout );

		return( EXIT_FAILURE );
	}
	path = argv[ optind++ ];

	libcnotify_stream_set(
	 stderr,
	 NULL );
	libcnotify_verbose_set(
	 verbose );

#if defined( WINAPI )

	result = CoInitialize(
	          NULL );

	if( FAILED( result ) ) 
	{ 
		result = GetLastError();

		libcerror_system_set_error(
		 &error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GENERIC,
		 (uint32_t) result,
		 "unable to initialize COM." );

		goto on_error;
	}
	result = CoCreateInstance(
	          &CLSID_ShellLink,
	          NULL,
	          CLSCTX_INPROC_SERVER,
	          &IID_IShellLink,
	          (void *) &shell_link ); 

	if( FAILED( result ) ) 
	{ 
		result = GetLastError();

		libcerror_system_set_error(
		 &error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GENERIC,
		 (uint32_t) result,
		 "unable to create shell link." );

		goto on_error;
	}
	shell_link->lpVtbl->SetPath(
	 shell_link,
	 path ); 

	shell_link->lpVtbl->SetDescription(
	 shell_link,
	 L"description" ); 
 
	result = shell_link->lpVtbl->QueryInterface(
	          shell_link,
	          &IID_IPersistFile,
	          (void *) &persist_file ); 
 
	if( FAILED( result ) ) 
	{ 
		result = GetLastError();

		libcerror_system_set_error(
		 &error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GENERIC,
		 (uint32_t) result,
		 "unable to create persist file." );

		goto on_error;
	}
	result = persist_file->lpVtbl->Save(
	          persist_file,
	          L"test.lnk",
	          TRUE ); 

	if( FAILED( result ) ) 
	{ 
		result = GetLastError();

		libcerror_system_set_error(
		 &error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GENERIC,
		 (uint32_t) result,
		 "unable to write persist file." );

		goto on_error;
	}
	persist_file->lpVtbl->Release(
	 persist_file ); 

	persist_file = NULL;

	shell_link->lpVtbl->Release(
	 shell_link ); 

	shell_link = NULL;

	CoUninitialize();

	return( EXIT_SUCCESS );
#else
	fprintf(
	 stderr,
	 "This program requires WINAPI.\n" );

	return( EXIT_FAILURE );

#endif /* defined( WINAPI ) */

on_error:
	if( error != NULL )
	{
		libcnotify_print_error_backtrace(
		 error );
		libcerror_error_free(
		 &error );
	}
#if defined( WINAPI )
	if( persist_file != NULL )
	{
		persist_file->lpVtbl->Release(
		 persist_file ); 
	}
	if( shell_link != NULL )
	{
		shell_link->lpVtbl->Release(
		 shell_link ); 
	}
	CoUninitialize();

#endif /* defined( WINAPI ) */

	return( EXIT_FAILURE );
}

