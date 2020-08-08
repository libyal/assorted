/*
 * Saves a Windows Registry key to a Registry hive file using RegSaveKeyEx
 *
 * Copyright (C) 2008-2020, Joachim Metz <joachim.metz@gmail.com>
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
#include <winreg.h>
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
	fprintf( stream, "Use winregsave save a Windows Registry key to a Registry hive file.\n\n" );

	fprintf( stream, "Usage: winregsave [ -12hvV ] key_path target\n\n" );

	fprintf( stream, "\tkey_path: the path of the Windows Registry key.\n" );
	fprintf( stream, "\ttarget:   specify the target file to write the output data.\n\n" );

	fprintf( stream, "\t-1:       write output in REG_STANDARD_FORMAT (default)\n" );
	fprintf( stream, "\t-2:       write output in REG_LATEST_FORMAT\n" );
	fprintf( stream, "\t-h:       shows this help\n" );
	fprintf( stream, "\t-v:       verbose output to stderr\n" );
	fprintf( stream, "\t-V:       print version\n" );
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
	system_character_t *key_path       = NULL;
	system_character_t *options_string = NULL;
	system_character_t *target_path    = NULL;
	char *program                      = "winregsave";
	system_integer_t option            = 0;
	int verbose                        = 0;

#if defined( WINAPI )
	TOKEN_PRIVILEGES priviledges_token;
	LUID local_identifier;

	HANDLE process_handle              = NULL;
	HANDLE process_token               = NULL;
	HKEY key_handle                    = NULL;
	DWORD disposition                  = 0;
	DWORD process_identifier           = 0;
	DWORD save_key_flags               = REG_STANDARD_FORMAT;
	LONG result                        = 0;
#endif

	assorted_output_version_fprint(
	 stdout,
	 program );

	options_string = _SYSTEM_STRING( "12hvV" );

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
#if defined( WINAPI )
				save_key_flags = REG_STANDARD_FORMAT;
#endif
				break;

			case (system_integer_t) '2':
#if defined( WINAPI )
				save_key_flags = REG_LATEST_FORMAT;
#endif
				break;

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
		 "Missing key path.\n" );

		usage_fprint(
		 stdout );

		return( EXIT_FAILURE );
	}
	key_path = argv[ optind++ ];

	if( optind == argc )
	{
		fprintf(
		 stderr,
		 "Missing target file.\n" );

		usage_fprint(
		 stdout );

		return( EXIT_FAILURE );
	}
	target_path = argv[ optind ];

	libcnotify_stream_set(
	 stderr,
	 NULL );
	libcnotify_verbose_set(
	 verbose );

#if defined( WINAPI )
	process_identifier = GetCurrentProcessId();

	process_handle = OpenProcess(
	                  PROCESS_QUERY_INFORMATION,
	                  FALSE,
	                  process_identifier );

	if( process_handle == NULL )
	{
		result = GetLastError();

		libcerror_system_set_error(
		 &error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GENERIC,
		 (uint32_t) result,
		 "unable to open process handle." );

		goto on_error;
	}
	if( OpenProcessToken(
	     process_handle,
	     TOKEN_ADJUST_PRIVILEGES,
	     &process_token ) == FALSE )
	{
		result = GetLastError();

		libcerror_system_set_error(
		 &error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GENERIC,
		 (uint32_t) result,
		 "unable to open process token." );

		goto on_error;
	}
	/* Need SE_BACKUP_NAME priviledge to open key with REG_OPTION_BACKUP_RESTORE
	 */
#if defined( HAVE_WIDE_SYSTEM_CHARACTER )
	if( LookupPrivilegeValueW(
	     NULL,
	     SE_BACKUP_NAME,
	     &local_identifier ) == FALSE )
#else
	if( LookupPrivilegeValueA(
	     NULL,
	     SE_BACKUP_NAME,
	     &local_identifier ) == FALSE )
#endif
	{
		result = GetLastError();

		libcerror_system_set_error(
		 &error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GENERIC,
		 (uint32_t) result,
		 "unable to look up SE_BACKUP_NAME priviledge." );

		goto on_error;
	}
	priviledges_token.PrivilegeCount           = 1;
	priviledges_token.Privileges[0].Luid       = local_identifier;
	priviledges_token.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if( AdjustTokenPrivileges(
	     process_token,
	     FALSE,
	     &priviledges_token,
	     sizeof( TOKEN_PRIVILEGES ),
	     NULL,
	     NULL ) == FALSE )
	{
		result = GetLastError();

		libcerror_system_set_error(
		 &error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GENERIC,
		 (uint32_t) result,
		 "unable to enable SE_BACKUP_NAME priviledge." );

		goto on_error;
	}
#if defined( HAVE_WIDE_SYSTEM_CHARACTER )
	result = RegCreateKeyExW(
	          HKEY_CURRENT_USER,
	          L"TestKey",
	          0,
	          NULL,
	          REG_OPTION_BACKUP_RESTORE,
	          KEY_READ | ACCESS_SYSTEM_SECURITY,
	          NULL,
	          &key_handle,
	          &disposition );
#else
	result = RegCreateKeyExA(
	          HKEY_CURRENT_USER,
	          "TestKey",
	          0,
	          NULL,
	          REG_OPTION_BACKUP_RESTORE,
	          KEY_READ | ACCESS_SYSTEM_SECURITY,
	          NULL,
	          &key_handle,
	          &disposition );
#endif
	if( result != ERROR_SUCCESS )
	{
		libcerror_system_set_error(
		 &error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GENERIC,
		 (uint32_t) result,
		 "unable to open key." );

		goto on_error;
	}
#if defined( HAVE_WIDE_SYSTEM_CHARACTER )
	result = RegSaveKeyExW(
	          key_handle,
	          target_path,
	          NULL,
	          save_key_flags );
#else
	result = RegSaveKeyExA(
	          key_handle,
	          target_path,
	          NULL,
	          save_key_flags );
#endif
	if( result != ERROR_SUCCESS )
	{
		libcerror_system_set_error(
		 &error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GENERIC,
		 (uint32_t) result,
		 "unable to save key to file." );

		goto on_error;
	}
	result = RegCloseKey(
	          key_handle );

	if( result != ERROR_SUCCESS )
	{
		fprintf(
		 stderr,
		 "Unable to close key.\n" );

		goto on_error;
	}
	key_handle = NULL;

	if( CloseHandle(
	     process_token ) == FALSE )
	{
		result = GetLastError();

		libcerror_system_set_error(
		 &error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GENERIC,
		 (uint32_t) result,
		 "unable to close process token." );

		goto on_error;
	}
	process_token = NULL;

	if( CloseHandle(
	     process_handle ) == FALSE )
	{
		result = GetLastError();

		libcerror_system_set_error(
		 &error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GENERIC,
		 (uint32_t) result,
		 "unable to close process handle." );

		goto on_error;
	}
	process_handle = NULL;

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
	if( key_handle != NULL )
	{
		RegCloseKey(
		 key_handle );
	}
	if( process_token != NULL )
	{
		 CloseHandle(
		 process_token );
	}
	if( process_handle != NULL )
	{
		 CloseHandle(
		 process_handle );
	}
#endif
	return( EXIT_FAILURE );
}

