/*
 * Determines a Windows Shell Folder from a path
 *
 * Copyright (C) 2008-2021, Joachim Metz <joachim.metz@gmail.com>
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
#include <shlobj.h>
#include <shlwapi.h>

#pragma comment(lib, "shlwapi.lib")
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
	fprintf( stream, "Use winshellfolder to determine a Shell Folder from a path.\n\n" );

	fprintf( stream, "Usage: winshellfolder [ -12hvV ] path\n\n" );

	fprintf( stream, "\tpath: the path to determine the shell folder of.\n" );

	fprintf( stream, "\t-h:   shows this help\n" );
	fprintf( stream, "\t-v:   verbose output to stderr\n" );
	fprintf( stream, "\t-V:   print version\n" );
	fprintf( stream, "\n" );
}

#if defined( WINAPI )

/* Prints the executable usage information
 */
int winshellfolder_print_shell_folder(
     IShellFolder *shell_folder,
     libcerror_error_t **error )
{
	CLSID class_identifier;
	system_character_t display_name_string[ MAX_PATH ];
	SHDESCRIPTIONID description;
	STRRET display_name_shell_string;

	ITEMIDLIST *item_list           = NULL;
	IPersistFolder *persist_folder  = NULL;
	IShellFolder *sub_shell_folder  = NULL;
	system_character_t *guid_string = NULL;
	static char *function           = "winshellfolder_print_shell_folder";
	ULONG attributes                = 0;
	LPENUMIDLIST enumeration_list   = NULL;
	ULONG number_of_elements        = 0;
	HRESULT result                  = 0;

	if( shell_folder == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid shell folder.",
		 function );

		return( -1 );
	}
	result = shell_folder->lpVtbl->EnumObjects(
	          shell_folder,
	          NULL,
	          SHCONTF_FOLDERS | SHCONTF_NONFOLDERS,
	          &enumeration_list );

	if( FAILED( result ) )
	{
		result = GetLastError();

		libcerror_system_set_error(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GENERIC,
		 (uint32_t) result,
		 "unable to create enumeration list." );

		goto on_error;
	}
	while( ( enumeration_list->lpVtbl->Next(
	          enumeration_list,
	          1,
	          &item_list,
	          &number_of_elements ) == S_OK )
	    && ( number_of_elements == 1 ) )
	{
		result = shell_folder->lpVtbl->BindToObject(
		          shell_folder,
		          item_list,
		          NULL,
		          &IID_IPersistFolder,
		          (void *) &persist_folder );

		if( SUCCEEDED( result ) )
		{
			result = persist_folder->lpVtbl->GetClassID(
			          persist_folder,
			          &class_identifier );

			if( FAILED( result ) )
			{
				result = GetLastError();

				libcerror_system_set_error(
				 error,
				 LIBCERROR_ERROR_DOMAIN_RUNTIME,
				 LIBCERROR_RUNTIME_ERROR_GENERIC,
				 (uint32_t) result,
				 "unable to retrieve class identifier." );

				goto on_error;
			}
			result = StringFromCLSID(
			          &class_identifier,
			          &guid_string );

			if( FAILED( result ) )
			{
				result = GetLastError();

				libcerror_system_set_error(
				 error,
				 LIBCERROR_ERROR_DOMAIN_RUNTIME,
				 LIBCERROR_RUNTIME_ERROR_GENERIC,
				 (uint32_t) result,
				 "unable to convert class identifier to string." );

				goto on_error;
			}
			libcnotify_printf(
			 "IPersist CLSID\t\t: %" PRIs_SYSTEM "\n",
			 guid_string );

			CoTaskMemFree(
			 guid_string );

			guid_string = NULL;

			persist_folder->lpVtbl->Release(
			 persist_folder );

			persist_folder = NULL;
		}
		result = shell_folder->lpVtbl->GetDisplayNameOf(
		          shell_folder,
		          item_list,
		          SHGDN_INFOLDER,
		          &display_name_shell_string );

		if( FAILED( result ) )
		{
			result = GetLastError();

			libcerror_system_set_error(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_GENERIC,
			 (uint32_t) result,
			 "unable to retrieve display name." );

			goto on_error;
		}
		result = StrRetToBuf(
		          &display_name_shell_string,
		          item_list,
		          display_name_string,
		          MAX_PATH );

		if( FAILED( result ) )
		{
			result = GetLastError();

			libcerror_system_set_error(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_GENERIC,
			 (uint32_t) result,
			 "unable to convert display name to string." );

			goto on_error;
		}
		result = SHGetDataFromIDListA(
		          shell_folder,
		          item_list,
		          SHGDFIL_DESCRIPTIONID,
		          &description,
		          sizeof( SHDESCRIPTIONID ) );

		libcnotify_printf(
		 "Display name\t\t: %" PRIs_SYSTEM "\n",
		 display_name_string );

		libcnotify_printf(
		 "Shell item type\t\t: %d",
		 description.dwDescriptionId );

		switch( description.dwDescriptionId )
		{
			case 1:
				libcnotify_printf(
				 " (SHDID_ROOT_REGITEM)" );
				break;

			case 2:
				libcnotify_printf(
				 " (SHDID_FS_FILE)" );
				break;

			case 3:
				libcnotify_printf(
				 " (SHDID_FS_DIRECTORY)" );
				break;

			case 4:
				libcnotify_printf(
				 " (SHDID_FS_OTHER)" );
				break;

			case 5:
				libcnotify_printf(
				 " (SHDID_COMPUTER_DRIVE35)" );
				break;

			case 6:
				libcnotify_printf(
				 " (SHDID_COMPUTER_DRIVE525)" );
				break;

			case 7:
				libcnotify_printf(
				 " (SHDID_COMPUTER_REMOVABLE)" );
				break;

			case 8:
				libcnotify_printf(
				 " (SHDID_COMPUTER_FIXED)" );
				break;

			case 9:
				libcnotify_printf(
				 " (SHDID_COMPUTER_NETDRIVE)" );
				break;

			case 10:
				libcnotify_printf(
				 " (SHDID_COMPUTER_CDROM)" );
				break;

			case 11:
				libcnotify_printf(
				 " (SHDID_COMPUTER_RAMDISK)" );
				break;

			case 12:
				libcnotify_printf(
				 " (SHDID_COMPUTER_OTHER)" );
				break;

			case 13:
				libcnotify_printf(
				 " (SHDID_NET_DOMAIN)" );
				break;

			case 14:
				libcnotify_printf(
				 " (SHDID_NET_SERVER)" );
				break;

			case 15:
				libcnotify_printf(
				 " (SHDID_NET_SHARE)" );
				break;

			case 16:
				libcnotify_printf(
				 " (SHDID_NET_RESTOFNET)" );
				break;

			case 17:
				libcnotify_printf(
				 " (SHDID_NET_OTHER)" );
				break;

			case 18:
				libcnotify_printf(
				 " (SHDID_COMPUTER_IMAGING)" );
				break;

			case 19:
				libcnotify_printf(
				 " (SHDID_COMPUTER_AUDIO)" );
				break;

			case 20:
				libcnotify_printf(
				 " (SHDID_COMPUTER_SHAREDDOCS)" );
				break;

			case 21:
				libcnotify_printf(
				 " (SHDID_MOBILE_DEVICE)" );
				break;

			default:
				libcnotify_printf(
				 " (UNKNOWN)" );
				break;
		}
		libcnotify_printf(
		 "\n" );

		result = StringFromCLSID(
		          &( description.clsid ),
		          &guid_string );

		if( FAILED( result ) )
		{
			result = GetLastError();

			libcerror_system_set_error(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_GENERIC,
			 (uint32_t) result,
			 "unable to convert class identifier to string." );

			goto on_error;
		}
		libcnotify_printf(
		 "Class identifier\t: %" PRIs_SYSTEM "\n",
		 guid_string );

		CoTaskMemFree(
		 guid_string );

		guid_string = NULL;

		libcnotify_printf(
		 "Shell item data:\n" );
		libcnotify_print_data(
		 (uint8_t *) item_list,
		 item_list->mkid.cb + 2,
		 0 );

		attributes = SFGAO_FOLDER;

		result = shell_folder->lpVtbl->GetAttributesOf(
		         shell_folder,
		         1,
			 (ITEMIDLIST **) &item_list,
		         &attributes );

		if( FAILED( result ) )
		{
			result = GetLastError();

			libcerror_system_set_error(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_GENERIC,
			 (uint32_t) result,
			 "unable to retrieve shell folder attributes." );

			goto on_error;
		}
		if( ( attributes & SFGAO_FOLDER ) != 0 )
		{
			result = shell_folder->lpVtbl->BindToObject(
			          shell_folder,
			          item_list,
			          NULL,
			          &IID_IShellFolder,
			          (void *) &sub_shell_folder );

			if( FAILED( result ) )
			{
				result = GetLastError();

				libcerror_system_set_error(
				 error,
				 LIBCERROR_ERROR_DOMAIN_RUNTIME,
				 LIBCERROR_RUNTIME_ERROR_GENERIC,
				 (uint32_t) result,
				 "unable to bind sub shell folder list item to IShellFolder." );

				goto on_error;
			}
			if( winshellfolder_print_shell_folder(
			     sub_shell_folder,
			     error ) != 1 )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_RUNTIME,
				 LIBCERROR_RUNTIME_ERROR_GENERIC,
				 "unable to print sub shell folder." );

				goto on_error;
			}
			sub_shell_folder->lpVtbl->Release(
			 sub_shell_folder );

			sub_shell_folder = NULL;
		}
		CoTaskMemFree(
		 item_list);

		item_list = NULL;
	}
	libcnotify_printf(
	 "\n\n" );

	enumeration_list->lpVtbl->Release(
	 enumeration_list );

	enumeration_list = NULL;

	return( 1 );

on_error:
	if( sub_shell_folder != NULL )
	{
		sub_shell_folder->lpVtbl->Release(
		 sub_shell_folder );
	}
	if( guid_string != NULL )
	{
		CoTaskMemFree(
		 guid_string );

		guid_string = NULL;
	}
	if( persist_folder != NULL )
	{
		persist_folder->lpVtbl->Release(
		 persist_folder );
	}
	if( item_list != NULL )
	{
		CoTaskMemFree(
		 item_list );

		item_list = NULL;
	}
	if( enumeration_list != NULL )
	{
		enumeration_list->lpVtbl->Release(
		 enumeration_list );
	}
	return( -1 );
}

#endif /* defined( WINAPI ) */

/* The main program
 */
#if defined( HAVE_WIDE_SYSTEM_CHARACTER )
int wmain( int argc, wchar_t * const argv[] )
#else
int main( int argc, char * const argv[] )
#endif
{
	libcerror_error_t *error            = NULL;
	system_character_t *options_string  = NULL;
	system_character_t *path            = NULL;
	char *program                       = "winshellfolder";
	system_integer_t option             = 0;
	int verbose                         = 0;

#if defined( WINAPI )
	IShellFolder *desktop_folder        = NULL;
	IShellFolder *program_files_folder  = NULL;
	ITEMIDLIST *program_files_item_list = NULL;
	HRESULT result                      = 0;
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
/* TODO
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
*/

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
	result = SHGetDesktopFolder(
	          &desktop_folder );

	if( FAILED( result ) )
	{
		result = GetLastError();

		libcerror_system_set_error(
		 &error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GENERIC,
		 (uint32_t) result,
		 "unable to retrieve Desktop folder location." );

		goto on_error;
	}
/* TODO
	result = SHGetFolderLocation(
	          NULL,
	          CSIDL_PROGRAM_FILES,
	          NULL,
	          0,
	          &program_files_item_list );

	if( FAILED( result ) )
	{
		result = GetLastError();

		libcerror_system_set_error(
		 &error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GENERIC,
		 (uint32_t) result,
		 "unable to retrieve Program Files item list." );

		goto on_error;
	}
	result = desktop_folder->lpVtbl->BindToObject(
	          desktop_folder,
	          program_files_item_list,
	          NULL,
	          &IID_IShellFolder,
	          (void *) &program_files_folder );

	if( FAILED( result ) )
	{
		result = GetLastError();

		libcerror_system_set_error(
		 &error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GENERIC,
		 (uint32_t) result,
		 "unable to bind Program Files item list to IShellFolder." );

		goto on_error;
	}
*/
	if( winshellfolder_print_shell_folder(
	     desktop_folder,
	     &error ) != 1 )
	{
		libcerror_error_set(
		 &error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GENERIC,
		 "unable to print shell folder." );

		goto on_error;
	}
/* TODO
	CoTaskMemFree(
	 program_files_item_list );

	program_files_item_list = NULL;

	program_files_folder->lpVtbl->Release(
	 program_files_folder );

	program_files_folder = NULL;
*/

	desktop_folder->lpVtbl->Release(
	 desktop_folder );

	desktop_folder = NULL;

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
	if( program_files_item_list != NULL )
	{
		CoTaskMemFree(
		 program_files_item_list );

		program_files_item_list = NULL;
	}
	if( program_files_folder != NULL )
	{
		program_files_folder->lpVtbl->Release(
		 program_files_folder );
	}
	if( desktop_folder != NULL )
	{
		desktop_folder->lpVtbl->Release(
		 desktop_folder );
	}
	CoUninitialize();

#endif /* defined( WINAPI ) */

	return( EXIT_FAILURE );
}

