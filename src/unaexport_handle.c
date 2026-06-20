/*
 * Export handle
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
#include <memory.h>
#include <narrow_string.h>
#include <system_string.h>
#include <types.h>
#include <wide_string.h>

#include "assorted_libcerror.h"
#include "assorted_libcfile.h"
#include "assorted_libclocale.h"
#include "assorted_libuna.h"
#include "process_status.h"
#include "unacommon.h"
#include "unaexport_handle.h"
#include "unainput.h"

#define UNAEXPORT_HANDLE_BUFFER_SIZE		8 * 1024 * 1024
#define UNAEXPORT_HANDLE_STRING_SIZE		1024
#define UNAEXPORT_HANDLE_NOTIFY_STREAM		stderr

/* Creates an export handle
 * Make sure the value export_handle is referencing, is set to NULL
 * Returns 1 if successful or -1 on error
 */
int export_handle_initialize(
     export_handle_t **export_handle,
     uint8_t mode,
     libcerror_error_t **error )
{
	static char *function = "export_handle_initialize";

	if( export_handle == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid export handle.",
		 function );

		return( -1 );
	}
	if( *export_handle != NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_ALREADY_SET,
		 "%s: invalid export handle value already set.",
		 function );

		return( -1 );
	}
	if( ( mode != UNAEXPORT_HANDLE_MODE_BASE_ENCODING )
	 && ( mode != UNAEXPORT_HANDLE_MODE_TEXT_ENCODING ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
		 "%s: unsupported mode.",
		 function );

		return( -1 );
	}
	*export_handle = memory_allocate_structure(
	                  export_handle_t );

	if( *export_handle == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
		 "%s: unable to create export handle.",
		 function );

		goto on_error;
	}
	if( memory_set(
	     *export_handle,
	     0,
	     sizeof( export_handle_t ) ) == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_SET_FAILED,
		 "%s: unable to clear export handle.",
		 function );

		memory_free(
		 *export_handle );

		*export_handle = NULL;

		return( -1 );
	}
	if( libcfile_file_initialize(
	     &( ( *export_handle )->source_file ),
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
		 "%s: unable to create source file.",
		 function );

		goto on_error;
	}
	if( libcfile_file_initialize(
	     &( ( *export_handle )->destination_file ),
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
		 "%s: unable to create destination file.",
		 function );

		goto on_error;
	}
	( *export_handle )->mode = mode;

	if( mode == UNAEXPORT_HANDLE_MODE_BASE_ENCODING )
	{
		( *export_handle )->base_encoding      = UNACOMMON_ENCODING_BASE64;
		( *export_handle )->base_encoding_mode = UNACOMMON_ENCODING_MODE_ENCODE;
	}
	else if( mode == UNAEXPORT_HANDLE_MODE_TEXT_ENCODING )
	{
		( *export_handle )->text_input_format           = UNACOMMON_FORMAT_AUTO_DETECT;
		( *export_handle )->text_output_format          = UNACOMMON_FORMAT_UTF8;
		( *export_handle )->text_newline_conversion     = UNACOMMON_NEWLINE_CONVERSION_NONE;
		( *export_handle )->text_export_byte_order_mark = 1;
		( *export_handle )->text_byte_stream_codepage   = LIBUNA_CODEPAGE_ASCII;
	}
	( *export_handle )->notify_stream = UNAEXPORT_HANDLE_NOTIFY_STREAM;

	return( 1 );

on_error:
	if( *export_handle != NULL )
	{
		if( ( *export_handle )->source_file != NULL )
		{
			libcfile_file_free(
			 &( ( *export_handle )->source_file ),
			 NULL );
		}
		memory_free(
		 *export_handle );

		*export_handle = NULL;
	}
	return( -1 );
}

/* Frees an export handle
 * Returns 1 if successful or -1 on error
 */
int export_handle_free(
     export_handle_t **export_handle,
     libcerror_error_t **error )
{
	static char *function = "export_handle_free";
	int result            = 1;

	if( export_handle == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid export handle.",
		 function );

		return( -1 );
	}
	if( *export_handle != NULL )
	{
		if( ( *export_handle )->source_filename != NULL )
		{
			memory_free(
			 ( *export_handle )->source_filename );
		}
		if( ( *export_handle )->destination_filename != NULL )
		{
			memory_free(
			 ( *export_handle )->destination_filename );
		}
		if( libcfile_file_free(
		     &( ( *export_handle )->source_file ),
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_FINALIZE_FAILED,
			 "%s: unable to free source file.",
			 function );

			result = -1;
		}
		if( libcfile_file_free(
		     &( ( *export_handle )->destination_file ),
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_FINALIZE_FAILED,
			 "%s: unable to free destination file.",
			 function );

			result = -1;
		}
		memory_free(
		 *export_handle );

		*export_handle = NULL;
	}
	return( result );
}

/* Signals the export handle to abort
 * Returns 1 if successful or -1 on error
 */
int export_handle_signal_abort(
     export_handle_t *export_handle,
     libcerror_error_t **error )
{
	static char *function = "export_handle_signal_abort";

	if( export_handle == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid export handle.",
		 function );

		return( -1 );
	}
	export_handle->abort = 1;

	return( 1 );
}

/* Opens the input of the export handle
 * Returns 1 if successful or -1 on error
 */
int export_handle_open_input(
     export_handle_t *export_handle,
     libcerror_error_t **error )
{
	static char *function = "export_handle_open_input";

	if( export_handle == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid export handle.",
		 function );

		return( -1 );
	}
	if( export_handle->source_filename == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_MISSING,
		 "%s: invalid export handle - missing source filename.",
		 function );

		return( -1 );
	}
#if defined( HAVE_WIDE_SYSTEM_CHARACTER )
	if( libcfile_file_open_wide(
	     export_handle->source_file,
	     export_handle->source_filename,
	     LIBCFILE_OPEN_READ,
	     error ) != 1 )
#else
	if( libcfile_file_open(
	     export_handle->source_file,
	     export_handle->source_filename,
	     LIBCFILE_OPEN_READ,
	     error ) != 1 )
#endif
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_IO,
		 LIBCERROR_IO_ERROR_OPEN_FAILED,
		 "%s: unable to open source file: %" PRIs_SYSTEM ".",
		 function,
		 export_handle->source_filename );

		return( -1 );
	}
	return( 1 );
}

/* Opens the output of the export handle
 * Returns 1 if successful or -1 on error
 */
int export_handle_open_output(
     export_handle_t *export_handle,
     libcerror_error_t **error )
{
	static char *function = "export_handle_open_output";

	if( export_handle == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid export handle.",
		 function );

		return( -1 );
	}
	if( export_handle->destination_filename == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_MISSING,
		 "%s: invalid export handle - missing destination filename.",
		 function );

		return( -1 );
	}
#if defined( HAVE_WIDE_SYSTEM_CHARACTER )
	if( libcfile_file_open_wide(
	     export_handle->destination_file,
	     export_handle->destination_filename,
	     LIBCFILE_OPEN_WRITE_TRUNCATE,
	     error ) != 1 )
#else
	if( libcfile_file_open(
	     export_handle->destination_file,
	     export_handle->destination_filename,
	     LIBCFILE_OPEN_WRITE_TRUNCATE,
	     error ) != 1 )
#endif
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_IO,
		 LIBCERROR_IO_ERROR_OPEN_FAILED,
		 "%s: unable to open destination file: %" PRIs_SYSTEM ".",
		 function,
		 export_handle->destination_filename );

		return( -1 );
	}
	return( 1 );
}

/* Closes the export handle
 * Returns the 0 if succesful or -1 on error
 */
int export_handle_close(
     export_handle_t *export_handle,
     libcerror_error_t **error )
{
	static char *function = "export_handle_close";
	int result            = 0;

	if( export_handle == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid export handle.",
		 function );

		return( -1 );
	}
	if( libcfile_file_close(
	     export_handle->source_file,
	     error ) != 0 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_IO,
		 LIBCERROR_IO_ERROR_CLOSE_FAILED,
		 "%s: unable to close source file.",
		 function );

		result = -1;
	}
	if( libcfile_file_close(
	     export_handle->destination_file,
	     error ) != 0 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_IO,
		 LIBCERROR_IO_ERROR_CLOSE_FAILED,
		 "%s: unable to close destination file.",
		 function );

		result = -1;
	}
	return( result );
}

/* Sets a string
 * Returns 1 if successful or -1 on error
 */
int export_handle_set_string(
     export_handle_t *export_handle,
     const system_character_t *string,
     system_character_t **internal_string,
     size_t *internal_string_size,
     libcerror_error_t **error )
{
	static char *function = "export_handle_set_string";
	size_t string_length  = 0;

	if( export_handle == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid export handle.",
		 function );

		return( -1 );
	}
	if( string == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid string.",
		 function );

		return( -1 );
	}
	if( internal_string == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid internal string.",
		 function );

		return( -1 );
	}
	if( internal_string_size == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid internal string size.",
		 function );

		return( -1 );
	}
	if( *internal_string != NULL )
	{
		memory_free(
		 *internal_string );

		*internal_string      = NULL;
		*internal_string_size = 0;
	}
	string_length = system_string_length(
	                 string );

	if( string_length > 0 )
	{
		*internal_string = system_string_allocate(
		                    string_length + 1 );

		if( *internal_string == NULL )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_MEMORY,
			 LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
			 "%s: unable to create internal string.",
			 function );

			goto on_error;
		}
		if( system_string_copy(
		     *internal_string,
		     string,
		     string_length ) == NULL )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_COPY_FAILED,
			 "%s: unable to copy string.",
			 function );

			goto on_error;
		}
		( *internal_string )[ string_length ] = 0;

		*internal_string_size = string_length + 1;
	}
	return( 1 );

on_error:
	if( *internal_string != NULL )
	{
		memory_free(
		 *internal_string );

		*internal_string = NULL;
	}
	*internal_string_size = 0;

	return( -1 );
}

/* Sets the encoding
 * Returns 1 if successful, 0 if unsupported value or -1 on error
 */
int export_handle_set_encoding(
     export_handle_t *export_handle,
     const system_character_t *string,
     libcerror_error_t **error )
{
	static char *function = "export_handle_set_encoding";
	int result            = 0;

	if( export_handle == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid export handle.",
		 function );

		return( -1 );
	}
	if( export_handle->mode != UNAEXPORT_HANDLE_MODE_BASE_ENCODING )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_UNSUPPORTED_VALUE,
		 "%s: invalid export handle - unsupported mode.",
		 function );

		return( -1 );
	}
	result = unainput_determine_encoding(
		  string,
		  &( export_handle->base_encoding ),
		  error );

	if( result == -1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to determine encoding.",
		 function );

		return( -1 );
	}
	return( result );
}

/* Sets the encoding mode
 * Returns 1 if successful, 0 if unsupported value or -1 on error
 */
int export_handle_set_encoding_mode(
     export_handle_t *export_handle,
     const system_character_t *string,
     libcerror_error_t **error )
{
	static char *function = "export_handle_set_encoding_mode";
	int result            = 0;

	if( export_handle == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid export handle.",
		 function );

		return( -1 );
	}
	if( export_handle->mode != UNAEXPORT_HANDLE_MODE_BASE_ENCODING )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_UNSUPPORTED_VALUE,
		 "%s: invalid export handle - unsupported mode.",
		 function );

		return( -1 );
	}
	result = unainput_determine_encoding_mode(
		  string,
		  &( export_handle->base_encoding_mode ),
		  error );

	if( result == -1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to determine encoding mode.",
		 function );

		return( -1 );
	}
	return( result );
}

/* Sets the input format
 * Returns 1 if successful, 0 if unsupported value or -1 on error
 */
int export_handle_set_input_format(
     export_handle_t *export_handle,
     const system_character_t *string,
     libcerror_error_t **error )
{
	static char *function = "export_handle_set_input_format";
	size_t string_length  = 0;
	int result            = 0;

	if( export_handle == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid export handle.",
		 function );

		return( -1 );
	}
	if( export_handle->mode != UNAEXPORT_HANDLE_MODE_TEXT_ENCODING )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_UNSUPPORTED_VALUE,
		 "%s: invalid export handle - unsupported mode.",
		 function );

		return( -1 );
	}
	string_length = system_string_length(
	                 string );

	if( string_length == 11 )
	{
		if( system_string_compare(
		     string,
		     _SYSTEM_STRING( "auto-detect" ),
		     11 ) == 0 )
		{
			export_handle->text_input_format = UNACOMMON_FORMAT_AUTO_DETECT;
			result                      = 1;
		}
	}
	if( result == 0 )
	{
		result = unainput_determine_format(
		          string,
		          &( export_handle->text_input_format ),
		          error );

		if( result == -1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
			 "%s: unable to determine input format.",
			 function );

			return( -1 );
		}
	}
	return( result );
}

/* Sets the output format
 * Returns 1 if successful, 0 if unsupported value or -1 on error
 */
int export_handle_set_output_format(
     export_handle_t *export_handle,
     const system_character_t *string,
     libcerror_error_t **error )
{
	static char *function = "export_handle_set_output_format";
	int result            = 0;

	if( export_handle == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid export handle.",
		 function );

		return( -1 );
	}
	if( export_handle->mode != UNAEXPORT_HANDLE_MODE_TEXT_ENCODING )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_UNSUPPORTED_VALUE,
		 "%s: invalid export handle - unsupported mode.",
		 function );

		return( -1 );
	}
	result = unainput_determine_format(
		  string,
		  &( export_handle->text_output_format ),
		  error );

	if( result == -1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to determine output format.",
		 function );

		return( -1 );
	}
	return( result );
}

/* Sets the newline conversion
 * Returns 1 if successful, 0 if unsupported value or -1 on error
 */
int export_handle_set_newline_conversion(
     export_handle_t *export_handle,
     const system_character_t *string,
     libcerror_error_t **error )
{
	static char *function = "export_handle_set_newline_conversion";
	int result            = 0;

	if( export_handle == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid export handle.",
		 function );

		return( -1 );
	}
	if( export_handle->mode != UNAEXPORT_HANDLE_MODE_TEXT_ENCODING )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_UNSUPPORTED_VALUE,
		 "%s: invalid export handle - unsupported mode.",
		 function );

		return( -1 );
	}
	result = unainput_determine_newline_conversion(
		  string,
		  &( export_handle->text_newline_conversion ),
		  error );

	if( result == -1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to determine newline conversion.",
		 function );

		return( -1 );
	}
	return( result );
}

/* Sets the byte stream codepage
 * Returns 1 if successful or -1 on error
 */
int export_handle_set_byte_stream_codepage(
     export_handle_t *export_handle,
     const system_character_t *string,
     libcerror_error_t **error )
{
	static char *function  = "export_handle_set_byte_stream_codepage";
	size_t string_length   = 0;
	uint32_t feature_flags = 0;
	int result             = 0;

	if( export_handle == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid export handle.",
		 function );

		return( -1 );
	}
	if( export_handle->mode != UNAEXPORT_HANDLE_MODE_TEXT_ENCODING )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_UNSUPPORTED_VALUE,
		 "%s: invalid export handle - unsupported mode.",
		 function );

		return( -1 );
	}
	feature_flags = LIBCLOCALE_CODEPAGE_FEATURE_FLAG_HAVE_ISO_8859
	              | LIBCLOCALE_CODEPAGE_FEATURE_FLAG_HAVE_KOI8
	              | LIBCLOCALE_CODEPAGE_FEATURE_FLAG_HAVE_WINDOWS;

	string_length = system_string_length(
	                 string );

#if defined( HAVE_WIDE_SYSTEM_CHARACTER )
	result = libclocale_codepage_copy_from_string_wide(
	          &( export_handle->text_byte_stream_codepage ),
	          string,
	          string_length,
	          feature_flags,
	          error );
#else
	result = libclocale_codepage_copy_from_string(
	          &( export_handle->text_byte_stream_codepage ),
	          string,
	          string_length,
	          feature_flags,
	          error );
#endif
	if( result == -1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to determine byte stream codepage.",
		 function );

		return( -1 );
	}
	return( result );
}

/* Exports the source file to the destination file
 * Returns the number of bytes of the source processed or -1 on error
 */
int export_handle_export_input(
     export_handle_t *export_handle,
     uint8_t print_status_information,
     libcerror_error_t **error )
{
	process_status_t *process_status = NULL;
	static char *function            = "export_handle_export_text_input";

	if( export_handle == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid export handle.",
		 function );

		return( -1 );
	}
	if( process_status_initialize(
	     &process_status,
	     _SYSTEM_STRING( "Export" ),
	     _SYSTEM_STRING( "exported" ),
	     _SYSTEM_STRING( "Exported" ),
	     stdout,
	     print_status_information,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
		 "%s: unable to create process status.",
		 function );

		goto on_error;
	}
	if( process_status_start(
	     process_status,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_SET_FAILED,
		 "%s: unable to start process status.",
		 function );

		goto on_error;
	}
	if( export_handle->mode == UNAEXPORT_HANDLE_MODE_BASE_ENCODING )
	{
		if( export_handle_export_base_encoded_input(
		     export_handle,
		     process_status,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_GENERIC,
			 "%s: unable to export base encoded input.",
			 function );

			goto on_error;
		}
	}
	else if( export_handle->mode == UNAEXPORT_HANDLE_MODE_TEXT_ENCODING )
	{
		if( export_handle_export_text_encoded_input(
		     export_handle,
		     process_status,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_GENERIC,
			 "%s: unable to export text encoded input.",
			 function );

			goto on_error;
		}
	}
	if( process_status_free(
	     &process_status,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_FINALIZE_FAILED,
		 "%s: unable to free process status.",
		 function );

		goto on_error;
	}
	return( 1 );

on_error:
	if( process_status != NULL )
	{
		process_status_free(
		 &process_status,
		 NULL );
	}
	return( -1 );
}

/* Exports the base-encoded source file to the destination file
 * Returns the number of bytes of the source processed or -1 on error
 */
int export_handle_export_base_encoded_input(
     export_handle_t *export_handle,
     process_status_t *process_status,
     libcerror_error_t **error )
{
	uint8_t *destination_buffer      = NULL;
	uint8_t *source_buffer           = NULL;
	const char *encoding_string      = NULL;
	const char *encoding_mode_string = NULL;
	static char *function            = "export_handle_export_base_encoded_input";
	size64_t export_count            = 0;
	size_t destination_buffer_size   = 0;
	size_t source_buffer_size        = 0;
	size_t write_size                = 0;
	ssize_t read_count               = 0;
	ssize_t write_count              = 0;
	int result                       = 0;

	if( export_handle == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid export handle.",
		 function );

		return( -1 );
	}
	if( export_handle->mode != UNAEXPORT_HANDLE_MODE_BASE_ENCODING )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_UNSUPPORTED_VALUE,
		 "%s: invalid export handle - unsupported mode.",
		 function );

		return( -1 );
	}
	if( ( export_handle->base_encoding != UNACOMMON_ENCODING_BASE16 )
	 && ( export_handle->base_encoding != UNACOMMON_ENCODING_BASE32 )
	 && ( export_handle->base_encoding != UNACOMMON_ENCODING_BASE32HEX )
	 && ( export_handle->base_encoding != UNACOMMON_ENCODING_BASE64 )
	 && ( export_handle->base_encoding != UNACOMMON_ENCODING_BASE64URL ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_UNSUPPORTED_VALUE,
		 "%s: invalid export handle - unsupported encoding.",
		 function );

		return( -1 );
	}
	if( ( export_handle->base_encoding_mode != UNACOMMON_ENCODING_MODE_DECODE )
	 && ( export_handle->base_encoding_mode != UNACOMMON_ENCODING_MODE_ENCODE ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_UNSUPPORTED_VALUE,
		 "%s: invalid export handle - unsupported encoding mode.",
		 function );

		return( -1 );
	}
	if( export_handle->base_encoding_mode == UNACOMMON_ENCODING_MODE_DECODE )
	{
		encoding_mode_string = "decode";
	}
	else
	{
		encoding_mode_string = "encode";
	}
	switch( export_handle->base_encoding )
	{
		case UNACOMMON_ENCODING_BASE16:
			if( export_handle->base_encoding_mode == UNACOMMON_ENCODING_MODE_DECODE )
			{
				source_buffer_size      = ( UNAEXPORT_HANDLE_BUFFER_SIZE / 2 ) * 2;
				destination_buffer_size = UNAEXPORT_HANDLE_BUFFER_SIZE / 2;
			}
			else
			{
				source_buffer_size       = UNAEXPORT_HANDLE_BUFFER_SIZE;
				destination_buffer_size  = UNAEXPORT_HANDLE_BUFFER_SIZE * 2;
				destination_buffer_size += ( destination_buffer_size / 76 ) + 1;
			}
			encoding_string = "base16";

			break;

		case UNACOMMON_ENCODING_BASE32:
			if( export_handle->base_encoding_mode == UNACOMMON_ENCODING_MODE_DECODE )
			{
				source_buffer_size      = ( UNAEXPORT_HANDLE_BUFFER_SIZE / 5 ) * 5;
				destination_buffer_size = ( UNAEXPORT_HANDLE_BUFFER_SIZE * 5 ) / 8;
			}
			else
			{
				source_buffer_size       = ( UNAEXPORT_HANDLE_BUFFER_SIZE / 8 ) * 8;
				destination_buffer_size  = ( ( UNAEXPORT_HANDLE_BUFFER_SIZE / 5 ) + 1 ) * 8;
				destination_buffer_size += ( destination_buffer_size / 76 ) + 1;
			}
			encoding_string = "base32";

			break;

		case UNACOMMON_ENCODING_BASE32HEX:
			if( export_handle->base_encoding_mode == UNACOMMON_ENCODING_MODE_DECODE )
			{
				source_buffer_size      = ( UNAEXPORT_HANDLE_BUFFER_SIZE / 5 ) * 5;
				destination_buffer_size = ( UNAEXPORT_HANDLE_BUFFER_SIZE * 5 ) / 8;
			}
			else
			{
				source_buffer_size       = ( UNAEXPORT_HANDLE_BUFFER_SIZE / 8 ) * 8;
				destination_buffer_size  = ( ( UNAEXPORT_HANDLE_BUFFER_SIZE / 5 ) + 1 ) * 8;
				destination_buffer_size += ( destination_buffer_size / 76 ) + 1;
			}
			encoding_string = "base32hex";

			break;

		case UNACOMMON_ENCODING_BASE64:
			if( export_handle->base_encoding_mode == UNACOMMON_ENCODING_MODE_DECODE )
			{
				source_buffer_size      = ( UNAEXPORT_HANDLE_BUFFER_SIZE / 3 ) * 3;
				destination_buffer_size = ( UNAEXPORT_HANDLE_BUFFER_SIZE * 3 ) / 4;
			}
			else
			{
				source_buffer_size       = ( UNAEXPORT_HANDLE_BUFFER_SIZE / 4 ) * 4;
				destination_buffer_size  = ( ( UNAEXPORT_HANDLE_BUFFER_SIZE / 3 ) + 1 ) * 4;
				destination_buffer_size += ( destination_buffer_size / 76 ) + 1;
			}
			encoding_string = "base64";

			break;

		case UNACOMMON_ENCODING_BASE64URL:
			if( export_handle->base_encoding_mode == UNACOMMON_ENCODING_MODE_DECODE )
			{
				source_buffer_size      = ( UNAEXPORT_HANDLE_BUFFER_SIZE / 3 ) * 3;
				destination_buffer_size = ( UNAEXPORT_HANDLE_BUFFER_SIZE * 3 ) / 4;
			}
			else
			{
				source_buffer_size       = ( UNAEXPORT_HANDLE_BUFFER_SIZE / 4 ) * 4;
				destination_buffer_size  = ( ( UNAEXPORT_HANDLE_BUFFER_SIZE / 3 ) + 1 ) * 4;
				destination_buffer_size += ( destination_buffer_size / 76 ) + 1;
			}
			encoding_string = "base64url";

			break;
	}
	if( source_buffer_size == 0 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_MISSING,
		 "%s: missing source buffer size.",
		 function );

		return( -1 );
	}
	source_buffer = (uint8_t *) memory_allocate(
	                             sizeof( uint8_t ) * source_buffer_size );

	if( source_buffer == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
		 "%s: unable to create source buffer.",
		 function );

		goto on_error;
	}
	if( destination_buffer_size == 0 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_MISSING,
		 "%s: missing destination buffer size.",
		 function );

		return( -1 );
	}
	destination_buffer = (uint8_t *) memory_allocate(
	                                  sizeof( uint8_t ) * destination_buffer_size );

	if( destination_buffer == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
		 "%s: unable to create destination buffer.",
		 function );

		goto on_error;
	}
	while( 1 )
	{
		read_count = libcfile_file_read_buffer(
		              export_handle->source_file,
		              source_buffer,
		              source_buffer_size,
		              error );

		if( read_count < 0 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_IO,
			 LIBCERROR_IO_ERROR_READ_FAILED,
			 "%s: unable to read from source.",
			 function );

			goto on_error;
		}
		export_count += read_count;

		if( read_count == 0 )
		{
			break;
		}
		switch( export_handle->base_encoding )
		{
			case UNACOMMON_ENCODING_BASE16:
				if( export_handle->base_encoding_mode == UNACOMMON_ENCODING_MODE_DECODE )
				{
					result = libuna_base16_stream_size_to_byte_stream(
					          source_buffer,
					          read_count,
					          &write_size,
					          LIBUNA_BASE16_VARIANT_CASE_MIXED \
					           | LIBUNA_BASE16_VARIANT_CHARACTER_LIMIT_NONE,
					          LIBUNA_BASE16_FLAG_STRIP_WHITESPACE,
					          error );
				}
				else
				{
					result = libuna_base16_stream_size_from_byte_stream(
					          source_buffer,
					          read_count,
					          &write_size,
					          LIBUNA_BASE16_VARIANT_CASE_UPPER \
					           | LIBUNA_BASE16_VARIANT_CHARACTER_LIMIT_76,
					          error );
				}
				break;

			case UNACOMMON_ENCODING_BASE32:
				if( export_handle->base_encoding_mode == UNACOMMON_ENCODING_MODE_DECODE )
				{
					result = libuna_base32_stream_size_to_byte_stream(
					          source_buffer,
					          read_count,
					          &write_size,
					          LIBUNA_BASE32_VARIANT_ALPHABET_NORMAL \
					           | LIBUNA_BASE32_VARIANT_CHARACTER_LIMIT_NONE \
					           | LIBUNA_BASE32_VARIANT_PADDING_REQUIRED,
					          LIBUNA_BASE32_FLAG_STRIP_WHITESPACE,
					          error );
				}
				else
				{
					result = libuna_base32_stream_size_from_byte_stream(
					          source_buffer,
					          read_count,
					          &write_size,
					          LIBUNA_BASE32_VARIANT_ALPHABET_NORMAL \
					           | LIBUNA_BASE32_VARIANT_CHARACTER_LIMIT_64 \
					           | LIBUNA_BASE32_VARIANT_PADDING_REQUIRED,
					          error );
				}
				break;

			case UNACOMMON_ENCODING_BASE32HEX:
				if( export_handle->base_encoding_mode == UNACOMMON_ENCODING_MODE_DECODE )
				{
					result = libuna_base32_stream_size_to_byte_stream(
					          source_buffer,
					          read_count,
					          &write_size,
					          LIBUNA_BASE32_VARIANT_ALPHABET_HEX \
					           | LIBUNA_BASE32_VARIANT_CHARACTER_LIMIT_NONE \
					           | LIBUNA_BASE32_VARIANT_PADDING_REQUIRED,
					          LIBUNA_BASE32_FLAG_STRIP_WHITESPACE,
					          error );
				}
				else
				{
					result = libuna_base32_stream_size_from_byte_stream(
					          source_buffer,
					          read_count,
					          &write_size,
					          LIBUNA_BASE32_VARIANT_ALPHABET_HEX \
					           | LIBUNA_BASE32_VARIANT_CHARACTER_LIMIT_64 \
					           | LIBUNA_BASE32_VARIANT_PADDING_REQUIRED,
					          error );
				}
				break;

			case UNACOMMON_ENCODING_BASE64:
				if( export_handle->base_encoding_mode == UNACOMMON_ENCODING_MODE_DECODE )
				{
					result = libuna_base64_stream_size_to_byte_stream(
					          source_buffer,
					          read_count,
					          &write_size,
					          LIBUNA_BASE64_VARIANT_ALPHABET_NORMAL \
					           | LIBUNA_BASE64_VARIANT_CHARACTER_LIMIT_NONE \
					           | LIBUNA_BASE64_VARIANT_PADDING_REQUIRED,
					          LIBUNA_BASE64_FLAG_STRIP_WHITESPACE,
					          error );
				}
				else
				{
					result = libuna_base64_stream_size_from_byte_stream(
					          source_buffer,
					          read_count,
					          &write_size,
					          LIBUNA_BASE64_VARIANT_MIME,
					          error );
				}
				break;

			case UNACOMMON_ENCODING_BASE64URL:
				if( export_handle->base_encoding_mode == UNACOMMON_ENCODING_MODE_DECODE )
				{
					result = libuna_base64_stream_size_to_byte_stream(
					          source_buffer,
					          read_count,
					          &write_size,
					          LIBUNA_BASE64_VARIANT_URL,
					          LIBUNA_BASE64_FLAG_STRIP_WHITESPACE,
					          error );
				}
				else
				{
					result = libuna_base64_stream_size_from_byte_stream(
					          source_buffer,
					          read_count,
					          &write_size,
					          LIBUNA_BASE64_VARIANT_URL,
					          error );
				}
				break;
		}
		if( result != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_CONVERSION,
			 LIBCERROR_CONVERSION_ERROR_INPUT_FAILED,
			 "%s: unable to determine %s size of %s source data.",
			 function,
			 encoding_string,
			 encoding_mode_string );

			goto on_error;
		}
		switch( export_handle->base_encoding )
		{
			case UNACOMMON_ENCODING_BASE16:
				if( export_handle->base_encoding_mode == UNACOMMON_ENCODING_MODE_DECODE )
				{
					result = libuna_base16_stream_copy_to_byte_stream(
					          source_buffer,
					          read_count,
					          destination_buffer,
					          destination_buffer_size,
					          LIBUNA_BASE16_VARIANT_CASE_MIXED \
					           | LIBUNA_BASE16_VARIANT_CHARACTER_LIMIT_NONE,
					          LIBUNA_BASE16_FLAG_STRIP_WHITESPACE,
					          error );
				}
				else
				{
					result = libuna_base16_stream_copy_from_byte_stream(
					          destination_buffer,
					          destination_buffer_size,
					          source_buffer,
					          read_count,
					          LIBUNA_BASE16_VARIANT_CASE_UPPER \
					           | LIBUNA_BASE16_VARIANT_CHARACTER_LIMIT_76,
					          error );
				}
				break;

			case UNACOMMON_ENCODING_BASE32:
				if( export_handle->base_encoding_mode == UNACOMMON_ENCODING_MODE_DECODE )
				{
					result = libuna_base32_stream_copy_to_byte_stream(
					          source_buffer,
					          read_count,
					          destination_buffer,
					          destination_buffer_size,
					          LIBUNA_BASE32_VARIANT_ALPHABET_NORMAL \
					           | LIBUNA_BASE32_VARIANT_CHARACTER_LIMIT_NONE \
					           | LIBUNA_BASE32_VARIANT_PADDING_REQUIRED,
					          LIBUNA_BASE32_FLAG_STRIP_WHITESPACE,
					          error );
				}
				else
				{
					result = libuna_base32_stream_copy_from_byte_stream(
					          destination_buffer,
					          destination_buffer_size,
					          source_buffer,
					          read_count,
					          LIBUNA_BASE32_VARIANT_ALPHABET_NORMAL \
					           | LIBUNA_BASE32_VARIANT_CHARACTER_LIMIT_64 \
					           | LIBUNA_BASE32_VARIANT_PADDING_REQUIRED,
					          error );
				}
				break;

			case UNACOMMON_ENCODING_BASE32HEX:
				if( export_handle->base_encoding_mode == UNACOMMON_ENCODING_MODE_DECODE )
				{
					result = libuna_base32_stream_copy_to_byte_stream(
					          source_buffer,
					          read_count,
					          destination_buffer,
					          destination_buffer_size,
					          LIBUNA_BASE32_VARIANT_ALPHABET_HEX \
					           | LIBUNA_BASE32_VARIANT_CHARACTER_LIMIT_NONE \
					           | LIBUNA_BASE32_VARIANT_PADDING_REQUIRED,
					          LIBUNA_BASE32_FLAG_STRIP_WHITESPACE,
					          error );
				}
				else
				{
					result = libuna_base32_stream_copy_from_byte_stream(
					          destination_buffer,
					          destination_buffer_size,
					          source_buffer,
					          read_count,
					          LIBUNA_BASE32_VARIANT_ALPHABET_HEX \
					           | LIBUNA_BASE32_VARIANT_CHARACTER_LIMIT_64 \
					           | LIBUNA_BASE32_VARIANT_PADDING_REQUIRED,
					          error );
				}
				break;

			case UNACOMMON_ENCODING_BASE64:
				if( export_handle->base_encoding_mode == UNACOMMON_ENCODING_MODE_DECODE )
				{
					result = libuna_base64_stream_copy_to_byte_stream(
					          source_buffer,
					          read_count,
					          destination_buffer,
					          destination_buffer_size,
					          LIBUNA_BASE64_VARIANT_ALPHABET_NORMAL \
					           | LIBUNA_BASE64_VARIANT_CHARACTER_LIMIT_NONE \
					           | LIBUNA_BASE64_VARIANT_PADDING_REQUIRED,
					          LIBUNA_BASE64_FLAG_STRIP_WHITESPACE,
					          error );
				}
				else
				{
					result = libuna_base64_stream_copy_from_byte_stream(
					          destination_buffer,
					          destination_buffer_size,
					          source_buffer,
					          read_count,
					          LIBUNA_BASE64_VARIANT_MIME,
					          error );
				}
				break;

			case UNACOMMON_ENCODING_BASE64URL:
				if( export_handle->base_encoding_mode == UNACOMMON_ENCODING_MODE_DECODE )
				{
					result = libuna_base64_stream_copy_to_byte_stream(
					          source_buffer,
					          read_count,
					          destination_buffer,
					          destination_buffer_size,
					          LIBUNA_BASE64_VARIANT_URL,
					          LIBUNA_BASE64_FLAG_STRIP_WHITESPACE,
					          error );
				}
				else
				{
					result = libuna_base64_stream_copy_from_byte_stream(
					          destination_buffer,
					          destination_buffer_size,
					          source_buffer,
					          read_count,
					          LIBUNA_BASE64_VARIANT_URL,
					          error );
				}
				break;
		}
		if( result != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_CONVERSION,
			 LIBCERROR_CONVERSION_ERROR_INPUT_FAILED,
			 "%s: unable to %s %s source data.",
			 function,
			 encoding_string,
			 encoding_mode_string );

			goto on_error;
		}
		write_count = libcfile_file_write_buffer(
			       export_handle->destination_file,
			       destination_buffer,
			       write_size,
			       error );

		if( write_count < 0 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_IO,
			 LIBCERROR_IO_ERROR_WRITE_FAILED,
			 "%s: unable to write to destination.",
			 function );

			goto on_error;
		}
		if( process_status_update_unknown_total(
		     process_status,
		     export_count,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_SET_FAILED,
			 "%s: unable to update process status.",
			 function );

			goto on_error;
		}
	}
	if( process_status_stop(
	     process_status,
	     (size64_t) export_count,
	     PROCESS_STATUS_COMPLETED,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_SET_FAILED,
		 "%s: unable to stop process status.",
		 function );

		goto on_error;
	}
	memory_free(
	 source_buffer );

	source_buffer = NULL;

	memory_free(
	 destination_buffer );

	destination_buffer = NULL;

	return( 1 );

on_error:
	if( process_status != NULL )
	{
		process_status_stop(
		 process_status,
		 (size64_t) export_count,
		 PROCESS_STATUS_FAILED,
		 NULL );
	}
	if( destination_buffer != NULL )
	{
		memory_free(
		 destination_buffer );
	}
	if( source_buffer != NULL )
	{
		memory_free(
		 source_buffer );
	}
	return( -1 );
}

/* Exports the text-encoded source file to the destination file
 * Returns the number of bytes of the source processed or -1 on error
 */
int export_handle_export_text_encoded_input(
     export_handle_t *export_handle,
     process_status_t *process_status,
     libcerror_error_t **error )
{
	libuna_unicode_character_t unicode_character[ 2 ];

	uint8_t *destination_buffer                  = NULL;
	uint8_t *source_buffer                       = NULL;
	static char *function                        = "export_handle_export_text_encoded_input";
	size64_t export_count                        = 0;
	size_t destination_buffer_index              = 0;
	size_t destination_buffer_size               = UNAEXPORT_HANDLE_BUFFER_SIZE;
	size_t last_source_buffer_index              = 0;
	size_t realignment_iterator                  = 0;
	size_t source_buffer_index                   = 0;
	size_t source_buffer_size                    = UNAEXPORT_HANDLE_BUFFER_SIZE;
	ssize_t read_count                           = 0;
	ssize_t write_count                          = 0;
	uint32_t destination_utf7_stream_base64_data = 0;
	uint32_t source_utf7_stream_base64_data      = 0;
	uint8_t analyze_first_character              = 1;
	uint8_t number_of_unicode_characters         = 0;
	uint8_t unicode_character_index              = 0;
	int result                                   = 1;

	if( export_handle == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid export handle.",
		 function );

		return( -1 );
	}
	if( export_handle->mode != UNAEXPORT_HANDLE_MODE_TEXT_ENCODING )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_UNSUPPORTED_VALUE,
		 "%s: invalid export handle - unsupported mode.",
		 function );

		return( -1 );
	}
	if( ( export_handle->text_input_format != UNACOMMON_FORMAT_AUTO_DETECT )
	 && ( export_handle->text_input_format != UNACOMMON_FORMAT_BYTE_STREAM )
	 && ( export_handle->text_input_format != UNACOMMON_FORMAT_UTF7 )
	 && ( export_handle->text_input_format != UNACOMMON_FORMAT_UTF8 )
	 && ( export_handle->text_input_format != UNACOMMON_FORMAT_UTF16BE )
	 && ( export_handle->text_input_format != UNACOMMON_FORMAT_UTF16LE )
	 && ( export_handle->text_input_format != UNACOMMON_FORMAT_UTF32BE )
	 && ( export_handle->text_input_format != UNACOMMON_FORMAT_UTF32LE ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_UNSUPPORTED_VALUE,
		 "%s: invalid export handle - unsupported input format.",
		 function );

		return( -1 );
	}
	if( ( export_handle->text_output_format != UNACOMMON_FORMAT_BYTE_STREAM )
	 && ( export_handle->text_output_format != UNACOMMON_FORMAT_UTF7 )
	 && ( export_handle->text_output_format != UNACOMMON_FORMAT_UTF8 )
	 && ( export_handle->text_output_format != UNACOMMON_FORMAT_UTF16BE )
	 && ( export_handle->text_output_format != UNACOMMON_FORMAT_UTF16LE )
	 && ( export_handle->text_output_format != UNACOMMON_FORMAT_UTF32BE )
	 && ( export_handle->text_output_format != UNACOMMON_FORMAT_UTF32LE ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_UNSUPPORTED_VALUE,
		 "%s: invalid export handle - unsupported output format.",
		 function );

		return( -1 );
	}
	if( ( export_handle->text_newline_conversion != UNACOMMON_NEWLINE_CONVERSION_NONE )
	 && ( export_handle->text_newline_conversion != UNACOMMON_NEWLINE_CONVERSION_CRLF )
	 && ( export_handle->text_newline_conversion != UNACOMMON_NEWLINE_CONVERSION_CR )
	 && ( export_handle->text_newline_conversion != UNACOMMON_NEWLINE_CONVERSION_LF ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_UNSUPPORTED_VALUE,
		 "%s: invalid export handle - unsupported newline conversion.",
		 function );

		return( -1 );
	}
	source_buffer = (uint8_t *) memory_allocate(
	                             sizeof( uint8_t ) * source_buffer_size );

	if( source_buffer == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
		 "%s: unable to create source buffer.",
		 function );

		goto on_error;
	}
	destination_buffer = (uint8_t *) memory_allocate(
	                                  sizeof( uint8_t ) * destination_buffer_size );

	if( destination_buffer == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
		 "%s: unable to create destination buffer.",
		 function );

		goto on_error;
	}
	if( export_handle->text_export_byte_order_mark != 0 )
	{
		switch( export_handle->text_output_format )
		{
			case UNACOMMON_FORMAT_UTF8:
				result = libuna_utf8_stream_copy_byte_order_mark(
				          destination_buffer,
				          destination_buffer_size,
				          &destination_buffer_index,
				          error );
				break;

			case UNACOMMON_FORMAT_UTF16BE:
				result = libuna_utf16_stream_copy_byte_order_mark(
				          destination_buffer,
				          destination_buffer_size,
				          &destination_buffer_index,
				          LIBUNA_ENDIAN_BIG,
				          error );
				break;

			case UNACOMMON_FORMAT_UTF16LE:
				result = libuna_utf16_stream_copy_byte_order_mark(
				          destination_buffer,
				          destination_buffer_size,
				          &destination_buffer_index,
				          LIBUNA_ENDIAN_LITTLE,
				          error );
				break;

			case UNACOMMON_FORMAT_UTF32BE:
				result = libuna_utf32_stream_copy_byte_order_mark(
				          destination_buffer,
				          destination_buffer_size,
				          &destination_buffer_index,
				          LIBUNA_ENDIAN_BIG,
				          error );
				break;

			case UNACOMMON_FORMAT_UTF32LE:
				result = libuna_utf32_stream_copy_byte_order_mark(
				          destination_buffer,
				          destination_buffer_size,
				          &destination_buffer_index,
				          LIBUNA_ENDIAN_LITTLE,
				          error );
				break;

			default:
				result = 1;
				break;
		}
		if( result != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_SET_FAILED,
			 "%s: unable to set byte order mark.",
			 function );

			goto on_error;
		}
	}
	while( 1 )
	{
		read_count = libcfile_file_read_buffer(
		              export_handle->source_file,
		              &( source_buffer[ source_buffer_index ] ),
		              source_buffer_size - source_buffer_index,
		              error );

		if( read_count < 0 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_IO,
			 LIBCERROR_IO_ERROR_READ_FAILED,
			 "%s: unable to read from source.",
			 function );

			goto on_error;
		}
		export_count       += read_count;
		read_count         += (ssize_t) source_buffer_index;
		source_buffer_index = 0;

		if( read_count == 0 )
		{
			break;
		}
		if( analyze_first_character != 0 )
		{
			if( ( read_count >= 3 )
			 && ( source_buffer[ 0 ] == 0xef )
			 && ( source_buffer[ 1 ] == 0xbb )
			 && ( source_buffer[ 2 ] == 0xbf ) )
			{
				if( export_handle->text_input_format == UNACOMMON_FORMAT_AUTO_DETECT )
				{
					export_handle->text_input_format = UNACOMMON_FORMAT_UTF8;
				}
				if( export_handle->text_input_format == UNACOMMON_FORMAT_UTF8 )
				{
					source_buffer_index += 3;
				}
			}
			else if( ( read_count >= 2 )
			      && ( source_buffer[ 0 ] == 0xfe )
			      && ( source_buffer[ 1 ] == 0xff ) )
			{
				if( export_handle->text_input_format == UNACOMMON_FORMAT_AUTO_DETECT )
				{
					export_handle->text_input_format = UNACOMMON_FORMAT_UTF16BE;
				}
				if( export_handle->text_input_format == UNACOMMON_FORMAT_UTF16BE )
				{
					source_buffer_index += 2;
				}
			}
			else if( ( read_count >= 2 )
			      && ( source_buffer[ 0 ] == 0xff )
			      && ( source_buffer[ 1 ] == 0xfe ) )
			{
				if( ( read_count >= 4 )
				 && ( source_buffer[ 2 ] == 0x00 )
			         && ( source_buffer[ 3 ] == 0x00 ) )
				{
					if( export_handle->text_input_format == UNACOMMON_FORMAT_AUTO_DETECT )
					{
						export_handle->text_input_format = UNACOMMON_FORMAT_UTF32LE;
					}
					if( export_handle->text_input_format == UNACOMMON_FORMAT_UTF32LE )
					{
						source_buffer_index += 4;
					}
				}
				else
				{
					if( export_handle->text_input_format == UNACOMMON_FORMAT_AUTO_DETECT )
					{
						export_handle->text_input_format = UNACOMMON_FORMAT_UTF16LE;
					}
					if( export_handle->text_input_format == UNACOMMON_FORMAT_UTF16LE )
					{
						source_buffer_index += 2;
					}
				}
			}
			else if( ( read_count >= 4 )
			      && ( source_buffer[ 0 ] == 0x00 )
			      && ( source_buffer[ 1 ] == 0x00 )
			      && ( source_buffer[ 2 ] == 0xfe )
			      && ( source_buffer[ 3 ] == 0xff ) )
			{
				if( export_handle->text_input_format == UNACOMMON_FORMAT_AUTO_DETECT )
				{
					export_handle->text_input_format = UNACOMMON_FORMAT_UTF32BE;
				}
				if( export_handle->text_input_format == UNACOMMON_FORMAT_UTF32BE )
				{
					source_buffer_index += 4;
				}
			}
			else if( export_handle->text_input_format == UNACOMMON_FORMAT_AUTO_DETECT )
			{
				export_handle->text_input_format = UNACOMMON_FORMAT_BYTE_STREAM;
			}
			read_count -= (ssize_t) source_buffer_index;

			analyze_first_character = 0;
		}
		last_source_buffer_index = source_buffer_index;

		while( read_count > 0 )
		{
			/* Sanity check
			 */
			if( source_buffer_index >= source_buffer_size )
			{
				break;
			}
			/* Make sure to have at least room for a 6 byte character in the destination buffer
			 */
		 	if( destination_buffer_index >= ( destination_buffer_size - 5 ) )
			{
				break;
			}
			switch( export_handle->text_input_format )
			{
				case UNACOMMON_FORMAT_BYTE_STREAM:
					result = libuna_unicode_character_copy_from_byte_stream(
						  &unicode_character[ unicode_character_index ],
						  source_buffer,
						  source_buffer_size,
						  &source_buffer_index,
						  export_handle->text_byte_stream_codepage,
					          error );
					break;

				case UNACOMMON_FORMAT_UTF7:
					result = libuna_unicode_character_copy_from_utf7_stream(
						  &unicode_character[ unicode_character_index ],
						  source_buffer,
						  source_buffer_size,
						  &source_buffer_index,
						  &source_utf7_stream_base64_data,
					          error );
					break;

				case UNACOMMON_FORMAT_UTF8:
					result = libuna_unicode_character_copy_from_utf8(
						  &unicode_character[ unicode_character_index ],
						  source_buffer,
						  source_buffer_size,
						  &source_buffer_index,
					          error );
					break;

				case UNACOMMON_FORMAT_UTF16BE:
					result = libuna_unicode_character_copy_from_utf16_stream(
						  &unicode_character[ unicode_character_index ],
						  source_buffer,
						  source_buffer_size,
						  &source_buffer_index,
						  LIBUNA_ENDIAN_BIG,
					          error );
					break;

				case UNACOMMON_FORMAT_UTF16LE:
					result = libuna_unicode_character_copy_from_utf16_stream(
						  &unicode_character[ unicode_character_index ],
						  source_buffer,
						  source_buffer_size,
						  &source_buffer_index,
						  LIBUNA_ENDIAN_LITTLE,
					          error );
					break;

				case UNACOMMON_FORMAT_UTF32BE:
					result = libuna_unicode_character_copy_from_utf32_stream(
						  &unicode_character[ unicode_character_index ],
						  source_buffer,
						  source_buffer_size,
						  &source_buffer_index,
						  LIBUNA_ENDIAN_BIG,
					          error );
					break;

				case UNACOMMON_FORMAT_UTF32LE:
					result = libuna_unicode_character_copy_from_utf32_stream(
						  &unicode_character[ unicode_character_index ],
						  source_buffer,
						  source_buffer_size,
						  &source_buffer_index,
						  LIBUNA_ENDIAN_LITTLE,
					          error );
					break;

				default:
					result = -1;
					break;
			}
			if( result != 1 )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_CONVERSION,
				 LIBCERROR_CONVERSION_ERROR_INPUT_FAILED,
				 "%s: unable to convert input character.",
				 function );

				goto on_error;
			}
			number_of_unicode_characters++;

			read_count -= source_buffer_index - last_source_buffer_index;

			last_source_buffer_index = source_buffer_index;

			if( export_handle->text_newline_conversion != UNACOMMON_NEWLINE_CONVERSION_NONE )
			{
				/* Determine if character is a line feed (LF)
				 */
				if( unicode_character[ unicode_character_index ] == 0x000a )
				{
					if( export_handle->text_newline_conversion == UNACOMMON_NEWLINE_CONVERSION_CRLF )
					{
						if( unicode_character_index == 0 )
						{
							unicode_character[ unicode_character_index     ] = 0x000d;
							unicode_character[ unicode_character_index + 1 ] = 0x000a;

							number_of_unicode_characters++;
						}
					}
					else if( export_handle->text_newline_conversion == UNACOMMON_NEWLINE_CONVERSION_CR )
					{
						if( unicode_character_index == 0 )
						{
							unicode_character[ unicode_character_index ] = 0x000d;
						}
						else if( unicode_character_index == 1 )
						{
							unicode_character[ unicode_character_index - 1 ] = 0x000d;

							number_of_unicode_characters--;
						}
					}
					else if( export_handle->text_newline_conversion == UNACOMMON_NEWLINE_CONVERSION_LF )
					{
						if( unicode_character_index == 1 )
						{
							unicode_character[ unicode_character_index - 1 ] = 0x000a;

							number_of_unicode_characters--;
						}
					}
				}
				/* Determine if character is a carriage return (CR)
				 */
				else if( unicode_character[ unicode_character_index ] == 0x000d )
				{
					if( unicode_character_index == 0 )
					{
						unicode_character_index++;

						continue;
					}
				}
			}
			/* Write all unicode characters
			 */
			for( unicode_character_index = 0;
			     unicode_character_index < number_of_unicode_characters;
			     unicode_character_index++ )
			{
				switch( export_handle->text_output_format )
				{
					case UNACOMMON_FORMAT_BYTE_STREAM:
						result = libuna_unicode_character_copy_to_byte_stream(
							  unicode_character[ unicode_character_index ],
							  destination_buffer,
							  destination_buffer_size,
							  &destination_buffer_index,
							  export_handle->text_byte_stream_codepage,
						          error );
						break;

					case UNACOMMON_FORMAT_UTF7:
						result = libuna_unicode_character_copy_to_utf7_stream(
							  unicode_character[ unicode_character_index ],
							  destination_buffer,
							  destination_buffer_size,
							  &destination_buffer_index,
							  &destination_utf7_stream_base64_data,
						          error );
						break;

					case UNACOMMON_FORMAT_UTF8:
						result = libuna_unicode_character_copy_to_utf8(
							  unicode_character[ unicode_character_index ],
							  destination_buffer,
							  destination_buffer_size,
							  &destination_buffer_index,
						          error );
						break;

					case UNACOMMON_FORMAT_UTF16BE:
						result = libuna_unicode_character_copy_to_utf16_stream(
							  unicode_character[ unicode_character_index ],
							  destination_buffer,
							  destination_buffer_size,
							  &destination_buffer_index,
							  LIBUNA_ENDIAN_BIG,
						          error );
						break;

					case UNACOMMON_FORMAT_UTF16LE:
						result = libuna_unicode_character_copy_to_utf16_stream(
							  unicode_character[ unicode_character_index ],
							  destination_buffer,
							  destination_buffer_size,
							  &destination_buffer_index,
							  LIBUNA_ENDIAN_LITTLE,
						          error );
						break;

					case UNACOMMON_FORMAT_UTF32BE:
						result = libuna_unicode_character_copy_to_utf32_stream(
							  unicode_character[ unicode_character_index ],
							  destination_buffer,
							  destination_buffer_size,
							  &destination_buffer_index,
							  LIBUNA_ENDIAN_BIG,
						          error );
						break;

					case UNACOMMON_FORMAT_UTF32LE:
						result = libuna_unicode_character_copy_to_utf32_stream(
							  unicode_character[ unicode_character_index ],
							  destination_buffer,
							  destination_buffer_size,
							  &destination_buffer_index,
							  LIBUNA_ENDIAN_LITTLE,
						          error );
						break;

					default:
						result = -1;
						break;
				}
				if( result != 1 )
				{
					libcerror_error_set(
					 error,
					 LIBCERROR_ERROR_DOMAIN_CONVERSION,
					 LIBCERROR_CONVERSION_ERROR_OUTPUT_FAILED,
					 "%s: unable to convert output character.",
					 function );

					goto on_error;
				}
			}
			number_of_unicode_characters = 0;
			unicode_character_index      = 0;
		}
		if( destination_buffer_index > 0 )
		{
			write_count = libcfile_file_write_buffer(
			               export_handle->destination_file,
			               destination_buffer,
		        	       destination_buffer_index,
			               error );

			if( write_count < 0 )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_IO,
				 LIBCERROR_IO_ERROR_WRITE_FAILED,
				 "%s: unable to write to destination.",
				 function );

				goto on_error;
			}
			destination_buffer_index = 0;
		}
		/* Realign the remaining bytes to the start of the source buffer
		 */
		realignment_iterator = source_buffer_index;
		source_buffer_index  = 0;

		for( ;
		     read_count > 0;
		     read_count-- )
		{
			if( realignment_iterator >= source_buffer_size )
			{
				break;
			}
			source_buffer[ source_buffer_index++ ] = source_buffer[ realignment_iterator++ ];
		}
		if( process_status_update_unknown_total(
		     process_status,
		     export_count,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_SET_FAILED,
			 "%s: unable to update process status.",
			 function );

			goto on_error;
		}
	}
	if( process_status_stop(
	     process_status,
	     (size64_t) export_count,
	     PROCESS_STATUS_COMPLETED,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_SET_FAILED,
		 "%s: unable to stop process status.",
		 function );

		goto on_error;
	}
	memory_free(
	 source_buffer );

	source_buffer = NULL;

	memory_free(
	 destination_buffer );

	destination_buffer = NULL;

	return( 1 );

on_error:
	if( process_status != NULL )
	{
		process_status_stop(
		 process_status,
		 (size64_t) export_count,
		 PROCESS_STATUS_FAILED,
		 NULL );
	}
	if( destination_buffer != NULL )
	{
		memory_free(
		 destination_buffer );
	}
	if( source_buffer != NULL )
	{
		memory_free(
		 source_buffer );
	}
	return( -1 );
}

/* Prints an overview of the parameters
 * Returns 1 if successful or -1 on error
 */
int export_handle_print_parameters(
     export_handle_t *export_handle,
     libcerror_error_t **error )
{
	static char *function = "export_handle_print_parameters";

	if( export_handle == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid export handle.",
		 function );

		return( -1 );
	}
	if( export_handle->notify_stream == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_MISSING,
		 "%s: invalid export handle - missing notify stream.",
		 function );

		return( -1 );
	}
	if( export_handle->source_filename == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_MISSING,
		 "%s: invalid export handle - missing source filename.",
		 function );

		return( -1 );
	}
	if( export_handle->destination_filename == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_MISSING,
		 "%s: invalid export handle - missing destination filename.",
		 function );

		return( -1 );
	}
	if( ( export_handle->mode != UNAEXPORT_HANDLE_MODE_BASE_ENCODING )
	 && ( export_handle->mode != UNAEXPORT_HANDLE_MODE_TEXT_ENCODING ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_UNSUPPORTED_VALUE,
		 "%s: invalid export handle - unsupported mode.",
		 function );

		return( -1 );
	}
	fprintf(
	 export_handle->notify_stream,
	 "Exporting:\n" );

	if( export_handle->mode == UNAEXPORT_HANDLE_MODE_BASE_ENCODING )
	{
	}
	else if( export_handle->mode == UNAEXPORT_HANDLE_MODE_TEXT_ENCODING )
	{
		fprintf(
		 export_handle->notify_stream,
		 "\tsource:\t\t\t%" PRIs_SYSTEM "\n",
		 export_handle->source_filename );

		fprintf(
		 export_handle->notify_stream,
		 "\tof format:\t\t" );

		export_handle_format_fprint(
		 export_handle->notify_stream,
		 export_handle->text_input_format );

		fprintf(
		 export_handle->notify_stream,
		 "\n" );

		fprintf(
		 export_handle->notify_stream,
		 "\tdestination:\t\t%" PRIs_SYSTEM "\n",
		 export_handle->destination_filename );

		fprintf(
		 export_handle->notify_stream,
		 "\tof format:\t\t" );

		export_handle_format_fprint(
		 export_handle->notify_stream,
		 export_handle->text_output_format );

		fprintf(
		 export_handle->notify_stream,
		 "\n" );

		fprintf(
		 export_handle->notify_stream,
		 "\tbyte-stream codepage:\t" );

		export_handle_codepage_fprint(
		 export_handle->notify_stream,
		 export_handle->text_byte_stream_codepage );

		fprintf(
		 export_handle->notify_stream,
		 "\n" );

		fprintf(
		 export_handle->notify_stream,
		 "\texport byte order mark:\t" );

		if( export_handle->text_export_byte_order_mark == 0 )
		{
			fprintf(
			 export_handle->notify_stream,
			 "no" );
		}
		else
		{
			fprintf(
			 export_handle->notify_stream,
			 "yes" );
		}
		fprintf(
		 export_handle->notify_stream,
		 "\n" );

		fprintf(
		 export_handle->notify_stream,
		 "\tnewline conversion:\t" );

		if( export_handle->text_newline_conversion == UNACOMMON_NEWLINE_CONVERSION_NONE )
		{
			fprintf(
			 export_handle->notify_stream,
			 "none" );
		}
		else if( export_handle->text_newline_conversion == UNACOMMON_NEWLINE_CONVERSION_CRLF )
		{
			fprintf(
			 export_handle->notify_stream,
			 "carriage return and line feed (crlf)" );
		}
		else if( export_handle->text_newline_conversion == UNACOMMON_NEWLINE_CONVERSION_CR )
		{
			fprintf(
			 export_handle->notify_stream,
			 "carriage return (cr)" );
		}
		else if( export_handle->text_newline_conversion == UNACOMMON_NEWLINE_CONVERSION_LF )
		{
			fprintf(
			 export_handle->notify_stream,
			 "line feed (lf)" );
		}
		else
		{
			fprintf(
			 export_handle->notify_stream,
			 "unsupported" );
		}
		fprintf(
		 export_handle->notify_stream,
		 "\n" );
	}
	fprintf(
	 export_handle->notify_stream,
	 "\n" );

	return( 1 );
}

/* Prints the codepage information
 */
void export_handle_codepage_fprint(
      FILE *stream,
      int codepage )
{
	if( stream == NULL )
	{
		return;
	}
	switch( codepage )
	{
		case LIBUNA_CODEPAGE_ASCII:
			fprintf(
			 stream,
			 "ASCII (US-ASCII)" );
			break;

		case LIBUNA_CODEPAGE_ISO_8859_1:
			fprintf(
			 stream,
			 "ISO 8859-1 (Western European)" );
			break;

		case LIBUNA_CODEPAGE_ISO_8859_2:
			fprintf(
			 stream,
			 "ISO 8859-2 (Central European)" );
			break;

		case LIBUNA_CODEPAGE_ISO_8859_3:
			fprintf(
			 stream,
			 "ISO 8859-3 (South European)" );
			break;

		case LIBUNA_CODEPAGE_ISO_8859_4:
			fprintf(
			 stream,
			 "ISO 8859-4 (North European)" );
			break;

		case LIBUNA_CODEPAGE_ISO_8859_5:
			fprintf(
			 stream,
			 "ISO 8859-5 (Cyrillic)" );
			break;

		case LIBUNA_CODEPAGE_ISO_8859_6:
			fprintf(
			 stream,
			 "ISO 8859-6 (Arabic)" );
			break;

		case LIBUNA_CODEPAGE_ISO_8859_7:
			fprintf(
			 stream,
			 "ISO 8859-7 (Greek)" );
			break;

		case LIBUNA_CODEPAGE_ISO_8859_8:
			fprintf(
			 stream,
			 "ISO 8859-8 (Hebrew)" );
			break;

		case LIBUNA_CODEPAGE_ISO_8859_9:
			fprintf(
			 stream,
			 "ISO 8859-9 (Turkish)" );
			break;

		case LIBUNA_CODEPAGE_ISO_8859_10:
			fprintf(
			 stream,
			 "ISO 8859-10 (Nordic)" );
			break;

		case LIBUNA_CODEPAGE_ISO_8859_11:
			fprintf(
			 stream,
			 "ISO 8859-11 (Thai)" );
			break;

		case LIBUNA_CODEPAGE_ISO_8859_13:
			fprintf(
			 stream,
			 "ISO 8859-13 (Baltic)" );
			break;

		case LIBUNA_CODEPAGE_ISO_8859_14:
			fprintf(
			 stream,
			 "ISO 8859-14 (Celtic)" );
			break;

		case LIBUNA_CODEPAGE_ISO_8859_15:
			fprintf(
			 stream,
			 "ISO 8859-15 (Latin-9)" );
			break;

		case LIBUNA_CODEPAGE_ISO_8859_16:
			fprintf(
			 stream,
			 "ISO 8859-16 (Latin-10)" );
			break;

		case LIBUNA_CODEPAGE_KOI8_R:
			fprintf(
			 stream,
			 "koi8-r (Russian)" );
			break;

		case LIBUNA_CODEPAGE_KOI8_U:
			fprintf(
			 stream,
			 "koi8-u (Ukrainian)" );
			break;

		case LIBUNA_CODEPAGE_WINDOWS_874:
			fprintf(
			 stream,
			 "Windows 874 (Thai)" );
			break;

		case LIBUNA_CODEPAGE_WINDOWS_932:
			fprintf(
			 stream,
			 "Windows 932 (Japanese)" );
			break;

		case LIBUNA_CODEPAGE_WINDOWS_936:
			fprintf(
			 stream,
			 "Windows 936 (Simplified Chinese GBK)" );
			break;

		case LIBUNA_CODEPAGE_WINDOWS_1250:
			fprintf(
			 stream,
			 "Windows 1250 (Central European)" );
			break;

		case LIBUNA_CODEPAGE_WINDOWS_1251:
			fprintf(
			 stream,
			 "Windows 1251 (Cyrillic)" );
			break;

		case LIBUNA_CODEPAGE_WINDOWS_1252:
			fprintf(
			 stream,
			 "Windows 1252 (Western European/Latin 1)" );
			break;

		case LIBUNA_CODEPAGE_WINDOWS_1253:
			fprintf(
			 stream,
			 "Windows 1253 (Greek)" );
			break;

		case LIBUNA_CODEPAGE_WINDOWS_1254:
			fprintf(
			 stream,
			 "Windows 1254 (Turkish)" );
			break;

		case LIBUNA_CODEPAGE_WINDOWS_1255:
			fprintf(
			 stream,
			 "Windows 1255 (Hebrew)" );
			break;

		case LIBUNA_CODEPAGE_WINDOWS_1256:
			fprintf(
			 stream,
			 "Windows 1256 (Arabic)" );
			break;

		case LIBUNA_CODEPAGE_WINDOWS_1257:
			fprintf(
			 stream,
			 "Windows 1257 (Baltic)" );
			break;

		case LIBUNA_CODEPAGE_WINDOWS_1258:
			fprintf(
			 stream,
			 "Windows 1258 (Vietnamese)" );
			break;

		default:
			fprintf(
			 stream,
			 "unsupported" );
			break;
	}
}

/* Prints the codepages information
 */
void export_handle_codepages_fprint(
      FILE *stream )
{
	if( stream == NULL )
	{
		return;
	}
	fprintf(
	 stream,
	 "\tCodepage:     Description:\n"
	 "\tascii:        Support 7-bit ASCII (US-ASCII) character set\n"
	 "\tiso-8859-1:   Support ISO 8859-1 (Western European) character set\n"
	 "\tiso-8859-2:   Support ISO 8859-2 (Central European) character set\n"
	 "\tiso-8859-3:   Support ISO 8859-3 (South European) character set\n"
	 "\tiso-8859-4:   Support ISO 8859-4 (North European) character set\n"
	 "\tiso-8859-5:   Support ISO 8859-5 (Cyrillic) character set\n"
	 "\tiso-8859-6:   Support ISO 8859-6 (Arabic) character set\n"
	 "\tiso-8859-7:   Support ISO 8859-7 (Greek) character set\n"
	 "\tiso-8859-8:   Support ISO 8859-8 (Hebrew) character set\n"
	 "\tiso-8859-9:   Support ISO 8859-9 (Turkish) character set\n"
	 "\tiso-8859-10:  Support ISO 8859-10 (Nordic) character set\n"
	 "\tiso-8859-11:  Support ISO 8859-11 (Thai) character set\n"
	 "\tiso-8859-13:  Support ISO 8859-13 (Baltic) character set\n"
	 "\tiso-8859-14:  Support ISO 8859-14 (Celtic) character set\n"
	 "\tiso-8859-15:  Support ISO 8859-14 (Latin-9) character set\n"
	 "\tiso-8859-16:  Support ISO 8859-16 (Latin-10) character set\n"
	 "\tkoi8-r:       Support KOI8-R (Russian) character set\n"
	 "\tkoi8-u:       Support KOI8-U (Ukrainian) character set\n"
	 "\twindows-874:  Supports the Windows 874 (Thai) character set\n"
	 "\twindows-1250: Supports the Windows 1250 (Central European) character set\n"
	 "\twindows-1251: Supports the Windows 1251 (Cyrillic) character set\n"
	 "\twindows-1252: Supports the Windows 1250 (Western European/Latin 1)\n"
	 "\t              character set\n"
	 "\twindows-1253: Supports the Windows 1253 (Greek) character set\n"
	 "\twindows-1254: Supports the Windows 1254 (Turkish) character set\n"
	 "\twindows-1255: Supports the Windows 1255 (Hebrew) character set\n"
	 "\twindows-1256: Supports the Windows 1256 (Arabic) character set\n"
	 "\twindows-1257: Supports the Windows 1257 (Baltic) character set\n"
	 "\twindows-1258: Supports the Windows 1258 (Vietnamese) character set\n" );
}

/* Prints the format (encoding) information
 */
void export_handle_format_fprint(
      FILE *stream,
      int format )
{
	if( stream == NULL )
	{
		return;
	}
	switch( format )
	{
		case UNACOMMON_FORMAT_AUTO_DETECT:
			fprintf(
			 stream,
			 "auto detect" );
			break;

		case UNACOMMON_FORMAT_BYTE_STREAM:
			fprintf(
			 stream,
			 "byte stream" );
			break;

		case UNACOMMON_FORMAT_UTF7:
			fprintf(
			 stream,
			 "UTF-7" );
			break;

		case UNACOMMON_FORMAT_UTF8:
			fprintf(
			 stream,
			 "UTF-8" );
			break;

		case UNACOMMON_FORMAT_UTF16BE:
			fprintf(
			 stream,
			 "UTF-16 big endian" );
			break;

		case UNACOMMON_FORMAT_UTF16LE:
			fprintf(
			 stream,
			 "UTF-16 little endian" );
			break;

		case UNACOMMON_FORMAT_UTF32BE:
			fprintf(
			 stream,
			 "UTF-32 big endian" );
			break;

		case UNACOMMON_FORMAT_UTF32LE:
			fprintf(
			 stream,
			 "UTF-32 little endian" );
			break;

		default:
			fprintf(
			 stream,
			 "unsupported" );
			break;
	}
}

