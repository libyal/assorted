/*
 * Common input functions for unabase and unaexport
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
#include <narrow_string.h>
#include <system_string.h>
#include <types.h>
#include <wide_string.h>

#include "assorted_libcerror.h"
#include "assorted_libuna.h"
#include "unacommon.h"
#include "unainput.h"

/* Determines the encoding from a string
 * Returns 1 if successful or -1 on error
 */
int unainput_determine_encoding(
     const system_character_t *string,
     uint8_t *encoding,
     libcerror_error_t **error )
{
	static char *function = "unainput_determine_encoding";
	size_t string_length  = 0;
	int result            = -1;

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
	if( encoding == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid encoding.",
		 function );

		return( -1 );
	}
	string_length = system_string_length(
	                 string );

	if( string_length == 6 )
	{
		if( system_string_compare(
		     string,
		     _SYSTEM_STRING( "base16" ),
		     6 ) == 0 )
		{
			*encoding = UNACOMMON_ENCODING_BASE16;
			result    = 1;
		}
		else if( system_string_compare(
			  string,
			  _SYSTEM_STRING( "base32" ),
			  6 ) == 0 )
		{
			*encoding = UNACOMMON_ENCODING_BASE32;
			result    = 1;
		}
		else if( system_string_compare(
			  string,
			  _SYSTEM_STRING( "base64" ),
			  6 ) == 0 )
		{
			*encoding = UNACOMMON_ENCODING_BASE64;
			result    = 1;
		}
	}
	else if( string_length == 9 )
	{
		if( system_string_compare(
		     string,
		     _SYSTEM_STRING( "base32hex" ),
		     9 ) == 0 )
		{
			*encoding = UNACOMMON_ENCODING_BASE32HEX;
			result    = 1;
		}
		else if( system_string_compare(
			  string,
			  _SYSTEM_STRING( "base64url" ),
			  9 ) == 0 )
		{
			*encoding = UNACOMMON_ENCODING_BASE64URL;
			result    = 1;
		}
	}
	return( result );
}

/* Determines the encoding mode from a string
 * Returns 1 if successful or -1 on error
 */
int unainput_determine_encoding_mode(
     const system_character_t *string,
     uint8_t *encoding_mode,
     libcerror_error_t **error )
{
	static char *function = "unainput_determine_encoding_mode";
	size_t string_length  = 0;
	int result            = -1;

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
	if( encoding_mode == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid encoding mode.",
		 function );

		return( -1 );
	}
	string_length = system_string_length(
	                 string );

	if( string_length == 6 )
	{
		if( system_string_compare(
		     string,
		     _SYSTEM_STRING( "decode" ),
		     6 ) == 0 )
		{
			*encoding_mode = UNACOMMON_ENCODING_MODE_DECODE;
			result         = 1;
		}
		else if( system_string_compare(
			  string,
			  _SYSTEM_STRING( "encode" ),
			  6 ) == 0 )
		{
			*encoding_mode = UNACOMMON_ENCODING_MODE_ENCODE;
			result         = 1;
		}
	}
	return( result );
}

/* Determines the format from a string
 * Returns 1 if successful or -1 on error
 */
int unainput_determine_format(
     const system_character_t *string,
     uint8_t *format,
     libcerror_error_t **error )
{
	static char *function = "unainput_determine_format";
	size_t string_length  = 0;
	int result            = -1;

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
	if( format == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid format.",
		 function );

		return( -1 );
	}
	string_length = system_string_length(
	                 string );

	if( string_length == 4 )
	{
		if( system_string_compare(
		     string,
		     _SYSTEM_STRING( "utf7" ),
		     4 ) == 0 )
		{
			*format = UNACOMMON_FORMAT_UTF7;
			result  = 1;
		}
		else if( system_string_compare(
			  string,
			  _SYSTEM_STRING( "utf8" ),
			  4 ) == 0 )
		{
			*format = UNACOMMON_FORMAT_UTF8;
			result  = 1;
		}
	}
	else if( string_length == 7 )
	{
		if( system_string_compare(
		     string,
		     _SYSTEM_STRING( "utf16be" ),
		     7 ) == 0 )
		{
			*format = UNACOMMON_FORMAT_UTF16BE;
			result  = 1;
		}
		else if( system_string_compare(
			  string,
			  _SYSTEM_STRING( "utf16le" ),
			  7 ) == 0 )
		{
			*format = UNACOMMON_FORMAT_UTF16LE;
			result  = 1;
		}
		else if( system_string_compare(
			  string,
			  _SYSTEM_STRING( "utf32be" ),
			  7 ) == 0 )
		{
			*format = UNACOMMON_FORMAT_UTF32BE;
			result  = 1;
		}
		else if( system_string_compare(
			  string,
			  _SYSTEM_STRING( "utf32le" ),
			  7 ) == 0 )
		{
			*format = UNACOMMON_FORMAT_UTF32LE;
			result  = 1;
		}
	}
	else if( string_length == 11 )
	{
		if( system_string_compare(
		     string,
		     _SYSTEM_STRING( "byte-stream" ),
		     11 ) == 0 )
		{
			*format = UNACOMMON_FORMAT_BYTE_STREAM;
			result  = 1;
		}
		else if( system_string_compare(
			  string,
			  _SYSTEM_STRING( "byte_stream" ),
			  11 ) == 0 )
		{
			*format = UNACOMMON_FORMAT_BYTE_STREAM;
			result  = 1;
		}
	}
	return( result );
}

/* Determines the newline conversion from a string
 * Returns 1 if successful, 0 if unsupported value or -1 on error
 */
int unainput_determine_newline_conversion(
     const system_character_t *string,
     uint8_t *newline_conversion,
     libcerror_error_t **error )
{
	static char *function = "unainput_determine_newline_conversion";
	size_t string_length  = 0;
	int result            = 0;

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
	if( newline_conversion == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid newline conversion.",
		 function );

		return( -1 );
	}
	string_length = system_string_length(
	                 string );

	if( string_length == 2 )
	{
		if( system_string_compare(
		     string,
		     _SYSTEM_STRING( "cr" ),
		     2 ) == 0 )
		{
			*newline_conversion = UNACOMMON_NEWLINE_CONVERSION_CR;
			result              = 1;
		}
		else if( system_string_compare(
			  string,
			  _SYSTEM_STRING( "lf" ),
			  2 ) == 0 )
		{
			*newline_conversion = UNACOMMON_NEWLINE_CONVERSION_LF;
			result              = 1;
		}
	}
	else if( string_length == 4 )
	{
		if( system_string_compare(
		     string,
		     _SYSTEM_STRING( "none" ),
		     4 ) == 0 )
		{
			*newline_conversion = UNACOMMON_NEWLINE_CONVERSION_NONE;
			result              = 1;
		}
		else if( system_string_compare(
			  string,
			  _SYSTEM_STRING( "crlf" ),
			  4 ) == 0 )
		{
			*newline_conversion = UNACOMMON_NEWLINE_CONVERSION_CRLF;
			result              = 1;
		}
	}
	return( result );
}

