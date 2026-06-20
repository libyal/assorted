/*
 * Common functions for unabase and unaexport
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

#if !defined( _UNACOMMON_H )
#define _UNACOMMON_H

#include <common.h>

#if defined( __cplusplus )
extern "C" {
#endif

enum UNACOMMON_ENCODINGS
{
	UNACOMMON_ENCODING_BASE16,
	UNACOMMON_ENCODING_BASE32,
	UNACOMMON_ENCODING_BASE32HEX,
	UNACOMMON_ENCODING_BASE64,
	UNACOMMON_ENCODING_BASE64URL,
};

enum UNACOMMON_ENCODING_MODES
{
	UNACOMMON_ENCODING_MODE_DECODE,
	UNACOMMON_ENCODING_MODE_ENCODE,
};

enum UNACOMMON_FORMATS
{
	UNACOMMON_FORMAT_AUTO_DETECT,
	UNACOMMON_FORMAT_BYTE_STREAM,
	UNACOMMON_FORMAT_UTF7,
	UNACOMMON_FORMAT_UTF8,
	UNACOMMON_FORMAT_UTF16BE,
	UNACOMMON_FORMAT_UTF16LE,
	UNACOMMON_FORMAT_UTF32BE,
	UNACOMMON_FORMAT_UTF32LE
};

enum UNACOMMON_NEWLINE_CONVERSIONS
{
	UNACOMMON_NEWLINE_CONVERSION_NONE,
	UNACOMMON_NEWLINE_CONVERSION_CR,
	UNACOMMON_NEWLINE_CONVERSION_CRLF,
	UNACOMMON_NEWLINE_CONVERSION_LF
};

#if defined( __cplusplus )
}
#endif

#endif /* !defined( _UNACOMMON_H ) */

