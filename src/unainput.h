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

#if !defined( _UNAINPUT_H )
#define _UNAINPUT_H

#include <common.h>
#include <types.h>

#include "assorted_libcerror.h"

#if defined( __cplusplus )
extern "C" {
#endif

int unainput_determine_encoding(
     const system_character_t *string,
     uint8_t *encoding,
     libcerror_error_t **error );

int unainput_determine_encoding_mode(
     const system_character_t *string,
     uint8_t *encoding_mode,
     libcerror_error_t **error );

int unainput_determine_format(
     const system_character_t *string,
     uint8_t *format,
     libcerror_error_t **error );

int unainput_determine_format(
     const system_character_t *argument,
     uint8_t *format,
     libcerror_error_t **error );

int unainput_determine_newline_conversion(
     const system_character_t *argument,
     uint8_t *newline_conversion,
     libcerror_error_t **error );

#if defined( __cplusplus )
}
#endif

#endif /* !defined( _UNAINPUT_H ) */

