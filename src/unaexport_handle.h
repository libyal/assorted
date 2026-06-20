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

#if !defined( _UNAEXPORT_HANDLE_H )
#define _UNAEXPORT_HANDLE_H

#include <common.h>
#include <types.h>

#include "assorted_libcerror.h"
#include "assorted_libcfile.h"
#include "assorted_libuna.h"
#include "process_status.h"

#if defined( __cplusplus )
extern "C" {
#endif

enum UNAEXPORT_HANDLE_MODE
{
	UNAEXPORT_HANDLE_MODE_BASE_ENCODING	= (uint8_t) 'b',
	UNAEXPORT_HANDLE_MODE_TEXT_ENCODING	= (uint8_t) 't'
};

typedef struct export_handle export_handle_t;

struct export_handle
{
	/* The mode
	 */
	uint8_t mode;

	/* The source filename
	 */
	system_character_t *source_filename;

	/* The source filename size
	 */
	size_t source_filename_size;

	/* The destination filename
	 */
	system_character_t *destination_filename;

	/* The destination filename size
	 */
	size_t destination_filename_size;

	/* The source file
	 */
	libcfile_file_t *source_file;

	/* The destination file
	 */
	libcfile_file_t *destination_file;

	/* Values for base encoding export
	 */

	/* The base enconding
	 */
	uint8_t base_encoding;

	/* The base encoding mode
	 */
	uint8_t base_encoding_mode;

	/* Values for text encoding export
	 */

	/* The input format
	 */
	uint8_t text_input_format;

	/* The output format
	 */
	uint8_t text_output_format;

	/* The newline conversion
	 */
	uint8_t text_newline_conversion;

	/* Value to indicate if the byte-order mark should be exported
	 */
	uint8_t text_export_byte_order_mark;

	/* The text byte stream codepage
	 */
	int text_byte_stream_codepage;

	/* The notification output stream
	 */
	FILE *notify_stream;

	/* Value to indicate if abort was signalled
	 */
	int abort;
};

int export_handle_initialize(
     export_handle_t **export_handle,
     uint8_t mode,
     libcerror_error_t **error );

int export_handle_free(
     export_handle_t **export_handle,
     libcerror_error_t **error );

int export_handle_signal_abort(
     export_handle_t *export_handle,
     libcerror_error_t **error );

int export_handle_open_input(
     export_handle_t *export_handle,
     libcerror_error_t **error );

int export_handle_open_output(
     export_handle_t *export_handle,
     libcerror_error_t **error );

int export_handle_close(
     export_handle_t *export_handle,
     libcerror_error_t **error );

int export_handle_set_string(
     export_handle_t *export_handle,
     const system_character_t *string,
     system_character_t **internal_string,
     size_t *internal_string_size,
     libcerror_error_t **error );

int export_handle_set_encoding(
     export_handle_t *export_handle,
     const system_character_t *string,
     libcerror_error_t **error );

int export_handle_set_encoding_mode(
     export_handle_t *export_handle,
     const system_character_t *string,
     libcerror_error_t **error );

int export_handle_set_input_format(
     export_handle_t *export_handle,
     const system_character_t *string,
     libcerror_error_t **error );

int export_handle_set_output_format(
     export_handle_t *export_handle,
     const system_character_t *string,
     libcerror_error_t **error );

int export_handle_set_newline_conversion(
     export_handle_t *export_handle,
     const system_character_t *string,
     libcerror_error_t **error );

int export_handle_set_byte_stream_codepage(
     export_handle_t *export_handle,
     const system_character_t *string,
     libcerror_error_t **error );

int export_handle_export_input(
     export_handle_t *export_handle,
     uint8_t print_status_information,
     libcerror_error_t **error );

int export_handle_export_base_encoded_input(
     export_handle_t *export_handle,
     process_status_t *process_status,
     libcerror_error_t **error );

int export_handle_export_text_encoded_input(
     export_handle_t *export_handle,
     process_status_t *process_status,
     libcerror_error_t **error );

int export_handle_print_parameters(
     export_handle_t *export_handle,
     libcerror_error_t **error );

void export_handle_codepage_fprint(
      FILE *stream,
      int codepage );

void export_handle_codepages_fprint(
      FILE *stream );

void export_handle_format_fprint(
      FILE *stream,
      int format );

#if defined( __cplusplus )
}
#endif

#endif /* !defined( _UNAEXPORT_HANDLE_H ) */

