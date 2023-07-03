/*
 * Decompression handle
 *
 * Copyright (C) 2008-2023, Joachim Metz <joachim.metz@gmail.com>
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

#if !defined( _DECOMPRESSION_HANDLE_H )
#define _DECOMPRESSION_HANDLE_H

#include <common.h>
#include <file_stream.h>
#include <types.h>

#include "assorted_libcerror.h"
#include "assorted_libcfile.h"

#if defined( __cplusplus )
extern "C" {
#endif

typedef struct decompression_handle decompression_handle_t;

struct decompression_handle
{
	/* The input file
	 */
	libcfile_file_t *input_file;

	/* The input size
	 */
	size64_t input_size;

	/* The input offset
	 */
	off64_t input_offset;

	/* The notification output stream
	 */
	FILE *notify_stream;

	/* Value to indicate if abort was signalled
	 */
	int abort;
};

int assorted_system_string_copy_from_64_bit_in_decimal(
     const system_character_t *string,
     size_t string_size,
     uint64_t *value_64bit,
     libcerror_error_t **error );

int decompression_handle_initialize(
     decompression_handle_t **decompression_handle,
     libcerror_error_t **error );

int decompression_handle_free(
     decompression_handle_t **decompression_handle,
     libcerror_error_t **error );

int decompression_handle_signal_abort(
     decompression_handle_t *decompression_handle,
     libcerror_error_t **error );

int decompression_handle_set_input_offset(
     decompression_handle_t *decompression_handle,
     const system_character_t *string,
     libcerror_error_t **error );

int decompression_handle_set_input_size(
     decompression_handle_t *decompression_handle,
     const system_character_t *string,
     libcerror_error_t **error );

int decompression_handle_open_input(
     decompression_handle_t *decompression_handle,
     const system_character_t *filename,
     libcerror_error_t **error );

int decompression_handle_close_input(
     decompression_handle_t *decompression_handle,
     libcerror_error_t **error );

int decompression_handle_read_data(
     decompression_handle_t *decompression_handle,
     uint8_t *compressed_data,
     size_t compressed_data_size,
     libcerror_error_t **error );

int decompression_handle_write_data(
     decompression_handle_t *decompression_handle,
     const system_character_t *output_filename,
     const uint8_t *uncompressed_data,
     size_t uncompressed_data_size,
     libcerror_error_t **error );

#if defined( __cplusplus )
}
#endif

#endif /* !defined( _DECOMPRESSION_HANDLE_H ) */

