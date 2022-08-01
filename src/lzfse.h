/*
 * LZFSE (un)compression functions
 *
 * Copyright (C) 2008-2022, Joachim Metz <joachim.metz@gmail.com>
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

#if !defined( _LZFSE_H )
#define _LZFSE_H

#include <common.h>
#include <types.h>

#include "assorted_libcerror.h"

#if defined( __cplusplus )
extern "C" {
#endif

#define LZFSE_NUMBER_OF_LITERAL_STATES		1024
#define LZFSE_NUMBER_OF_LITERAL_SYMBOLS		256

#define LZFSE_NUMBER_OF_L_VALUE_STATES		64
#define LZFSE_NUMBER_OF_L_VALUE_SYMBOLS		20

#define LZFSE_NUMBER_OF_M_VALUE_STATES		64
#define LZFSE_NUMBER_OF_M_VALUE_SYMBOLS		20

#define LZFSE_NUMBER_OF_D_VALUE_STATES		256
#define LZFSE_NUMBER_OF_D_VALUE_SYMBOLS		64

typedef struct lzfse_bit_stream lzfse_bit_stream_t;

struct lzfse_bit_stream
{
	/* The byte stream
	 */
	const uint8_t *byte_stream;

	/* The byte stream size
	 */
	size_t byte_stream_size;

	/* The byte stream offset
	 */
	size_t byte_stream_offset;

	/* The bit buffer
	 */
	uint32_t bit_buffer;

	/* The number of bits remaining in the bit buffer
	 */
	uint8_t bit_buffer_size;
};

typedef struct lzfse_decoder_entry lzfse_decoder_entry_t;

struct lzfse_decoder_entry
{
	/* The number of bits
	 */
	int8_t number_of_bits;

	/* The symbol
	 */
	uint8_t symbol;

	/* The delta to compute the next state
	 */
	int16_t delta;
};

typedef struct lzfse_value_decoder_entry lzfse_value_decoder_entry_t;

struct lzfse_value_decoder_entry
{
	/* The (total) number of bits
	 */
	uint8_t number_of_bits;

	/* The value bits
	 */
	uint8_t value_bits;

	/* The delta
	 */
	int16_t delta;

	/* The value base
	 */
	int32_t value_base;

	/* The value bitmask
	 */
	uint32_t value_bitmask;
};

typedef struct lzfse_state lzfse_state_t;

struct lzfse_state
{
	/* The number of literals
	 */
	uint32_t number_of_literals;

	/* The number of L, M, D values
	 */
	uint32_t number_of_lmd_values;

	/* The literals data size
	 */
	uint32_t literals_data_size;

	/* The L, M, D values data size
	 */
	uint32_t lmd_values_data_size;

	/* The literal states
	 */
	uint16_t literal_states[ 4 ];

	/* The L value states
	 */
	uint16_t l_value_state;

	/* The M value states
	 */
	uint16_t m_value_state;

	/* The D value states
	 */
	uint16_t d_value_state;

	/* TODO
	 */
	int32_t literal_bits;

	/* TODO
	 */
	int32_t lmd_values_bits;

	/* The literal decoder table
	 */
	lzfse_decoder_entry_t literal_decoder_table[ LZFSE_NUMBER_OF_LITERAL_STATES ];

	/* The L value decoder table
	 */
	lzfse_value_decoder_entry_t l_value_decoder_table[ LZFSE_NUMBER_OF_L_VALUE_STATES ];

	/* The M value decoder table
	 */
	lzfse_value_decoder_entry_t m_value_decoder_table[ LZFSE_NUMBER_OF_M_VALUE_STATES ];

	/* The D value decoder table
	 */
	lzfse_value_decoder_entry_t d_value_decoder_table[ LZFSE_NUMBER_OF_D_VALUE_STATES ];
};

int lzfse_bit_stream_initialize(
     lzfse_bit_stream_t **bit_stream,
     const uint8_t *byte_stream,
     size_t byte_stream_size,
     libcerror_error_t **error );

int lzfse_bit_stream_free(
     lzfse_bit_stream_t **bit_stream,
     libcerror_error_t **error );

int lzfse_bit_stream_read(
     lzfse_bit_stream_t *bit_stream,
     uint8_t number_of_bits,
     libcerror_error_t **error );

int lzfse_bit_stream_get_value(
     lzfse_bit_stream_t *bit_stream,
     uint8_t number_of_bits,
     uint32_t *value_32bit,
     libcerror_error_t **error );

int lzfse_state_initialize(
     lzfse_state_t **state,
     libcerror_error_t **error );

int lzfse_state_state(
     lzfse_state_t **state,
     libcerror_error_t **error );

int lzfse_build_decoder_table(
     int number_of_states,
     uint16_t number_of_symbols,
     const uint16_t *frequency_table,
     lzfse_decoder_entry_t *decoder_table,
     libcerror_error_t **error );

int lzfse_build_value_decoder_table(
     int number_of_states,
     uint16_t number_of_symbols,
     const uint16_t *frequency_table,
     const uint8_t *value_bits_table,
     const int32_t *value_base_table,
     lzfse_value_decoder_entry_t *value_decoder_table,
     libcerror_error_t **error );

int lzfse_read_v1_block_header(
     lzfse_state_t *state,
     const uint8_t *compressed_data,
     size_t compressed_data_size,
     size_t *compressed_data_offset,
     uint16_t *frequency_table,
     libcerror_error_t **error );

int lzfse_read_v2_block_header(
     lzfse_state_t *state,
     const uint8_t *compressed_data,
     size_t compressed_data_size,
     size_t *compressed_data_offset,
     uint16_t *frequency_table,
     libcerror_error_t **error );

int lzfse_read_compressed_frequency_table(
     const uint8_t *compressed_data,
     size_t compressed_data_size,
     uint16_t *frequency_table,
     libcerror_error_t **error );

int lzfse_read_block(
     lzfse_state_t *state,
     const uint8_t *compressed_data,
     size_t compressed_data_size,
     size_t *compressed_data_offset,
     uint8_t *uncompressed_data,
     size_t uncompressed_data_size,
     size_t *uncompressed_data_offset,
     libcerror_error_t **error );

int lzfse_read_literal_values(
     lzfse_state_t *state,
     lzfse_bit_stream_t *bit_stream,
     uint8_t *literal_values,
     libcerror_error_t **error );

int lzfse_read_lmd_values(
     lzfse_state_t *state,
     lzfse_bit_stream_t *bit_stream,
     uint8_t *literal_values,
     uint8_t *uncompressed_data,
     size_t uncompressed_data_size,
     size_t *uncompressed_data_offset,
     libcerror_error_t **error );

int lzfse_decompress(
     const uint8_t *compressed_data,
     size_t compressed_data_size,
     uint8_t *uncompressed_data,
     size_t *uncompressed_data_size,
     libcerror_error_t **error );

#if defined( __cplusplus )
}
#endif

#endif /* !defined( _LZFSE_H ) */

