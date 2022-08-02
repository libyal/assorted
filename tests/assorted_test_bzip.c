/*
 * BZip decompression testing program
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

#include <common.h>
#include <memory.h>
#include <file_stream.h>
#include <types.h>

#if defined( HAVE_STDLIB_H ) || defined( WINAPI )
#include <stdlib.h>
#endif

#include "assorted_test_libcerror.h"
#include "assorted_test_libcnotify.h"
#include "assorted_test_macros.h"
#include "assorted_test_unused.h"

#include "../src/assorted_bit_stream.h"
#include "../src/assorted_bzip.h"
#include "../src/assorted_huffman_tree.h"

/* Define to make assorted_test_bzip generate verbose output
#define ASSORTED_TEST_BZIP_VERBOSE
 */

uint8_t assorted_test_bzip_compressed_data[ 125 ] = {
	0x42, 0x5a, 0x68, 0x31, 0x31, 0x41, 0x59, 0x26, 0x53, 0x59, 0x5a, 0x55, 0xc4, 0x1e, 0x00,
       	0x00, 0x0c, 0x5f, 0x80, 0x20, 0x00, 0x40, 0x84, 0x00, 0x00, 0x80, 0x20, 0x40, 0x00, 0x2f,
       	0x6c, 0xdc, 0x80, 0x20, 0x00, 0x48, 0x4a, 0x9a, 0x4c, 0xd5, 0x53, 0xfc, 0x69, 0xa5, 0x53,
       	0xff, 0x55, 0x3f, 0x69, 0x50, 0x15, 0x48, 0x95, 0x4f, 0xff, 0x55, 0x51, 0xff, 0xaa, 0xa0,
       	0xff, 0xf5, 0x55, 0x31, 0xff, 0xaa, 0xa7, 0xfb, 0x4b, 0x34, 0xc9, 0xb8, 0x38, 0xff, 0x16,
       	0x14, 0x56, 0x5a, 0xe2, 0x8b, 0x9d, 0x50, 0xb9, 0x00, 0x81, 0x1a, 0x91, 0xfa, 0x25, 0x4f,
       	0x08, 0x5f, 0x4b, 0x5f, 0x53, 0x92, 0x4b, 0x11, 0xc5, 0x22, 0x92, 0xd9, 0x50, 0x56, 0x6b,
       	0x6f, 0x9e, 0x17, 0x72, 0x45, 0x38, 0x50, 0x90, 0x5a, 0x55, 0xc4, 0x1e };

uint8_t assorted_test_bzip_uncompressed_data[ 108 ] = {
	0x49, 0x66, 0x20, 0x50, 0x65, 0x74, 0x65, 0x72, 0x20, 0x50, 0x69, 0x70, 0x65, 0x72, 0x20,
	0x70, 0x69, 0x63, 0x6b, 0x65, 0x64, 0x20, 0x61, 0x20, 0x70, 0x65, 0x63, 0x6b, 0x20, 0x6f,
	0x66, 0x20, 0x70, 0x69, 0x63, 0x6b, 0x6c, 0x65, 0x64, 0x20, 0x70, 0x65, 0x70, 0x70, 0x65,
	0x72, 0x73, 0x2c, 0x20, 0x77, 0x68, 0x65, 0x72, 0x65, 0x27, 0x73, 0x20, 0x74, 0x68, 0x65,
	0x20, 0x70, 0x65, 0x63, 0x6b, 0x20, 0x6f, 0x66, 0x20, 0x70, 0x69, 0x63, 0x6b, 0x6c, 0x65,
	0x64, 0x20, 0x70, 0x65, 0x70, 0x70, 0x65, 0x72, 0x73, 0x20, 0x50, 0x65, 0x74, 0x65, 0x72,
	0x20, 0x50, 0x69, 0x70, 0x65, 0x72, 0x20, 0x70, 0x69, 0x63, 0x6b, 0x65, 0x64, 0x3f, 0x3f,
	0x3f, 0x3f, 0x3f };

#if defined( __GNUC__ )

/* Tests the assorted_bzip_initialize_crc32_table function
 * Returns 1 if successful or 0 if not
 */
int assorted_test_bzip_initialize_crc32_table(
     void )
{
	/* Test invocation of function only
	 */
	assorted_bzip_initialize_crc32_table();

	return( 1 );
}

/* Tests the assorted_bzip_calculate_crc32 function
 * Returns 1 if successful or 0 if not
 */
int assorted_test_bzip_calculate_crc32(
     void )
{
	char *data               = "Hello, world!";
	libcerror_error_t *error = NULL;
	uint32_t checksum        = 0;
	int result               = 0;

	/* Test regular cases
	 */
	result = assorted_bzip_calculate_crc32(
	          &checksum,
	          (uint8_t *) data,
	          13,
	          0,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	ASSORTED_TEST_ASSERT_EQUAL_UINT32(
	 "checksum",
	 checksum,
	 (uint32_t) 0x8e9a7706UL );

	ASSORTED_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test error cases
	 */
	result = assorted_bzip_calculate_crc32(
	          NULL,
	          (uint8_t *) data,
	          13,
	          0,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	ASSORTED_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	result = assorted_bzip_calculate_crc32(
	          &checksum,
	          NULL,
	          13,
	          0,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	ASSORTED_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	result = assorted_bzip_calculate_crc32(
	          &checksum,
	          (uint8_t *) data,
	          (size_t) SSIZE_MAX + 1,
	          0,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	ASSORTED_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	return( 1 );

on_error:
	return( 0 );
}

/* Tests the assorted_bzip_reverse_burrows_wheeler_transform function
 * Returns 1 if successful or 0 if not
 */
int assorted_test_bzip_reverse_burrows_wheeler_transform(
     void )
{
	uint8_t expected_output_data[ 35 ] = {
		's', 'h', 'e', ' ', 's', 'e', 'l', 'l', 's', ' ', 's', 'e', 'a', 's', 'h', 'e',
	       	'l', 'l', 's', ' ', 'b', 'y', ' ', 't', 'h', 'e', ' ', 's', 'e', 'a', 's', 'h',
	       	'o', 'r', 'e' };

	uint8_t input_data[ 35 ] = {
		's', 's', 'e', 'e', 'y', 'e', 'e', ' ', 'h', 'h', 's', 's', 'h', 's', 'r', 't',
	       	's', 's', 's', 'e', 'e', 'l', 'l', 'h', 'o', 'l', 'l', ' ', ' ', ' ', 'e', 'a',
	       	'a', ' ', 'b' };

	uint8_t output_data[ 35 ];
	size_t permutations[ 35 ];

	libcerror_error_t *error  = NULL;
	void *memset_result       = NULL;
	size_t output_data_offset = 0;
	int result                = 0;

	/* Initialize test
	 */
	memset_result = memory_set(
	                 permutations,
	                 0,
	                 sizeof( size_t ) * 32 );

	ASSORTED_TEST_ASSERT_IS_NOT_NULL(
	 "memset_result",
	 memset_result );

	/* Test regular cases
	 */
	output_data_offset = 0;

	result = assorted_bzip_reverse_burrows_wheeler_transform(
	          input_data,
	          35,
	          permutations,
	          30,
	          output_data,
	          35,
	          &output_data_offset,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	ASSORTED_TEST_ASSERT_EQUAL_SIZE(
	 "output_data_offset",
	 output_data_offset,
	 (size_t) 35 );

	ASSORTED_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = memory_compare(
	          output_data,
	          expected_output_data,
	          35 );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 0 );

	/* Test error cases
	 */
	output_data_offset = 0;

	result = assorted_bzip_reverse_burrows_wheeler_transform(
	          NULL,
	          35,
	          permutations,
	          30,
	          output_data,
	          35,
	          &output_data_offset,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	ASSORTED_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	return( 1 );

on_error:
	return( 0 );
}

/* Tests the assorted_bzip_read_stream_header function
 * Returns 1 if successful or 0 if not
 */
int assorted_test_bzip_read_stream_header(
     void )
{
	libcerror_error_t *error      = NULL;
	size_t compressed_data_offset = 0;
	uint8_t compression_level     = 0;
	int result                    = 0;

	/* Test regular cases
	 */
	compressed_data_offset = 0;

	result = assorted_bzip_read_stream_header(
	          assorted_test_bzip_compressed_data,
	          125,
	          &compressed_data_offset,
	          &compression_level,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	ASSORTED_TEST_ASSERT_EQUAL_UINT8(
	 "compression_level",
	 compression_level,
	 1 );

	ASSORTED_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test error cases
	 */
	compressed_data_offset = 0;

	result = assorted_bzip_read_stream_header(
	          NULL,
	          125,
	          &compressed_data_offset,
	          &compression_level,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	ASSORTED_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	result = assorted_bzip_read_stream_header(
	          assorted_test_bzip_compressed_data,
	          (size_t) SSIZE_MAX + 1,
	          &compressed_data_offset,
	          &compression_level,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	ASSORTED_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	result = assorted_bzip_read_stream_header(
	          assorted_test_bzip_compressed_data,
	          125,
	          NULL,
	          &compression_level,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	ASSORTED_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	result = assorted_bzip_read_stream_header(
	          assorted_test_bzip_compressed_data,
	          125,
	          &compressed_data_offset,
	          NULL,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	ASSORTED_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	return( 1 );

on_error:
	return( 0 );
}

/* Tests the assorted_bzip_read_signature function
 * Returns 1 if successful or 0 if not
 */
int assorted_test_bzip_read_signature(
     void )
{
	assorted_bit_stream_t *bit_stream = NULL;
	libcerror_error_t *error          = NULL;
	uint64_t signature                = 0;
	int result                        = 0;

	/* Initialize test
	 */
	result = assorted_bit_stream_initialize(
	          &bit_stream,
	          assorted_test_bzip_compressed_data,
	          125,
	          4,
	          ASSORTED_BIT_STREAM_STORAGE_TYPE_BYTE_FRONT_TO_BACK,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	ASSORTED_TEST_ASSERT_IS_NOT_NULL(
	 "bit_stream",
	 bit_stream );

	ASSORTED_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test regular cases
	 */
	result = assorted_bzip_read_signature(
	          bit_stream,
	          &signature,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	ASSORTED_TEST_ASSERT_EQUAL_UINT64(
	 "signature",
	 signature,
	 (uint64_t) 0x314159265359UL );

	ASSORTED_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test error cases
	 */
	result = assorted_bzip_read_signature(
	          NULL,
	          &signature,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	ASSORTED_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	/* Clean up
	 */
	result = assorted_bit_stream_free(
	          &bit_stream,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	ASSORTED_TEST_ASSERT_IS_NULL(
	 "bit_stream",
	 bit_stream );

	ASSORTED_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	return( 1 );

on_error:
	if( bit_stream != NULL )
	{
		assorted_bit_stream_free(
		 &bit_stream,
		 NULL );
	}
	return( 0 );
}

/* Tests the assorted_bzip_read_block_header function
 * Returns 1 if successful or 0 if not
 */
int assorted_test_bzip_read_block_header(
     void )
{
	assorted_bit_stream_t *bit_stream = NULL;
	libcerror_error_t *error          = NULL;
	uint64_t signature                = 0;
	uint32_t origin_pointer           = 0;
	int result                        = 0;

	/* Initialize test
	 */
	result = assorted_bit_stream_initialize(
	          &bit_stream,
	          assorted_test_bzip_compressed_data,
	          125,
	          4,
	          ASSORTED_BIT_STREAM_STORAGE_TYPE_BYTE_FRONT_TO_BACK,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	ASSORTED_TEST_ASSERT_IS_NOT_NULL(
	 "bit_stream",
	 bit_stream );

	ASSORTED_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = assorted_bzip_read_signature(
	          bit_stream,
	          &signature,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	ASSORTED_TEST_ASSERT_EQUAL_UINT64(
	 "signature",
	 signature,
	 (uint64_t) 0x314159265359UL );

	ASSORTED_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test regular cases
	 */
	result = assorted_bzip_read_block_header(
	          bit_stream,
	          signature,
	          &origin_pointer,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	ASSORTED_TEST_ASSERT_EQUAL_UINT32(
	 "origin_pointer",
	 origin_pointer,
	 (uint32_t) 24 );

	ASSORTED_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test error cases
	 */
	result = assorted_bzip_read_block_header(
	          NULL,
	          signature,
	          &origin_pointer,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	ASSORTED_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	/* Clean up
	 */
	result = assorted_bit_stream_free(
	          &bit_stream,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	ASSORTED_TEST_ASSERT_IS_NULL(
	 "bit_stream",
	 bit_stream );

	ASSORTED_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	return( 1 );

on_error:
	if( bit_stream != NULL )
	{
		assorted_bit_stream_free(
		 &bit_stream,
		 NULL );
	}
	return( 0 );
}

/* Tests the assorted_bzip_read_symbol_stack function
 * Returns 1 if successful or 0 if not
 */
int assorted_test_bzip_read_symbol_stack(
     void )
{
	uint8_t symbol_stack[ 256 ];

	uint8_t expected_symbol_stack[ 22 ] = {
		1, 32, 39, 44, 63, 73, 80, 97, 99, 100, 101, 102, 104, 105, 107, 108,
	       	111, 112, 114, 115, 116, 119 };

	assorted_bit_stream_t *bit_stream    = NULL;
	libcerror_error_t *error             = NULL;
	void *memset_result                  = NULL;
	uint64_t signature                   = 0;
	uint32_t origin_pointer              = 0;
	uint16_t number_of_symbols           = 0;
	int result                           = 0;

	/* Initialize test
	 */
	result = assorted_bit_stream_initialize(
	          &bit_stream,
	          assorted_test_bzip_compressed_data,
	          125,
	          4,
	          ASSORTED_BIT_STREAM_STORAGE_TYPE_BYTE_FRONT_TO_BACK,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	ASSORTED_TEST_ASSERT_IS_NOT_NULL(
	 "bit_stream",
	 bit_stream );

	ASSORTED_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = assorted_bzip_read_signature(
	          bit_stream,
	          &signature,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	ASSORTED_TEST_ASSERT_EQUAL_UINT64(
	 "signature",
	 signature,
	 (uint64_t) 0x314159265359UL );

	ASSORTED_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = assorted_bzip_read_block_header(
	          bit_stream,
	          signature,
	          &origin_pointer,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	ASSORTED_TEST_ASSERT_EQUAL_UINT32(
	 "origin_pointer",
	 origin_pointer,
	 (uint32_t) 24 );

	ASSORTED_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	memset_result = memory_set(
	                 symbol_stack,
	                 0,
	                 256 );

	ASSORTED_TEST_ASSERT_IS_NOT_NULL(
	 "memset_result",
	 memset_result );

	/* Test regular cases
	 */
	result = assorted_bzip_read_symbol_stack(
	          bit_stream,
	          symbol_stack,
	          &number_of_symbols,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	ASSORTED_TEST_ASSERT_EQUAL_UINT16(
	 "number_of_symbols",
	 number_of_symbols,
	 (uint16_t) 24 );

	ASSORTED_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = memory_compare(
	          symbol_stack,
	          expected_symbol_stack,
	          22 );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 0 );

	/* Test error cases
	 */
	result = assorted_bzip_read_symbol_stack(
	          NULL,
	          symbol_stack,
	          &number_of_symbols,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	ASSORTED_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	/* Clean up
	 */
	result = assorted_bit_stream_free(
	          &bit_stream,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	ASSORTED_TEST_ASSERT_IS_NULL(
	 "bit_stream",
	 bit_stream );

	ASSORTED_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	return( 1 );

on_error:
	if( bit_stream != NULL )
	{
		assorted_bit_stream_free(
		 &bit_stream,
		 NULL );
	}
	return( 0 );
}

/* Tests the assorted_bzip_read_selectors function
 * Returns 1 if successful or 0 if not
 */
int assorted_test_bzip_read_selectors(
     void )
{
	uint8_t symbol_stack[ 256 ];
	uint8_t selectors[ ( 1 << 15 ) + 1 ];

	uint8_t expected_selectors[ 2 ] = {
		0, 1 };

	assorted_bit_stream_t *bit_stream = NULL;
	libcerror_error_t *error          = NULL;
	void *memset_result               = NULL;
	uint64_t signature                = 0;
	uint32_t origin_pointer           = 0;
	uint32_t value_32bit              = 0;
	uint16_t number_of_selectors      = 0;
	uint16_t number_of_symbols        = 0;
	uint8_t number_of_trees           = 0;
	int result                        = 0;

	/* Initialize test
	 */
	result = assorted_bit_stream_initialize(
	          &bit_stream,
	          assorted_test_bzip_compressed_data,
	          125,
	          4,
	          ASSORTED_BIT_STREAM_STORAGE_TYPE_BYTE_FRONT_TO_BACK,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	ASSORTED_TEST_ASSERT_IS_NOT_NULL(
	 "bit_stream",
	 bit_stream );

	ASSORTED_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = assorted_bzip_read_signature(
	          bit_stream,
	          &signature,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	ASSORTED_TEST_ASSERT_EQUAL_UINT64(
	 "signature",
	 signature,
	 (uint64_t) 0x314159265359UL );

	ASSORTED_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = assorted_bzip_read_block_header(
	          bit_stream,
	          signature,
	          &origin_pointer,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	ASSORTED_TEST_ASSERT_EQUAL_UINT32(
	 "origin_pointer",
	 origin_pointer,
	 (uint32_t) 24 );

	ASSORTED_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	memset_result = memory_set(
	                 symbol_stack,
	                 0,
	                 256 );

	ASSORTED_TEST_ASSERT_IS_NOT_NULL(
	 "memset_result",
	 memset_result );

	result = assorted_bzip_read_symbol_stack(
	          bit_stream,
	          symbol_stack,
	          &number_of_symbols,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	ASSORTED_TEST_ASSERT_EQUAL_UINT16(
	 "number_of_symbols",
	 number_of_symbols,
	 (uint16_t) 24 );

	ASSORTED_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = assorted_bit_stream_get_value(
	          bit_stream,
	          18,
	          &value_32bit,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	ASSORTED_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	number_of_selectors = (uint16_t) ( value_32bit & 0x00007fffUL );
	value_32bit       >>= 15;
	number_of_trees     = (uint8_t) ( value_32bit & 0x00000007UL );

	ASSORTED_TEST_ASSERT_EQUAL_UINT16(
	 "number_of_selectors",
	 number_of_selectors,
	 (uint16_t) 2 );

	ASSORTED_TEST_ASSERT_EQUAL_UINT8(
	 "number_of_trees",
	 number_of_trees,
	 (uint16_t) 2 );

	/* Test regular cases
	 */
	result = assorted_bzip_read_selectors(
	          bit_stream,
	          selectors,
	          number_of_selectors,
	          number_of_trees,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	ASSORTED_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = memory_compare(
	          selectors,
	          expected_selectors,
	          2 );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 0 );

	/* Test error cases
	 */
	result = assorted_bzip_read_selectors(
	          NULL,
	          selectors,
	          number_of_selectors,
	          number_of_trees,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	ASSORTED_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	/* Clean up
	 */
	result = assorted_bit_stream_free(
	          &bit_stream,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	ASSORTED_TEST_ASSERT_IS_NULL(
	 "bit_stream",
	 bit_stream );

	ASSORTED_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	return( 1 );

on_error:
	if( bit_stream != NULL )
	{
		assorted_bit_stream_free(
		 &bit_stream,
		 NULL );
	}
	return( 0 );
}

/* Tests the assorted_bzip_read_huffman_tree function
 * Returns 1 if successful or 0 if not
 */
int assorted_test_bzip_read_huffman_tree(
     void )
{
	uint8_t symbol_stack[ 256 ];
	uint8_t selectors[ ( 1 << 15 ) + 1 ];

	assorted_bit_stream_t *bit_stream     = NULL;
	assorted_huffman_tree_t *huffman_tree = NULL;
	libcerror_error_t *error              = NULL;
	void *memset_result                   = NULL;
	uint64_t signature                    = 0;
	uint32_t origin_pointer               = 0;
	uint32_t value_32bit                  = 0;
	uint16_t number_of_selectors          = 0;
	uint16_t number_of_symbols            = 0;
	uint8_t number_of_trees               = 0;
	int result                            = 0;

	/* Initialize test
	 */
	result = assorted_bit_stream_initialize(
	          &bit_stream,
	          assorted_test_bzip_compressed_data,
	          125,
	          4,
	          ASSORTED_BIT_STREAM_STORAGE_TYPE_BYTE_FRONT_TO_BACK,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	ASSORTED_TEST_ASSERT_IS_NOT_NULL(
	 "bit_stream",
	 bit_stream );

	ASSORTED_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = assorted_bzip_read_signature(
	          bit_stream,
	          &signature,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	ASSORTED_TEST_ASSERT_EQUAL_UINT64(
	 "signature",
	 signature,
	 (uint64_t) 0x314159265359UL );

	ASSORTED_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = assorted_bzip_read_block_header(
	          bit_stream,
	          signature,
	          &origin_pointer,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	ASSORTED_TEST_ASSERT_EQUAL_UINT32(
	 "origin_pointer",
	 origin_pointer,
	 (uint32_t) 24 );

	ASSORTED_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	memset_result = memory_set(
	                 symbol_stack,
	                 0,
	                 256 );

	ASSORTED_TEST_ASSERT_IS_NOT_NULL(
	 "memset_result",
	 memset_result );

	result = assorted_bzip_read_symbol_stack(
	          bit_stream,
	          symbol_stack,
	          &number_of_symbols,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	ASSORTED_TEST_ASSERT_EQUAL_UINT16(
	 "number_of_symbols",
	 number_of_symbols,
	 (uint16_t) 24 );

	ASSORTED_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = assorted_bit_stream_get_value(
	          bit_stream,
	          18,
	          &value_32bit,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	ASSORTED_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	number_of_selectors = (uint16_t) ( value_32bit & 0x00007fffUL );
	value_32bit       >>= 15;
	number_of_trees     = (uint8_t) ( value_32bit & 0x00000007UL );

	ASSORTED_TEST_ASSERT_EQUAL_UINT16(
	 "number_of_selectors",
	 number_of_selectors,
	 (uint16_t) 2 );

	ASSORTED_TEST_ASSERT_EQUAL_UINT8(
	 "number_of_trees",
	 number_of_trees,
	 (uint16_t) 2 );

	result = assorted_bzip_read_selectors(
	          bit_stream,
	          selectors,
	          number_of_selectors,
	          number_of_trees,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	ASSORTED_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = assorted_huffman_tree_initialize(
	          &huffman_tree,
	          number_of_symbols,
	          20,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	ASSORTED_TEST_ASSERT_IS_NOT_NULL(
	 "huffman_tree",
	 huffman_tree );

	ASSORTED_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test regular cases
	 */
	result = assorted_bzip_read_huffman_tree(
	          bit_stream,
	          huffman_tree,
	          number_of_symbols,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	ASSORTED_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test error cases
	 */
	result = assorted_bzip_read_huffman_tree(
	          NULL,
	          huffman_tree,
	          number_of_symbols,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	ASSORTED_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	/* Clean up
	 */
	result = assorted_huffman_tree_free(
	          &huffman_tree,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	ASSORTED_TEST_ASSERT_IS_NULL(
	 "huffman_tree",
	 huffman_tree );

	ASSORTED_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = assorted_bit_stream_free(
	          &bit_stream,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	ASSORTED_TEST_ASSERT_IS_NULL(
	 "bit_stream",
	 bit_stream );

	ASSORTED_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	return( 1 );

on_error:
	if( huffman_tree != NULL )
	{
		assorted_huffman_tree_free(
		 &huffman_tree,
		 NULL );
	}
	if( bit_stream != NULL )
	{
		assorted_bit_stream_free(
		 &bit_stream,
		 NULL );
	}
	return( 0 );
}

/* Tests the assorted_bzip_read_huffman_trees function
 * Returns 1 if successful or 0 if not
 */
int assorted_test_bzip_read_huffman_trees(
     void )
{
	uint8_t symbol_stack[ 256 ];
	uint8_t selectors[ ( 1 << 15 ) + 1 ];

	assorted_huffman_tree_t *huffman_trees[ 7 ] = { NULL, NULL, NULL, NULL, NULL, NULL, NULL };
	assorted_bit_stream_t *bit_stream           = NULL;
	libcerror_error_t *error                    = NULL;
	void *memset_result                         = NULL;
	uint64_t signature                          = 0;
	uint32_t origin_pointer                     = 0;
	uint32_t value_32bit                        = 0;
	uint16_t number_of_selectors                = 0;
	uint16_t number_of_symbols                  = 0;
	uint8_t number_of_trees                     = 0;
	uint8_t tree_index                          = 0;
	int result                                  = 0;

	/* Initialize test
	 */
	result = assorted_bit_stream_initialize(
	          &bit_stream,
	          assorted_test_bzip_compressed_data,
	          125,
	          4,
	          ASSORTED_BIT_STREAM_STORAGE_TYPE_BYTE_FRONT_TO_BACK,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	ASSORTED_TEST_ASSERT_IS_NOT_NULL(
	 "bit_stream",
	 bit_stream );

	ASSORTED_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = assorted_bzip_read_signature(
	          bit_stream,
	          &signature,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	ASSORTED_TEST_ASSERT_EQUAL_UINT64(
	 "signature",
	 signature,
	 (uint64_t) 0x314159265359UL );

	ASSORTED_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = assorted_bzip_read_block_header(
	          bit_stream,
	          signature,
	          &origin_pointer,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	ASSORTED_TEST_ASSERT_EQUAL_UINT32(
	 "origin_pointer",
	 origin_pointer,
	 (uint32_t) 24 );

	ASSORTED_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	memset_result = memory_set(
	                 symbol_stack,
	                 0,
	                 256 );

	ASSORTED_TEST_ASSERT_IS_NOT_NULL(
	 "memset_result",
	 memset_result );

	result = assorted_bzip_read_symbol_stack(
	          bit_stream,
	          symbol_stack,
	          &number_of_symbols,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	ASSORTED_TEST_ASSERT_EQUAL_UINT16(
	 "number_of_symbols",
	 number_of_symbols,
	 (uint16_t) 24 );

	ASSORTED_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = assorted_bit_stream_get_value(
	          bit_stream,
	          18,
	          &value_32bit,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	ASSORTED_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	number_of_selectors = (uint16_t) ( value_32bit & 0x00007fffUL );
	value_32bit       >>= 15;
	number_of_trees     = (uint8_t) ( value_32bit & 0x00000007UL );

	ASSORTED_TEST_ASSERT_EQUAL_UINT16(
	 "number_of_selectors",
	 number_of_selectors,
	 (uint16_t) 2 );

	ASSORTED_TEST_ASSERT_EQUAL_UINT8(
	 "number_of_trees",
	 number_of_trees,
	 (uint16_t) 2 );

	result = assorted_bzip_read_selectors(
	          bit_stream,
	          selectors,
	          number_of_selectors,
	          number_of_trees,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	ASSORTED_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test regular cases
	 */
	result = assorted_bzip_read_huffman_trees(
	          bit_stream,
	          huffman_trees,
	          number_of_trees,
	          number_of_symbols,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	ASSORTED_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test error cases
	 */
	result = assorted_bzip_read_huffman_trees(
	          NULL,
	          huffman_trees,
	          number_of_trees,
	          number_of_symbols,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	ASSORTED_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	/* Clean up
	 */
	for( tree_index = 0;
	     tree_index < number_of_trees;
	     tree_index++ )
	{
		result = assorted_huffman_tree_free(
		          &( huffman_trees[ tree_index ] ),
		          &error );

		ASSORTED_TEST_ASSERT_EQUAL_INT(
		 "result",
		 result,
		 1 );

		ASSORTED_TEST_ASSERT_IS_NULL(
		 "huffman_tree",
		 huffman_trees[ tree_index ] );

		ASSORTED_TEST_ASSERT_IS_NULL(
		 "error",
		 error );
	}
	result = assorted_bit_stream_free(
	          &bit_stream,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	ASSORTED_TEST_ASSERT_IS_NULL(
	 "bit_stream",
	 bit_stream );

	ASSORTED_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	return( 1 );

on_error:
	for( tree_index = 0;
	     tree_index < number_of_trees;
	     tree_index++ )
	{
		assorted_huffman_tree_free(
		 &( huffman_trees[ tree_index ] ),
		 NULL );
	}
	if( bit_stream != NULL )
	{
		assorted_bit_stream_free(
		 &bit_stream,
		 NULL );
	}
	return( 0 );
}

/* Tests the assorted_bzip_read_block_data function
 * Returns 1 if successful or 0 if not
 */
int assorted_test_bzip_read_block_data(
     void )
{
	uint8_t block_data[ 128 ];
	uint8_t symbol_stack[ 256 ];
	uint8_t selectors[ ( 1 << 15 ) + 1 ];

	uint8_t expected_block_data[ 108 ] = {
		0x3f, 0x66, 0x73, 0x72, 0x72, 0x64, 0x6b, 0x6b, 0x65, 0x61, 0x64, 0x64, 0x72, 0x72, 0x66, 0x66,
		0x73, 0x2c, 0x65, 0x73, 0x3f, 0x3f, 0x3f, 0x64, 0x01, 0x20, 0x20, 0x20, 0x20, 0x20, 0x65, 0x65,
		0x69, 0x69, 0x69, 0x69, 0x65, 0x65, 0x65, 0x65, 0x68, 0x72, 0x70, 0x70, 0x6b, 0x6c, 0x6c, 0x6b,
		0x70, 0x70, 0x74, 0x74, 0x70, 0x70, 0x68, 0x70, 0x70, 0x50, 0x50, 0x49, 0x6f, 0x6f, 0x74, 0x77,
		0x70, 0x70, 0x70, 0x70, 0x50, 0x50, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x6b, 0x6b, 0x20, 0x20,
		0x20, 0x20, 0x20, 0x20, 0x69, 0x69, 0x70, 0x70, 0x20, 0x20, 0x20, 0x20, 0x65, 0x65, 0x65, 0x65,
		0x65, 0x65, 0x65, 0x65, 0x65, 0x72, 0x27, 0x72, 0x65, 0x65, 0x20, 0x20 };

	assorted_huffman_tree_t *huffman_trees[ 7 ] = { NULL, NULL, NULL, NULL, NULL, NULL, NULL };
	assorted_bit_stream_t *bit_stream           = NULL;
	libcerror_error_t *error                    = NULL;
	void *memset_result                         = NULL;
	size_t block_data_size                      = 0;
	uint64_t signature                          = 0;
	uint32_t origin_pointer                     = 0;
	uint32_t value_32bit                        = 0;
	uint16_t number_of_selectors                = 0;
	uint16_t number_of_symbols                  = 0;
	uint8_t number_of_trees                     = 0;
	uint8_t tree_index                          = 0;
	int result                                  = 0;

	/* Initialize test
	 */
	result = assorted_bit_stream_initialize(
	          &bit_stream,
	          assorted_test_bzip_compressed_data,
	          125,
	          4,
	          ASSORTED_BIT_STREAM_STORAGE_TYPE_BYTE_FRONT_TO_BACK,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	ASSORTED_TEST_ASSERT_IS_NOT_NULL(
	 "bit_stream",
	 bit_stream );

	ASSORTED_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = assorted_bzip_read_signature(
	          bit_stream,
	          &signature,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	ASSORTED_TEST_ASSERT_EQUAL_UINT64(
	 "signature",
	 signature,
	 (uint64_t) 0x314159265359UL );

	ASSORTED_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = assorted_bzip_read_block_header(
	          bit_stream,
	          signature,
	          &origin_pointer,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	ASSORTED_TEST_ASSERT_EQUAL_UINT32(
	 "origin_pointer",
	 origin_pointer,
	 (uint32_t) 24 );

	ASSORTED_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	memset_result = memory_set(
	                 symbol_stack,
	                 0,
	                 256 );

	ASSORTED_TEST_ASSERT_IS_NOT_NULL(
	 "memset_result",
	 memset_result );

	result = assorted_bzip_read_symbol_stack(
	          bit_stream,
	          symbol_stack,
	          &number_of_symbols,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	ASSORTED_TEST_ASSERT_EQUAL_UINT16(
	 "number_of_symbols",
	 number_of_symbols,
	 (uint16_t) 24 );

	ASSORTED_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = assorted_bit_stream_get_value(
	          bit_stream,
	          18,
	          &value_32bit,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	ASSORTED_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	number_of_selectors = (uint16_t) ( value_32bit & 0x00007fffUL );
	value_32bit       >>= 15;
	number_of_trees     = (uint8_t) ( value_32bit & 0x00000007UL );

	ASSORTED_TEST_ASSERT_EQUAL_UINT16(
	 "number_of_selectors",
	 number_of_selectors,
	 (uint16_t) 2 );

	ASSORTED_TEST_ASSERT_EQUAL_UINT8(
	 "number_of_trees",
	 number_of_trees,
	 (uint16_t) 2 );

	result = assorted_bzip_read_selectors(
	          bit_stream,
	          selectors,
	          number_of_selectors,
	          number_of_trees,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	ASSORTED_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = assorted_bzip_read_huffman_trees(
	          bit_stream,
	          huffman_trees,
	          number_of_trees,
	          number_of_symbols,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	ASSORTED_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test regular cases
	 */
	block_data_size = 128;

	result = assorted_bzip_read_block_data(
	          bit_stream,
	          huffman_trees,
	          number_of_trees,
	          selectors,
	          number_of_selectors,
	          symbol_stack,
	          number_of_symbols,
	          block_data,
	          &block_data_size,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	ASSORTED_TEST_ASSERT_EQUAL_SIZE(
	 "block_data_size",
	 block_data_size,
	 (size_t) 108 );

	ASSORTED_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = memory_compare(
	          block_data,
	          expected_block_data,
	          108 );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 0 );

	/* Test error cases
	 */
	result = assorted_bzip_read_block_data(
	          NULL,
	          huffman_trees,
	          number_of_trees,
	          selectors,
	          number_of_selectors,
	          symbol_stack,
	          number_of_symbols,
	          block_data,
	          &block_data_size,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	ASSORTED_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	/* Clean up
	 */
	for( tree_index = 0;
	     tree_index < number_of_trees;
	     tree_index++ )
	{
		result = assorted_huffman_tree_free(
		          &( huffman_trees[ tree_index ] ),
		          &error );

		ASSORTED_TEST_ASSERT_EQUAL_INT(
		 "result",
		 result,
		 1 );

		ASSORTED_TEST_ASSERT_IS_NULL(
		 "huffman_tree",
		 huffman_trees[ tree_index ] );

		ASSORTED_TEST_ASSERT_IS_NULL(
		 "error",
		 error );
	}
	result = assorted_bit_stream_free(
	          &bit_stream,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	ASSORTED_TEST_ASSERT_IS_NULL(
	 "bit_stream",
	 bit_stream );

	ASSORTED_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	return( 1 );

on_error:
	for( tree_index = 0;
	     tree_index < number_of_trees;
	     tree_index++ )
	{
		assorted_huffman_tree_free(
		 &( huffman_trees[ tree_index ] ),
		 NULL );
	}
	if( bit_stream != NULL )
	{
		assorted_bit_stream_free(
		 &bit_stream,
		 NULL );
	}
	return( 0 );
}

/* Tests the assorted_bzip_read_stream_footer function
 * Returns 1 if successful or 0 if not
 */
int assorted_test_bzip_read_stream_footer(
     void )
{
	assorted_bit_stream_t *bit_stream = NULL;
	libcerror_error_t *error          = NULL;
	uint64_t signature                = 0;
	uint32_t checksum                 = 0;
	int result                        = 0;

	/* Initialize test
	 */
	result = assorted_bit_stream_initialize(
	          &bit_stream,
	          assorted_test_bzip_compressed_data,
	          125,
	          107,
	          ASSORTED_BIT_STREAM_STORAGE_TYPE_BYTE_FRONT_TO_BACK,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	ASSORTED_TEST_ASSERT_IS_NOT_NULL(
	 "bit_stream",
	 bit_stream );

	ASSORTED_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = assorted_bzip_read_signature(
	          bit_stream,
	          &signature,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	ASSORTED_TEST_ASSERT_EQUAL_UINT64(
	 "signature",
	 signature,
	 (uint64_t) 0x177245385090UL );

	ASSORTED_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test regular cases
	 */
	result = assorted_bzip_read_stream_footer(
	          bit_stream,
	          signature,
	          &checksum,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	ASSORTED_TEST_ASSERT_EQUAL_UINT32(
	 "checksum",
	 checksum,
	 (uint32_t) 0x5a55c41eUL );

	ASSORTED_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test error cases
	 */
	result = assorted_bzip_read_stream_footer(
	          NULL,
	          signature,
	          &checksum,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	ASSORTED_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	/* Clean up
	 */
	result = assorted_bit_stream_free(
	          &bit_stream,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	ASSORTED_TEST_ASSERT_IS_NULL(
	 "bit_stream",
	 bit_stream );

	ASSORTED_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	return( 1 );

on_error:
	if( bit_stream != NULL )
	{
		assorted_bit_stream_free(
		 &bit_stream,
		 NULL );
	}
	return( 0 );
}

/* Tests the assorted_bzip_decompress function
 * Returns 1 if successful or 0 if not
 */
int assorted_test_bzip_decompress(
     void )
{
	uint8_t uncompressed_data[ 256 ];

	libcerror_error_t *error      = NULL;
	size_t uncompressed_data_size = 125;
	int result                    = 0;

	/* Test regular cases
	 */
	result = assorted_bzip_decompress(
	          assorted_test_bzip_compressed_data,
	          125,
	          uncompressed_data,
	          &uncompressed_data_size,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	ASSORTED_TEST_ASSERT_EQUAL_SIZE(
	 "uncompressed_data_size",
	 uncompressed_data_size,
	 (size_t) 108 );

	ASSORTED_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = memory_compare(
	          uncompressed_data,
	          assorted_test_bzip_uncompressed_data,
	          108 );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 0 );

/* TODO: test uncompressed data too small */

	/* Test error cases
	 */
	result = assorted_bzip_decompress(
	          NULL,
	          125,
	          uncompressed_data,
	          &uncompressed_data_size,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	ASSORTED_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	result = assorted_bzip_decompress(
	          assorted_test_bzip_compressed_data,
	          (size_t) SSIZE_MAX + 1,
	          uncompressed_data,
	          &uncompressed_data_size,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	ASSORTED_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	result = assorted_bzip_decompress(
	          assorted_test_bzip_compressed_data,
	          125,
	          NULL,
	          &uncompressed_data_size,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	ASSORTED_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	result = assorted_bzip_decompress(
	          assorted_test_bzip_compressed_data,
	          125,
	          uncompressed_data,
	          NULL,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	ASSORTED_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	return( 1 );

on_error:
	if( error != NULL )
	{
		libcerror_error_free(
		 &error );
	}
	return( 0 );
}

#endif /* defined( __GNUC__ ) */

/* The main program
 */
#if defined( HAVE_WIDE_SYSTEM_CHARACTER )
int wmain(
     int argc ASSORTED_TEST_ATTRIBUTE_UNUSED,
     wchar_t * const argv[] ASSORTED_TEST_ATTRIBUTE_UNUSED )
#else
int main(
     int argc ASSORTED_TEST_ATTRIBUTE_UNUSED,
     char * const argv[] ASSORTED_TEST_ATTRIBUTE_UNUSED )
#endif
{
	ASSORTED_TEST_UNREFERENCED_PARAMETER( argc )
	ASSORTED_TEST_UNREFERENCED_PARAMETER( argv )

#if defined( HAVE_DEBUG_OUTPUT ) && defined( ASSORTED_TEST_BZIP_VERBOSE )
	libcnotify_verbose_set(
	 1 );
	libcnotify_stream_set(
	 stderr,
	 NULL );
#endif

#if defined( __GNUC__ )

	ASSORTED_TEST_RUN(
	 "assorted_bzip_initialize_crc32_table",
	 assorted_test_bzip_initialize_crc32_table );

	ASSORTED_TEST_RUN(
	 "assorted_bzip_calculate_crc32",
	 assorted_test_bzip_calculate_crc32 );

	ASSORTED_TEST_RUN(
	 "assorted_bzip_reverse_burrows_wheeler_transform",
	 assorted_test_bzip_reverse_burrows_wheeler_transform );

	ASSORTED_TEST_RUN(
	 "assorted_bzip_read_stream_header",
	 assorted_test_bzip_read_stream_header );

	ASSORTED_TEST_RUN(
	 "assorted_bzip_read_signature",
	 assorted_test_bzip_read_signature );

	ASSORTED_TEST_RUN(
	 "assorted_bzip_read_block_header",
	 assorted_test_bzip_read_block_header );

	ASSORTED_TEST_RUN(
	 "assorted_bzip_read_symbol_stack",
	 assorted_test_bzip_read_symbol_stack );

	ASSORTED_TEST_RUN(
	 "assorted_bzip_read_selectors",
	 assorted_test_bzip_read_selectors );

	ASSORTED_TEST_RUN(
	 "assorted_bzip_read_huffman_tree",
	 assorted_test_bzip_read_huffman_tree );

	ASSORTED_TEST_RUN(
	 "assorted_bzip_read_huffman_trees",
	 assorted_test_bzip_read_huffman_trees );

	ASSORTED_TEST_RUN(
	 "assorted_bzip_read_block_data",
	 assorted_test_bzip_read_block_data );

	ASSORTED_TEST_RUN(
	 "assorted_bzip_read_stream_footer",
	 assorted_test_bzip_read_stream_footer );

	ASSORTED_TEST_RUN(
	 "assorted_bzip_decompress",
	 assorted_test_bzip_decompress );

#endif /* defined( __GNUC__ ) */

	return( EXIT_SUCCESS );

#if defined( __GNUC__ )

on_error:
	return( EXIT_FAILURE );

#endif /* defined( __GNUC__ ) */
}

