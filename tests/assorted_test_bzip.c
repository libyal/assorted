/*
 * BZip decompression testing program
 *
 * Copyright (C) 2009-2022, Joachim Metz <joachim.metz@gmail.com>
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

#include "../src/bit_stream.h"
#include "../src/bzip.h"

/* Define to make assorted_test_bzip generate verbose output
#define ASSORTED_TEST_BZIP_VERBOSE
 */

uint8_t assorted_test_bzip_compressed_byte_stream[ 125 ] = {
	0x42, 0x5a, 0x68, 0x31, 0x31, 0x41, 0x59, 0x26, 0x53, 0x59, 0x5a, 0x55, 0xc4, 0x1e, 0x00,
       	0x00, 0x0c, 0x5f, 0x80, 0x20, 0x00, 0x40, 0x84, 0x00, 0x00, 0x80, 0x20, 0x40, 0x00, 0x2f,
       	0x6c, 0xdc, 0x80, 0x20, 0x00, 0x48, 0x4a, 0x9a, 0x4c, 0xd5, 0x53, 0xfc, 0x69, 0xa5, 0x53,
       	0xff, 0x55, 0x3f, 0x69, 0x50, 0x15, 0x48, 0x95, 0x4f, 0xff, 0x55, 0x51, 0xff, 0xaa, 0xa0,
       	0xff, 0xf5, 0x55, 0x31, 0xff, 0xaa, 0xa7, 0xfb, 0x4b, 0x34, 0xc9, 0xb8, 0x38, 0xff, 0x16,
       	0x14, 0x56, 0x5a, 0xe2, 0x8b, 0x9d, 0x50, 0xb9, 0x00, 0x81, 0x1a, 0x91, 0xfa, 0x25, 0x4f,
       	0x08, 0x5f, 0x4b, 0x5f, 0x53, 0x92, 0x4b, 0x11, 0xc5, 0x22, 0x92, 0xd9, 0x50, 0x56, 0x6b,
       	0x6f, 0x9e, 0x17, 0x72, 0x45, 0x38, 0x50, 0x90, 0x5a, 0x55, 0xc4, 0x1e };

#if defined( __GNUC__ )

/* Tests the bzip_reverse_burrows_wheeler_transform function
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

	libcerror_error_t *error = NULL;
	int result               = 0;

	/* Test regular cases
	 */
	result = bzip_reverse_burrows_wheeler_transform(
	          input_data,
	          35,
	          30,
	          output_data,
	          35,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

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
	result = bzip_reverse_burrows_wheeler_transform(
	          NULL,
	          35,
	          30,
	          output_data,
	          35,
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

/* Tests the bzip_read_stream_header function
 * Returns 1 if successful or 0 if not
 */
int assorted_test_bzip_read_stream_header(
     void )
{
	libcerror_error_t *error  = NULL;
	uint8_t compression_level = 0;
	int result                = 0;

	/* Test regular cases
	 */
	result = bzip_read_stream_header(
	          assorted_test_bzip_compressed_byte_stream,
	          125,
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
	result = bzip_read_stream_header(
	          NULL,
	          125,
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

	return( 1 );

on_error:
	return( 0 );
}

/* Tests the bzip_read_block_header function
 * Returns 1 if successful or 0 if not
 */
int assorted_test_bzip_read_block_header(
     void )
{
	bit_stream_t *bit_stream = NULL;
	libcerror_error_t *error = NULL;
	uint32_t origin_pointer  = 0;
	int result               = 0;

	/* Initialize test
	 */
	result = bit_stream_initialize(
	          &bit_stream,
	          assorted_test_bzip_compressed_byte_stream,
	          125,
	          4,
	          BIT_STREAM_STORAGE_TYPE_BYTE_FRONT_TO_BACK,
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
	result = bzip_read_block_header(
	          bit_stream,
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
	result = bzip_read_block_header(
	          NULL,
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
	result = bit_stream_free(
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
		bit_stream_free(
		 &bit_stream,
		 NULL );
	}
	return( 0 );
}

/* Tests the bzip_read_symbol_stack function
 * Returns 1 if successful or 0 if not
 */
int assorted_test_bzip_read_symbol_stack(
     void )
{
	uint8_t symbol_stack[ 256 ];

	uint8_t expected_symbol_stack[ 22 ] = {
		1, 32, 39, 44, 63, 73, 80, 97, 99, 100, 101, 102, 104, 105, 107, 108,
	       	111, 112, 114, 115, 116, 119 };

	bit_stream_t *bit_stream             = NULL;
	libcerror_error_t *error             = NULL;
	void *memset_result                  = NULL;
	uint32_t origin_pointer              = 0;
	uint16_t number_of_symbols           = 0;
	int result                           = 0;

	/* Initialize test
	 */
	result = bit_stream_initialize(
	          &bit_stream,
	          assorted_test_bzip_compressed_byte_stream,
	          125,
	          4,
	          BIT_STREAM_STORAGE_TYPE_BYTE_FRONT_TO_BACK,
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

	result = bzip_read_block_header(
	          bit_stream,
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
	result = bzip_read_symbol_stack(
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
	result = bzip_read_symbol_stack(
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
	result = bit_stream_free(
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
		bit_stream_free(
		 &bit_stream,
		 NULL );
	}
	return( 0 );
}

/* Tests the bzip_read_selectors function
 * Returns 1 if successful or 0 if not
 */
int assorted_test_bzip_read_selectors(
     void )
{
	uint8_t symbol_stack[ 256 ];
	uint8_t selectors[ ( 1 << 15 ) + 1 ];

	uint8_t expected_selectors[ 2 ] = {
		0, 1 };

	bit_stream_t *bit_stream        = NULL;
	libcerror_error_t *error        = NULL;
	void *memset_result             = NULL;
	uint32_t origin_pointer         = 0;
	uint32_t value_32bit            = 0;
	uint16_t number_of_selectors    = 0;
	uint16_t number_of_symbols      = 0;
	uint8_t number_of_trees         = 0;
	int result                      = 0;

	/* Initialize test
	 */
	result = bit_stream_initialize(
	          &bit_stream,
	          assorted_test_bzip_compressed_byte_stream,
	          125,
	          4,
	          BIT_STREAM_STORAGE_TYPE_BYTE_FRONT_TO_BACK,
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

	result = bzip_read_block_header(
	          bit_stream,
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

	result = bzip_read_symbol_stack(
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

	result = bit_stream_get_value(
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
	result = bzip_read_selectors(
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
	result = bzip_read_selectors(
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
	result = bit_stream_free(
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
		bit_stream_free(
		 &bit_stream,
		 NULL );
	}
	return( 0 );
}

/* Tests the bzip_read_huffman_tree function
 * Returns 1 if successful or 0 if not
 */
int assorted_test_bzip_read_huffman_tree(
     void )
{
	uint8_t symbol_stack[ 256 ];
	uint8_t selectors[ ( 1 << 15 ) + 1 ];

	bit_stream_t *bit_stream     = NULL;
	huffman_tree_t *huffman_tree = NULL;
	libcerror_error_t *error     = NULL;
	void *memset_result          = NULL;
	uint32_t origin_pointer      = 0;
	uint32_t value_32bit         = 0;
	uint16_t number_of_selectors = 0;
	uint16_t number_of_symbols   = 0;
	uint8_t number_of_trees      = 0;
	int result                   = 0;

	/* Initialize test
	 */
	result = bit_stream_initialize(
	          &bit_stream,
	          assorted_test_bzip_compressed_byte_stream,
	          125,
	          4,
	          BIT_STREAM_STORAGE_TYPE_BYTE_FRONT_TO_BACK,
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

	result = bzip_read_block_header(
	          bit_stream,
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

	result = bzip_read_symbol_stack(
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

	result = bit_stream_get_value(
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

	result = bzip_read_selectors(
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

	result = huffman_tree_initialize(
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
	result = bzip_read_huffman_tree(
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
	result = bzip_read_huffman_tree(
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
	result = huffman_tree_free(
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

	result = bit_stream_free(
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
		huffman_tree_free(
		 &huffman_tree,
		 NULL );
	}
	if( bit_stream != NULL )
	{
		bit_stream_free(
		 &bit_stream,
		 NULL );
	}
	return( 0 );
}

/* Tests the bzip_read_huffman_trees function
 * Returns 1 if successful or 0 if not
 */
int assorted_test_bzip_read_huffman_trees(
     void )
{
	uint8_t symbol_stack[ 256 ];
	uint8_t selectors[ ( 1 << 15 ) + 1 ];

	huffman_tree_t *huffman_trees[ 7 ] = { NULL, NULL, NULL, NULL, NULL, NULL, NULL };
	bit_stream_t *bit_stream           = NULL;
	libcerror_error_t *error           = NULL;
	void *memset_result                = NULL;
	uint32_t origin_pointer            = 0;
	uint32_t value_32bit               = 0;
	uint16_t number_of_selectors       = 0;
	uint16_t number_of_symbols         = 0;
	uint8_t number_of_trees            = 0;
	uint8_t tree_index                 = 0;
	int result                         = 0;

	/* Initialize test
	 */
	result = bit_stream_initialize(
	          &bit_stream,
	          assorted_test_bzip_compressed_byte_stream,
	          125,
	          4,
	          BIT_STREAM_STORAGE_TYPE_BYTE_FRONT_TO_BACK,
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

	result = bzip_read_block_header(
	          bit_stream,
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

	result = bzip_read_symbol_stack(
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

	result = bit_stream_get_value(
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

	result = bzip_read_selectors(
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
	result = bzip_read_huffman_trees(
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
	result = bzip_read_huffman_trees(
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
		result = huffman_tree_free(
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
	result = bit_stream_free(
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
		huffman_tree_free(
		 &( huffman_trees[ tree_index ] ),
		 NULL );
	}
	if( bit_stream != NULL )
	{
		bit_stream_free(
		 &bit_stream,
		 NULL );
	}
	return( 0 );
}

/* Tests the bzip_read_block_data function
 * Returns 1 if successful or 0 if not
 */
int assorted_test_bzip_read_block_data(
     void )
{
	uint8_t symbol_stack[ 256 ];
	uint8_t selectors[ ( 1 << 15 ) + 1 ];

	huffman_tree_t *huffman_trees[ 7 ] = { NULL, NULL, NULL, NULL, NULL, NULL, NULL };
	bit_stream_t *bit_stream           = NULL;
	libcerror_error_t *error           = NULL;
	void *memset_result                = NULL;
	uint32_t origin_pointer            = 0;
	uint32_t value_32bit               = 0;
	uint16_t number_of_selectors       = 0;
	uint16_t number_of_symbols         = 0;
	uint8_t number_of_trees            = 0;
	uint8_t tree_index                 = 0;
	int result                         = 0;

	/* Initialize test
	 */
	result = bit_stream_initialize(
	          &bit_stream,
	          assorted_test_bzip_compressed_byte_stream,
	          125,
	          4,
	          BIT_STREAM_STORAGE_TYPE_BYTE_FRONT_TO_BACK,
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

	result = bzip_read_block_header(
	          bit_stream,
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

	result = bzip_read_symbol_stack(
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

	result = bit_stream_get_value(
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

	result = bzip_read_selectors(
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

	result = bzip_read_huffman_trees(
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
/* TODO implement */

	/* Test error cases
	 */
/* TODO implement */

	/* Clean up
	 */
	for( tree_index = 0;
	     tree_index < number_of_trees;
	     tree_index++ )
	{
		result = huffman_tree_free(
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
	result = bit_stream_free(
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
		huffman_tree_free(
		 &( huffman_trees[ tree_index ] ),
		 NULL );
	}
	if( bit_stream != NULL )
	{
		bit_stream_free(
		 &bit_stream,
		 NULL );
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
	 "bzip_reverse_burrows_wheeler_transform",
	 assorted_test_bzip_reverse_burrows_wheeler_transform );

	ASSORTED_TEST_RUN(
	 "bzip_read_stream_header",
	 assorted_test_bzip_read_stream_header );

	ASSORTED_TEST_RUN(
	 "bzip_read_block_header",
	 assorted_test_bzip_read_block_header );

	ASSORTED_TEST_RUN(
	 "bzip_read_symbol_stack",
	 assorted_test_bzip_read_symbol_stack );

	ASSORTED_TEST_RUN(
	 "bzip_read_selectors",
	 assorted_test_bzip_read_selectors );

	ASSORTED_TEST_RUN(
	 "bzip_read_huffman_tree",
	 assorted_test_bzip_read_huffman_tree );

	ASSORTED_TEST_RUN(
	 "bzip_read_huffman_trees",
	 assorted_test_bzip_read_huffman_trees );

	ASSORTED_TEST_RUN(
	 "bzip_read_block_data",
	 assorted_test_bzip_read_block_data );

#endif /* defined( __GNUC__ ) */

	return( EXIT_SUCCESS );

#if defined( __GNUC__ )

on_error:
	return( EXIT_FAILURE );

#endif /* defined( __GNUC__ ) */
}

