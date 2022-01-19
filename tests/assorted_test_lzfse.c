/*
 * LZFSE (un)compression testing program
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

#include "../src/lzfse.h"

/* Define to make assorted_test_lzfse generate verbose output
#define ASSORTED_TEST_LZFSE_VERBOSE
 */

uint8_t assorted_test_lzfse_compressed_data[ 226 ] = {
	0x62, 0x76, 0x78, 0x32, 0x00, 0x40, 0x00, 0x00, 0x44, 0x00, 0x30, 0x02, 0x00, 0x0a, 0x00, 0x40,
	0xe4, 0x8b, 0xd9, 0xa2, 0xc9, 0x18, 0x00, 0x00, 0xa3, 0x00, 0x00, 0x00, 0x3a, 0x24, 0xc0, 0x0e,
	0x0f, 0x01, 0x4c, 0x80, 0x09, 0x00, 0x30, 0x27, 0x13, 0x80, 0x09, 0x00, 0x13, 0x80, 0xb7, 0xe0,
	0x9d, 0x79, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0xe0, 0xe5, 0x02, 0xb8, 0x03, 0x00, 0x80, 0xbb, 0x37, 0x00, 0x00, 0xb8, 0x03, 0xe0,
	0xee, 0x0e, 0x00, 0xb8, 0x03, 0x00, 0xee, 0xe0, 0xee, 0x0e, 0x00, 0x00, 0x00, 0xee, 0x00, 0xb8,
	0xbb, 0x03, 0x00, 0x00, 0xb8, 0x03, 0x00, 0xe0, 0x0e, 0xee, 0xbe, 0x02, 0xee, 0x78, 0x03, 0xee,
	0xee, 0xb8, 0x03, 0xe0, 0x0e, 0x00, 0xe0, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x80, 0x37, 0x80, 0x3b, 0x00, 0x00, 0xee, 0x00, 0xb8, 0x03, 0x00, 0xee, 0x00, 0x00,
	0x00, 0x00, 0xb8, 0xbb, 0xbb, 0x03, 0xb8, 0x03, 0x00, 0xe0, 0x0e, 0xe0, 0x0e, 0xee, 0xee, 0x00,
	0x00, 0x00, 0x00, 0x00, 0xef, 0x1c, 0x68, 0xbd, 0xc5, 0xd0, 0xc4, 0x3c, 0x8c, 0xb7, 0xbe, 0x86,
	0x9b, 0xeb, 0x76, 0x65, 0xd2, 0x38, 0x3e, 0x26, 0x5c, 0x31, 0x96, 0xe7, 0x57, 0xc5, 0x31, 0xd3,
	0x83, 0xb0, 0x45, 0x9f, 0xa7, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0xca,
	0xfd, 0x9f, 0xff, 0xff, 0xbf, 0xff, 0xff, 0xbf, 0xff, 0x83, 0x81, 0x89, 0x26, 0x01, 0x62, 0x76,
	0x78, 0x24 };

#if defined( __GNUC__ )

/* Tests the lzfse_decompress function
 * Returns 1 if successful or 0 if not
 */
int assorted_test_lzfse_decompress(
     void )
{
	uint8_t uncompressed_data[ 512 ];

	libcerror_error_t *error      = NULL;
	size_t uncompressed_data_size = 0;
	int result                    = 0;

	/* Test regular cases
	 */
	uncompressed_data_size = 512;

/* TODO
	result = lzfse_decompress(
	          assorted_test_lzfse_compressed_data,
	          226,
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
	 (size_t) 512 );

	ASSORTED_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = memory_compare(
	          uncompressed_data,
	          expected_uncompressed_data,
	          512 );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 0 );
*/

	/* Test error cases
	 */
	uncompressed_data_size = 512;

	result = lzfse_decompress(
	          NULL,
	          226,
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

	result = lzfse_decompress(
	          assorted_test_lzfse_compressed_data,
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

	result = lzfse_decompress(
	          assorted_test_lzfse_compressed_data,
	          226,
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

	result = lzfse_decompress(
	          assorted_test_lzfse_compressed_data,
	          226,
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

	uncompressed_data_size = (size_t) SSIZE_MAX + 1;

	result = lzfse_decompress(
	          assorted_test_lzfse_compressed_data,
	          226,
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

	return( 1 );

on_error:
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

#if defined( HAVE_DEBUG_OUTPUT ) && defined( ASSORTED_TEST_LZFSE_VERBOSE )
	libcnotify_verbose_set(
	 1 );
	libcnotify_stream_set(
	 stderr,
	 NULL );
#endif

#if defined( __GNUC__ )

	ASSORTED_TEST_RUN(
	 "lzfse_decompress",
	 assorted_test_lzfse_decompress );

#endif /* defined( __GNUC__ ) */

	return( EXIT_SUCCESS );

#if defined( __GNUC__ )

on_error:
	return( EXIT_FAILURE );

#endif /* defined( __GNUC__ ) */
}

