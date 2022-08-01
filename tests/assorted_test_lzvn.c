/*
 * LZVN (un)compression testing program
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

#include "../src/lzvn.h"

/* Define to make assorted_test_lzvn generate verbose output
#define ASSORTED_TEST_LZVN_VERBOSE
 */

uint8_t assorted_test_lzvn_compressed_data[ 29 ] = {
	0xe0, 0x03, 0x4d, 0x79, 0x20, 0x63, 0x6f, 0x6d, 0x70, 0x72, 0x65, 0x73, 0x73, 0x65, 0x64, 0x20,
	0x66, 0x69, 0x6c, 0x65, 0x0a, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

uint8_t assorted_test_lzvn_uncompressed_data[ 19 ] = {
	0x4d, 0x79, 0x20, 0x63, 0x6f, 0x6d, 0x70, 0x72, 0x65, 0x73, 0x73, 0x65, 0x64, 0x20, 0x66, 0x69,
	0x6c, 0x65, 0x0a };

#if defined( __GNUC__ )

/* Tests the lzvn_decompress function
 * Returns 1 if successful or 0 if not
 */
int assorted_test_lzvn_decompress(
     void )
{
	uint8_t uncompressed_data[ 64 ];

	libcerror_error_t *error      = NULL;
	size_t uncompressed_data_size = 19;
	int result                    = 0;

	/* Test regular cases
	 */
	result = lzvn_decompress(
	          assorted_test_lzvn_compressed_data,
	          29,
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
	 (size_t) 19 );

	ASSORTED_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = memory_compare(
	          uncompressed_data,
	          assorted_test_lzvn_uncompressed_data,
	          19 );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 0 );

/* TODO: test uncompressed data too small */

	/* Test error cases
	 */
	result = lzvn_decompress(
	          NULL,
	          29,
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

	result = lzvn_decompress(
	          assorted_test_lzvn_compressed_data,
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

	result = lzvn_decompress(
	          assorted_test_lzvn_compressed_data,
	          29,
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

	result = lzvn_decompress(
	          assorted_test_lzvn_compressed_data,
	          29,
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

#if defined( HAVE_DEBUG_OUTPUT ) && defined( ASSORTED_TEST_LZVN_VERBOSE )
	libcnotify_verbose_set(
	 1 );
	libcnotify_stream_set(
	 stderr,
	 NULL );
#endif

#if defined( __GNUC__ )

	ASSORTED_TEST_RUN(
	 "lzvn_decompress",
	 assorted_test_lzvn_decompress );

#endif /* defined( __GNUC__ ) */

	return( EXIT_SUCCESS );

#if defined( __GNUC__ )

on_error:
	return( EXIT_FAILURE );

#endif /* defined( __GNUC__ ) */
}

