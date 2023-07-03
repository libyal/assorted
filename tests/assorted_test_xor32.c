/*
 * XOR-32 checksum testing program
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

#include "../src/assorted_xor32.h"

/* Define to make assorted_test_xor32 generate verbose output
#define ASSORTED_TEST_XOR32_VERBOSE
 */

uint8_t assorted_test_xor32_data[ 16 ] = {
	0x78, 0xda, 0xbd, 0x59, 0x6d, 0x8f, 0xdb, 0xb8, 0x11, 0xfe, 0x7c, 0xfa, 0x15, 0xc4, 0x7e, 0xb9 };

#if defined( __GNUC__ )

/* Tests the assorted_xor32_calculate_checksum_little_endian_basic function
 * Returns 1 if successful or 0 if not
 */
int assorted_test_xor32_calculate_checksum_little_endian_basic(
     void )
{
	libcerror_error_t *error = NULL;
	uint32_t checksum_value  = 0;
	int result               = 0;

	/* Test regular cases
	 */
	result = assorted_xor32_calculate_checksum_little_endian_basic(
	          &checksum_value,
	          assorted_test_xor32_data,
	          16,
	          0,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	ASSORTED_TEST_ASSERT_EQUAL_UINT32(
	 "checksum_value",
	 checksum_value,
	 (uint32_t) 0xa2646f11UL );

	ASSORTED_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test error cases
	 */
	result = assorted_xor32_calculate_checksum_little_endian_basic(
	          NULL,
	          assorted_test_xor32_data,
	          16,
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

	result = assorted_xor32_calculate_checksum_little_endian_basic(
	          &checksum_value,
	          NULL,
	          16,
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

	result = assorted_xor32_calculate_checksum_little_endian_basic(
	          &checksum_value,
	          assorted_test_xor32_data,
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

/* Tests the assorted_xor32_calculate_checksum_little_endian_cpu_aligned function
 * Returns 1 if successful or 0 if not
 */
int assorted_test_xor32_calculate_checksum_little_endian_cpu_aligned(
     void )
{
	libcerror_error_t *error = NULL;
	uint32_t checksum_value  = 0;
	int result               = 0;

	/* Test regular cases
	 */
	result = assorted_xor32_calculate_checksum_little_endian_cpu_aligned(
	          &checksum_value,
	          assorted_test_xor32_data,
	          16,
	          0,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	ASSORTED_TEST_ASSERT_EQUAL_UINT32(
	 "checksum_value",
	 checksum_value,
	 (uint32_t) 0xa2646f11UL );

	ASSORTED_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test error cases
	 */
	result = assorted_xor32_calculate_checksum_little_endian_cpu_aligned(
	          NULL,
	          assorted_test_xor32_data,
	          16,
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

	result = assorted_xor32_calculate_checksum_little_endian_cpu_aligned(
	          &checksum_value,
	          NULL,
	          16,
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

	result = assorted_xor32_calculate_checksum_little_endian_cpu_aligned(
	          &checksum_value,
	          assorted_test_xor32_data,
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

#if defined( HAVE_DEBUG_OUTPUT ) && defined( ASSORTED_TEST_XOR32_VERBOSE )
	libcnotify_verbose_set(
	 1 );
	libcnotify_stream_set(
	 stderr,
	 NULL );
#endif

#if defined( __GNUC__ )

	ASSORTED_TEST_RUN(
	 "xor32_calculate_checksum_little_endian_basic",
	 assorted_test_xor32_calculate_checksum_little_endian_basic );

	ASSORTED_TEST_RUN(
	 "xor32_calculate_checksum_little_endian_cpu_aligned",
	 assorted_test_xor32_calculate_checksum_little_endian_cpu_aligned );

#endif /* defined( __GNUC__ ) */

	return( EXIT_SUCCESS );

#if defined( __GNUC__ )

on_error:
	return( EXIT_FAILURE );

#endif /* defined( __GNUC__ ) */
}

