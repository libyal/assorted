/*
 * ADC (un)compression testing program
 *
 * Copyright (C) 2009-2021, Joachim Metz <joachim.metz@gmail.com>
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

#include "../src/adc.h"

/* Define to make assorted_test_adc generate verbose output
#define ASSORTED_TEST_ADC_VERBOSE
 */

uint8_t assorted_test_adc_compressed_data[ 10 ] = {
	0x83, 0xfe, 0xed, 0xfa, 0xce, 0x00, 0x00, 0x40, 0x00, 0x06 };

#if defined( __GNUC__ )

/* Tests the adc_decompress function
 * Returns 1 if successful or 0 if not
 */
int assorted_test_adc_decompress(
     void )
{
	uint8_t uncompressed_data[ 16 ];

	uint8_t expected_uncompressed_data[ 11 ] = {
		0xfe, 0xed, 0xfa, 0xce, 0xce, 0xce, 0xce, 0xfe, 0xed, 0xfa, 0xce };

	libcerror_error_t *error                 = NULL;
	size_t uncompressed_data_size            = 0;
	int result                               = 0;

	/* Test regular cases
	 */
	uncompressed_data_size = 16;

	result = adc_decompress(
	          assorted_test_adc_compressed_data,
	          10,
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
	 (size_t) 11 );

	ASSORTED_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = memory_compare(
	          uncompressed_data,
	          expected_uncompressed_data,
	          11 );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 0 );

	/* Test error cases
	 */
	uncompressed_data_size = 16;

	result = adc_decompress(
	          NULL,
	          10,
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

	result = adc_decompress(
	          assorted_test_adc_compressed_data,
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

	result = adc_decompress(
	          assorted_test_adc_compressed_data,
	          10,
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

	result = adc_decompress(
	          assorted_test_adc_compressed_data,
	          10,
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

	result = adc_decompress(
	          assorted_test_adc_compressed_data,
	          10,
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

#if defined( HAVE_DEBUG_OUTPUT ) && defined( ASSORTED_TEST_ADC_VERBOSE )
	libcnotify_verbose_set(
	 1 );
	libcnotify_stream_set(
	 stderr,
	 NULL );
#endif

#if defined( __GNUC__ )

	ASSORTED_TEST_RUN(
	 "adc_decompress",
	 assorted_test_adc_decompress );

#endif /* defined( __GNUC__ ) */

	return( EXIT_SUCCESS );

#if defined( __GNUC__ )

on_error:
	return( EXIT_FAILURE );

#endif /* defined( __GNUC__ ) */
}

