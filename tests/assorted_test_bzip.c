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

#if defined( __GNUC__ )

#ifdef TODO

/* Tests the bzip_decode_move_to_front_transform function
 * Returns 1 if successful or 0 if not
 */
int assorted_test_bzip_decode_move_to_front_transform(
     void )
{
	uint8_t expected_symbols[ 29 ] = {
		'b', 'b', 'y', 'a', 'e', 'e', 'e', 'e', 'e', 'e', 'a', 'f', 'e', 'e', 'e', 'y',
	       	'b', 'z', 'z', 'z', 'z', 'z', 'z', 'z', 'z', 'z', 'y', 'z' };
	uint8_t indexes[ 28 ] = {
		1, 0, 4, 2, 3, 0, 0, 0, 0, 0, 1, 4, 2, 0, 0, 3,
	       	4, 5, 0, 0, 0, 0, 0, 0, 0, 0, 2, 1 };
	uint8_t stack[ 6 ] = {
		97, 98, 101, 102, 121, 122 };
	uint8_t symbols[ 29 ] = {
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0 };

	libcerror_error_t *error = NULL;
	int result               = 0;

	/* Test regular cases
	 */
	result = bzip_decode_move_to_front_transform(
	          symbols,
	          indexes,
	          stack,
	          28,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	ASSORTED_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = memory_compare(
	          symbols,
	          expected_symbols,
	          29 );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 0 );

	/* Test error cases
	 */
	result = bzip_decode_move_to_front_transform(
	          NULL,
	          indexes,
	          stack,
	          28,
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

	result = bzip_decode_move_to_front_transform(
	          symbols,
	          NULL,
	          stack,
	          28,
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

	result = bzip_decode_move_to_front_transform(
	          symbols,
	          indexes,
	          NULL,
	          28,
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

#endif /* TODO */

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

#ifdef TODO

	ASSORTED_TEST_RUN(
	 "bzip_decode_move_to_front_transform",
	 assorted_test_bzip_decode_move_to_front_transform );

#endif /* TODO */

#endif /* defined( __GNUC__ ) */

	return( EXIT_SUCCESS );

#if defined( __GNUC__ )

on_error:
	return( EXIT_FAILURE );

#endif /* defined( __GNUC__ ) */
}

