/*
 * Bit-stream testing program
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
#include "assorted_test_memory.h"
#include "assorted_test_unused.h"

#include "../src/assorted_bit_stream.h"

/* Define to make assorted_test_bit_stream generate verbose output
#define ASSORTED_TEST_BIT_STREAM_VERBOSE
 */

uint8_t assorted_test_bit_stream_data[ 16 ] = {
	0x78, 0xda, 0xbd, 0x59, 0x6d, 0x8f, 0xdb, 0xb8, 0x11, 0xfe, 0x7c, 0xfa, 0x15, 0xc4, 0x7e, 0xb9 };

#if defined( __GNUC__ )

/* Tests the assorted_bit_stream_initialize function
 * Returns 1 if successful or 0 if not
 */
int assorted_test_bit_stream_initialize(
     void )
{
	libcerror_error_t *error          = NULL;
	assorted_bit_stream_t *bit_stream = NULL;
	int result                        = 0;

#if defined( HAVE_ASSORTED_TEST_MEMORY )
	int number_of_malloc_fail_tests   = 1;
	int number_of_memset_fail_tests   = 1;
	int test_number                   = 0;
#endif

	/* Test regular cases
	 */
	result = assorted_bit_stream_initialize(
	          &bit_stream,
	          assorted_test_bit_stream_data,
	          16,
	          0,
	          ASSORTED_BIT_STREAM_STORAGE_TYPE_BYTE_BACK_TO_FRONT,
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

	/* Test error cases
	 */
	result = assorted_bit_stream_initialize(
	          NULL,
	          assorted_test_bit_stream_data,
	          16,
	          0,
	          ASSORTED_BIT_STREAM_STORAGE_TYPE_BYTE_BACK_TO_FRONT,
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

	bit_stream = (assorted_bit_stream_t *) 0x12345678UL;

	result = assorted_bit_stream_initialize(
	          &bit_stream,
	          assorted_test_bit_stream_data,
	          16,
	          0,
	          ASSORTED_BIT_STREAM_STORAGE_TYPE_BYTE_BACK_TO_FRONT,
	          &error );

	bit_stream = NULL;

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	ASSORTED_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	result = assorted_bit_stream_initialize(
	          &bit_stream,
	          NULL,
	          16,
	          0,
	          ASSORTED_BIT_STREAM_STORAGE_TYPE_BYTE_BACK_TO_FRONT,
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

	result = assorted_bit_stream_initialize(
	          &bit_stream,
	          assorted_test_bit_stream_data,
	          (size_t) SSIZE_MAX + 1,
	          0,
	          ASSORTED_BIT_STREAM_STORAGE_TYPE_BYTE_BACK_TO_FRONT,
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

	result = assorted_bit_stream_initialize(
	          &bit_stream,
	          assorted_test_bit_stream_data,
	          16,
	          (size_t) SSIZE_MAX + 1,
	          ASSORTED_BIT_STREAM_STORAGE_TYPE_BYTE_BACK_TO_FRONT,
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

	result = assorted_bit_stream_initialize(
	          &bit_stream,
	          assorted_test_bit_stream_data,
	          16,
	          0,
	          0xff,
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

#if defined( HAVE_ASSORTED_TEST_MEMORY )

	for( test_number = 0;
	     test_number < number_of_malloc_fail_tests;
	     test_number++ )
	{
		/* Test assorted_bit_stream_initialize with malloc failing
		 */
		assorted_test_malloc_attempts_before_fail = test_number;

		result = assorted_bit_stream_initialize(
		          &bit_stream,
		          assorted_test_bit_stream_data,
		          16,
		          0,
		          ASSORTED_BIT_STREAM_STORAGE_TYPE_BYTE_BACK_TO_FRONT,
		          &error );

		if( assorted_test_malloc_attempts_before_fail != -1 )
		{
			assorted_test_malloc_attempts_before_fail = -1;

			if( bit_stream != NULL )
			{
				assorted_bit_stream_free(
				 &bit_stream,
				 NULL );
			}
		}
		else
		{
			ASSORTED_TEST_ASSERT_EQUAL_INT(
			 "result",
			 result,
			 -1 );

			ASSORTED_TEST_ASSERT_IS_NULL(
			 "bit_stream",
			 bit_stream );

			ASSORTED_TEST_ASSERT_IS_NOT_NULL(
			 "error",
			 error );

			libcerror_error_free(
			 &error );
		}
	}
	for( test_number = 0;
	     test_number < number_of_memset_fail_tests;
	     test_number++ )
	{
		/* Test assorted_bit_stream_initialize with memset failing
		 */
		assorted_test_memset_attempts_before_fail = test_number;

		result = assorted_bit_stream_initialize(
		          &bit_stream,
		          assorted_test_bit_stream_data,
		          16,
		          0,
		          ASSORTED_BIT_STREAM_STORAGE_TYPE_BYTE_BACK_TO_FRONT,
		          &error );

		if( assorted_test_memset_attempts_before_fail != -1 )
		{
			assorted_test_memset_attempts_before_fail = -1;

			if( bit_stream != NULL )
			{
				assorted_bit_stream_free(
				 &bit_stream,
				 NULL );
			}
		}
		else
		{
			ASSORTED_TEST_ASSERT_EQUAL_INT(
			 "result",
			 result,
			 -1 );

			ASSORTED_TEST_ASSERT_IS_NULL(
			 "bit_stream",
			 bit_stream );

			ASSORTED_TEST_ASSERT_IS_NOT_NULL(
			 "error",
			 error );

			libcerror_error_free(
			 &error );
		}
	}
#endif /* defined( HAVE_MODI_TEST_MEMORY ) */

	return( 1 );

on_error:
	if( error != NULL )
	{
		libcerror_error_free(
		 &error );
	}
	if( bit_stream != NULL )
	{
		assorted_bit_stream_free(
		 &bit_stream,
		 NULL );
	}
	return( 0 );
}

/* Tests the assorted_bit_stream_free function
 * Returns 1 if successful or 0 if not
 */
int assorted_test_bit_stream_free(
     void )
{
	libcerror_error_t *error = NULL;
	int result               = 0;

	/* Test error cases
	 */
	result = assorted_bit_stream_free(
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

/* Tests the assorted_bit_stream_read function
 * Returns 1 if successful or 0 if not
 */
int assorted_test_bit_stream_read(
     void )
{
	assorted_bit_stream_t *bit_stream = NULL;
	libcerror_error_t *error          = NULL;
	int result                        = 0;

	/* Initialize test
	 */
	result = assorted_bit_stream_initialize(
	          &bit_stream,
	          assorted_test_bit_stream_data,
	          16,
	          0,
	          ASSORTED_BIT_STREAM_STORAGE_TYPE_BYTE_BACK_TO_FRONT,
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
	result = assorted_bit_stream_read(
	          bit_stream,
	          8,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	ASSORTED_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	ASSORTED_TEST_ASSERT_EQUAL_SIZE(
	 "bit_stream->byte_stream_offset",
	 bit_stream->byte_stream_offset,
	 (size_t) 1 );

	ASSORTED_TEST_ASSERT_EQUAL_UINT32(
	 "bit_stream->bit_buffer",
	 bit_stream->bit_buffer,
	 (uint32_t) 0x00000078UL );

	ASSORTED_TEST_ASSERT_EQUAL_UINT8(
	 "bit_stream->bit_buffer_size",
	 bit_stream->bit_buffer_size,
	 (uint8_t) 8 );

	/* Test error cases
	 */
	result = assorted_bit_stream_read(
	          NULL,
	          8,
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

/* Tests the assorted_bit_stream_get_value function
 * Returns 1 if successful or 0 if not
 */
int assorted_test_bit_stream_get_value(
     void )
{
	assorted_bit_stream_t *bit_stream = NULL;
	libcerror_error_t *error          = NULL;
	uint32_t value_32bit              = 0;
	int result                        = 0;

	/* Initialize test
	 */
	result = assorted_bit_stream_initialize(
	          &bit_stream,
	          assorted_test_bit_stream_data,
	          16,
	          0,
	          ASSORTED_BIT_STREAM_STORAGE_TYPE_BYTE_BACK_TO_FRONT,
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
	result = assorted_bit_stream_get_value(
	          bit_stream,
	          0,
	          &value_32bit,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	ASSORTED_TEST_ASSERT_EQUAL_UINT32(
	 "value_32bit",
	 value_32bit,
	 (uint32_t) 0x00000000UL );

	ASSORTED_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	ASSORTED_TEST_ASSERT_EQUAL_SIZE(
	 "bit_stream->byte_stream_offset",
	 bit_stream->byte_stream_offset,
	 (size_t) 0 );

	ASSORTED_TEST_ASSERT_EQUAL_UINT32(
	 "bit_stream->bit_buffer",
	 bit_stream->bit_buffer,
	 (uint32_t) 0x00000000UL );

	ASSORTED_TEST_ASSERT_EQUAL_UINT8(
	 "bit_stream->bit_buffer_size",
	 bit_stream->bit_buffer_size,
	 (uint8_t) 0 );

	result = assorted_bit_stream_get_value(
	          bit_stream,
	          4,
	          &value_32bit,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	ASSORTED_TEST_ASSERT_EQUAL_UINT32(
	 "value_32bit",
	 value_32bit,
	 (uint32_t) 0x00000008UL );

	ASSORTED_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	ASSORTED_TEST_ASSERT_EQUAL_SIZE(
	 "bit_stream->byte_stream_offset",
	 bit_stream->byte_stream_offset,
	 (size_t) 1 );

	ASSORTED_TEST_ASSERT_EQUAL_UINT32(
	 "bit_stream->bit_buffer",
	 bit_stream->bit_buffer,
	 (uint32_t) 0x00000007UL );

	ASSORTED_TEST_ASSERT_EQUAL_UINT8(
	 "bit_stream->bit_buffer_size",
	 bit_stream->bit_buffer_size,
	 (uint8_t) 4 );

	result = assorted_bit_stream_get_value(
	          bit_stream,
	          12,
	          &value_32bit,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	ASSORTED_TEST_ASSERT_EQUAL_UINT32(
	 "value_32bit",
	 value_32bit,
	 (uint32_t) 0x00000da7UL );

	ASSORTED_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	ASSORTED_TEST_ASSERT_EQUAL_SIZE(
	 "bit_stream->byte_stream_offset",
	 bit_stream->byte_stream_offset,
	 (size_t) 2 );

	ASSORTED_TEST_ASSERT_EQUAL_UINT32(
	 "bit_stream->bit_buffer",
	 bit_stream->bit_buffer,
	 (uint32_t) 0x00000000UL );

	ASSORTED_TEST_ASSERT_EQUAL_UINT8(
	 "bit_stream->bit_buffer_size",
	 bit_stream->bit_buffer_size,
	 (uint8_t) 0 );

	result = assorted_bit_stream_get_value(
	          bit_stream,
	          32,
	          &value_32bit,
	          &error );

	ASSORTED_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	ASSORTED_TEST_ASSERT_EQUAL_UINT32(
	 "value_32bit",
	 value_32bit,
	 (uint32_t) 0x8f6d59bdUL );

	ASSORTED_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	ASSORTED_TEST_ASSERT_EQUAL_SIZE(
	 "bit_stream->byte_stream_offset",
	 bit_stream->byte_stream_offset,
	 (size_t) 6 );

	ASSORTED_TEST_ASSERT_EQUAL_UINT32(
	 "bit_stream->bit_buffer",
	 bit_stream->bit_buffer,
	 (uint32_t) 0x00000000UL );

	ASSORTED_TEST_ASSERT_EQUAL_UINT8(
	 "bit_stream->bit_buffer_size",
	 bit_stream->bit_buffer_size,
	 (uint8_t) 0 );

	/* Test error cases
	 */
	result = assorted_bit_stream_get_value(
	          NULL,
	          32,
	          &value_32bit,
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

	result = assorted_bit_stream_get_value(
	          bit_stream,
	          64,
	          &value_32bit,
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

	result = assorted_bit_stream_get_value(
	          bit_stream,
	          32,
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

	bit_stream->byte_stream_offset = 16;
        bit_stream->bit_buffer_size    = 0;

	result = assorted_bit_stream_get_value(
	          bit_stream,
	          32,
	          &value_32bit,
	          &error );

	bit_stream->byte_stream_offset = 0;

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

#if defined( HAVE_DEBUG_OUTPUT ) && defined( ASSORTED_TEST_BIT_STREAM_VERBOSE )
	libcnotify_verbose_set(
	 1 );
	libcnotify_stream_set(
	 stderr,
	 NULL );
#endif

#if defined( __GNUC__ )

	ASSORTED_TEST_RUN(
	 "assorted_bit_stream_initialize",
	 assorted_test_bit_stream_initialize );

	ASSORTED_TEST_RUN(
	 "assorted_bit_stream_free",
	 assorted_test_bit_stream_free );

	ASSORTED_TEST_RUN(
	 "assorted_bit_stream_read",
	 assorted_test_bit_stream_read );

	ASSORTED_TEST_RUN(
	 "assorted_bit_stream_get_value",
	 assorted_test_bit_stream_get_value );

#endif /* defined( __GNUC__ ) */

	return( EXIT_SUCCESS );

#if defined( __GNUC__ )

on_error:
	return( EXIT_FAILURE );

#endif /* defined( __GNUC__ ) */
}

