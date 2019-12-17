/*
 * Copyright (c) 2013, infinit.io
 *
 * This software is provided "as is" without warranty of any kind,
 * either expressed or implied, including but not limited to the
 * implied warranties of fitness for a particular purpose.
 *
 * See the LICENSE file for more information on the terms and
 * conditions.
 */

#ifndef DOPENSSL_PLATFORM_H
# define DOPENSSL_PLATFORM_H

#if defined(_MSC_VER) || (defined(__INTEL_COMPILER) && defined(_WIN32))
#if defined(_M_X64)
#define DOPENSSL_64_BIT
#else
#define DOPENSSL_32_BIT
#endif

#elif defined(__clang__) || defined(__INTEL_COMPILER) || defined(__GNUC__)
#if defined(__x86_64)
#define DOPENSSL_64_BIT
#else
#define DOPENSSL_32_BIT
#endif

#else
#error "Error determining CPU target"
#endif

#endif
