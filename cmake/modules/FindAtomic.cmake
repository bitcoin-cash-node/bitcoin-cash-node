# Copyright (c) 2026-present The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

#.rst:
# FindAtomic
# ----------
#
# Determine what is needed to use std::atomic<T> for types that are not
# lock-free (GCC requires linking against libatomic; clang/libc++ does not).
#
# This will define the following variables::
#
#   Atomic_FOUND - atomics are usable, with Atomic_LIBRARIES if non-empty
#   Atomic_LIBRARIES - libraries needed to use atomics; may be empty
#
# And the following imported target, defined only when a library is needed::
#
#   Atomic::Atomic

include(CheckCXXSourceCompiles)

# The 24-byte struct is what forces the compiler to emit out-of-line
# __atomic_load/__atomic_store calls rather than inline instructions.
set(_Atomic_TEST_SOURCE "
	#include <atomic>
	#include <cstdint>
	struct S { uint64_t a, b, c; };
	std::atomic<S> s;
	std::atomic<uint64_t> u;
	int main() {
		u = 1;
		s.store(S{0, 2, ++u});
		return static_cast<int>(s.load().a);
	}
")

check_cxx_source_compiles("${_Atomic_TEST_SOURCE}" Atomic_BUILTIN)

if(Atomic_BUILTIN)
	set(Atomic_LIBRARIES)
	set(Atomic_FOUND TRUE)
else()
	find_library(Atomic_LIBRARY NAMES atomic libatomic.so.1)

	set(_Atomic_SAVED_REQUIRED_LIBRARIES "${CMAKE_REQUIRED_LIBRARIES}")
	if(Atomic_LIBRARY)
		set(CMAKE_REQUIRED_LIBRARIES "${Atomic_LIBRARY}")
	else()
		# Some toolchains ship libatomic where only the linker can find it.
		set(CMAKE_REQUIRED_LIBRARIES "-latomic")
	endif()
	check_cxx_source_compiles("${_Atomic_TEST_SOURCE}" Atomic_WITH_LIBATOMIC)
	set(CMAKE_REQUIRED_LIBRARIES "${_Atomic_SAVED_REQUIRED_LIBRARIES}")
	unset(_Atomic_SAVED_REQUIRED_LIBRARIES)

	if(Atomic_WITH_LIBATOMIC)
		# Fall back to the bare library name when no path was resolved, and let
		# the linker find it. Not written to the cache, which holds paths only.
		if(Atomic_LIBRARY)
			set(_Atomic_LINK_ITEM "${Atomic_LIBRARY}")
		else()
			set(_Atomic_LINK_ITEM atomic)
		endif()
		set(Atomic_LIBRARIES "${_Atomic_LINK_ITEM}")
		if(NOT TARGET Atomic::Atomic)
			if(IS_ABSOLUTE "${_Atomic_LINK_ITEM}")
				add_library(Atomic::Atomic UNKNOWN IMPORTED)
				set_target_properties(Atomic::Atomic PROPERTIES
					IMPORTED_LOCATION "${_Atomic_LINK_ITEM}"
				)
			else()
				add_library(Atomic::Atomic INTERFACE IMPORTED)
				set_target_properties(Atomic::Atomic PROPERTIES
					INTERFACE_LINK_LIBRARIES "${_Atomic_LINK_ITEM}"
				)
			endif()
		endif()
		unset(_Atomic_LINK_ITEM)
	endif()

	include(FindPackageHandleStandardArgs)
	find_package_handle_standard_args(Atomic
		REQUIRED_VARS Atomic_LIBRARIES
		FAIL_MESSAGE "std::atomic<struct> does not link, with or without libatomic"
	)
	mark_as_advanced(Atomic_LIBRARY)
endif()

unset(_Atomic_TEST_SOURCE)
