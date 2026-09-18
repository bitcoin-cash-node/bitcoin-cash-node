# Copyright (c) 2026-present The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

#.rst:
# FindAtomic
# -----
# Finds the ATOMIC library
#
# This will define the following variables::
#
# ATOMIC_FOUND - system has ATOMIC
# ATOMIC_LIBRARIES - the ATOMIC libraries
#
# and the following imported targets::
#
#   ATOMIC::ATOMIC    - The ATOMIC library


include(CheckCXXSourceCompiles)

set(atomic_code
    "
    #include <atomic>
    #include <cstdint>
    struct S { uint64_t a, b, c; };
    std::atomic<S> s;
    std::atomic<uint64_t> u;
    int main() {
        u = 1;
        s.store(S{.a=0, .b=2, .c=++u});
        return s.load().a;
    }")

check_cxx_source_compiles("${atomic_code}" ATOMIC_LIBRARY_NOT_NEEDED)

if(ATOMIC_LIBRARY_NOT_NEEDED)
    set(ATOMIC_FOUND TRUE)
    set(ATOMIC_LIBRARIES)
    unset(ATOMIC_LIBRARY_NOT_NEEDED)
else()
    set(OLD_CMAKE_REQUIRED_LIBRARIES "${CMAKE_REQUIRED_LIBRARIES}")
    set(CMAKE_REQUIRED_LIBRARIES "-latomic")
    check_cxx_source_compiles("${atomic_code}" ATOMIC_IN_LIBRARY)
    set(CMAKE_REQUIRED_LIBRARIES)
    if(ATOMIC_IN_LIBRARY)
        set(ATOMIC_LIBRARY atomic)
        include(FindPackageHandleStandardArgs)
        find_package_handle_standard_args(Atomic DEFAULT_MSG ATOMIC_LIBRARY)
        set(ATOMIC_LIBRARIES ${ATOMIC_LIBRARY})
        if(NOT TARGET ATOMIC::ATOMIC)
            add_library(ATOMIC::ATOMIC UNKNOWN IMPORTED)
            set_target_properties(ATOMIC::ATOMIC PROPERTIES IMPORTED_LOCATION "${ATOMIC_LIBRARY}")
        endif()
        unset(ATOMIC_LIBRARY)
    else()
        if(Atomic_FIND_REQUIRED)
            message(FATAL_ERROR "Cannot compile atomics and -latomic was not found.")
        endif()
    endif()
    set(CMAKE_REQUIRED_LIBRARIES "${OLD_CMAKE_REQUIRED_LIBRARIES}")
endif()
unset(atomic_code)
