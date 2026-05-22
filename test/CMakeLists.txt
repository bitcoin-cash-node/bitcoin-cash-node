###
# User options
##
set(EXCLUDE_FUNCTIONAL_TESTS "" CACHE STRING "Comma-separated-list of functional tests to exclude.")

###
# Create config.ini file for tests
###
if("fuzzer" IN_LIST ENABLE_SANITIZERS)
  set(ENABLE_FUZZ ON)
else()
  set(ENABLE_FUZZ OFF)
endif()

# Create build ini file
configure_file(config.ini.cmake.in config.ini)

option(ENABLE_EATMYDATA "Enable eatmydata to speed up tests by suppressing fsync calls" ON)
if(ENABLE_EATMYDATA)
  find_program(EATMYDATA eatmydata)
  if(EATMYDATA)
    message(STATUS "Found eatmydata at ${EATMYDATA} - tests will be sped up by suppressing fsync.  Disable this behaviour with -DENABLE_EATMYDATA=OFF.")
    set(EATMYDATA_EXECUTABLE "${EATMYDATA}" CACHE FILEPATH "location of the eatmydata binary (optional)")
  endif()
endif()

###
# Setup symlinks for testing
###
include(SanitizeHelper)
function(make_link file)
  set(src "${CMAKE_CURRENT_SOURCE_DIR}/${file}")
  set(dest "${CMAKE_CURRENT_BINARY_DIR}/${file}")

  # Create the target directory and parents if needed.
  get_filename_component(dest_dir "${dest}" DIRECTORY)
  file(MAKE_DIRECTORY "${dest_dir}")

  add_custom_command(
    OUTPUT "${dest}"
    COMMAND ${CMAKE_COMMAND} -E create_symlink "${src}" "${dest}"
    COMMENT "link ${file}"
    MAIN_DEPENDENCY "${src}"
  )
  # Add a phony target to make sure the files are linked by default.
  sanitize_target_name("link-" "${file}" NAME)
  add_custom_target(${NAME} ALL DEPENDS "${dest}")
endfunction()

make_link(functional/test_runner.py)
make_link(util/bitcoin-util-test.py)
make_link(util/rpcauth-test.py)
make_link(fuzz/test_runner.py)

include(Coverage)
include(TestSuite)

macro(add_functional_test_check TARGET COMMENT)
  if ("${EXCLUDE_FUNCTIONAL_TESTS}" STREQUAL "")
    set(exclude_arg "")
  else()
    set(exclude_arg "--exclude=${EXCLUDE_FUNCTIONAL_TESTS}")
  endif()
  set(listDepends "")
  list(APPEND listDepends "bitcoind"
                          "bitcoin-cli"
                          ${CMAKE_CURRENT_BINARY_DIR}/functional/test_runner.py)
  if(BUILD_BITCOIN_WALLET)
      list(APPEND listDepends "bitcoin-wallet")
  endif()
  add_test_custom_target(${TARGET}
    TEST_COMMAND
      "${EATMYDATA_EXECUTABLE}"
      "${Python_EXECUTABLE}"
      ./functional/test_runner.py
      ${ARGN}
      ${exclude_arg}
    CUSTOM_TARGET_ARGS
      COMMENT "${COMMENT}"
      DEPENDS
        ${listDepends}
      USES_TERMINAL
      VERBATIM
  )

  add_custom_target_coverage(${TARGET})
endmacro()

add_functional_test_check(check-functional
  "Run the functional tests"
)
add_dependencies(check-all check-functional)

add_functional_test_check(check-functional-extended
  "Run the extended functional tests"
  --extended
  --coverage
)
add_dependencies(check-extended check-functional-extended)

set(TEST_SUITE_NAME_UPGRADE_ACTIVATED "Bitcoin Cash Node functional tests with the next upgrade activated")

add_functional_test_check(check-functional-upgrade-activated
  "Run the functional tests with the upgrade activated"
  --with-upgrade2027activation
  -n "${TEST_SUITE_NAME_UPGRADE_ACTIVATED}"
)
add_dependencies(check-upgrade-activated check-functional-upgrade-activated)

add_functional_test_check(check-functional-upgrade-activated-extended
  "Run the extended functional tests with the upgrade activated"
  --extended
  --with-upgrade2027activation
  -n "${TEST_SUITE_NAME_UPGRADE_ACTIVATED}"
)
add_dependencies(check-upgrade-activated-extended check-functional-upgrade-activated-extended)

# same constant as in test_runner.py
set(DEFAULT_EXTENDED_CUTOFF 40)

add_functional_test_check(check-functional-longeronly
    "Run the long-runtime functional tests only"
    --startfrom=${DEFAULT_EXTENDED_CUTOFF}
)

add_functional_test_check(check-functional-upgrade-activated-longeronly
  "Run the long-runtime functional tests only with the upgrade activated"
  --with-upgrade12activation
    --startfrom=${DEFAULT_EXTENDED_CUTOFF}
)


if(BUILD_BITCOIN_TX)
  add_test_custom_target(check-bitcoin-util
    TEST_COMMAND
      "${EATMYDATA_EXECUTABLE}"
      "${Python_EXECUTABLE}"
      ./util/bitcoin-util-test.py
    CUSTOM_TARGET_ARGS
      COMMENT "Test Bitcoin utilities..."
      DEPENDS
        bitcoin-tx
        ${CMAKE_CURRENT_BINARY_DIR}/util/bitcoin-util-test.py
  )

  add_dependencies(check check-bitcoin-util)
endif()

add_custom_target(check-rpcauth
  COMMENT "Test Bitcoin RPC authentication..."
  COMMAND
    "${EATMYDATA_EXECUTABLE}"
    "${Python_EXECUTABLE}"
    ./util/rpcauth-test.py
  DEPENDS
    ${CMAKE_CURRENT_BINARY_DIR}/util/rpcauth-test.py
  COMMAND_EXPAND_LISTS
)

add_dependencies(check check-rpcauth)

include(PackageHelper)
exclude_from_source_package(
  # Subdirectories
  "cache/"
  "lint/"
  "sanitizer_suppressions/"
)


set_property(DIRECTORY "${CMAKE_SOURCE_DIR}" APPEND PROPERTY ADDITIONAL_CLEAN_FILES "${CMAKE_CURRENT_BINARY_DIR}/tmp" "${CMAKE_CURRENT_BINARY_DIR}/cache")

add_subdirectory(lint)
