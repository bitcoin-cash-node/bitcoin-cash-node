# Copyright (c) 2018-2026 The Bitcoin developers

project(bitcoin-test)

option(ENABLE_PROPERTY_BASED_TESTS "Enable property based tests" OFF)

# ZLib is required (we compresss the json libauth tests)
find_package(ZLIB)

# Process json files.
file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/data")

function(gen_json_header NAME)
  set(HEADERS "")
  foreach(f ${ARGN})
    set(h "${CMAKE_CURRENT_BINARY_DIR}/${f}.h")

    # Get the proper name for the test variable.
    get_filename_component(TEST_NAME ${f} NAME_WE)
    add_custom_command(OUTPUT ${h}
      COMMAND
        "${Python_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/data/generate_header.py"
        "${TEST_NAME}"
        "${CMAKE_CURRENT_SOURCE_DIR}/${f}" > ${h}
      MAIN_DEPENDENCY ${f}
      DEPENDS
        "data/generate_header.py"
      VERBATIM
    )
    list(APPEND HEADERS ${h})
  endforeach(f)
  set(${NAME} "${HEADERS}" PARENT_SCOPE)
endfunction()

gen_json_header(JSON_HEADERS
  data/base58_encode_decode.json
  data/blockfilters.json
  data/cashaddr_token_types.json
  data/key_io_valid.json
  data/key_io_invalid.json
  data/script_tests.json
  data/sighash.json
  data/token_tests_prefix_invalid.json
  data/token_tests_prefix_valid.json
  data/tx_invalid.json
  data/tx_valid.json
)

function(gen_json_header_and_cpp NAME)
  set(CPPS "")
  foreach(f ${ARGN})
    set(h "${CMAKE_CURRENT_BINARY_DIR}/${f}.h")
    set(cpp "${CMAKE_CURRENT_BINARY_DIR}/${f}.cpp")

    # Get the proper name for the test variable.
    get_filename_component(TEST_NAME ${f} NAME_WE)
    add_custom_command(OUTPUT ${h} ${cpp}
      COMMAND
        "${Python_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/data/generate_header_and_cpp.py"
        "${TEST_NAME}"
        "${CMAKE_CURRENT_SOURCE_DIR}/${f}"
        "${h}"
        "${cpp}"
      MAIN_DEPENDENCY ${f}
      DEPENDS
        "data/generate_header_and_cpp.py"
      VERBATIM
    )
    list(APPEND CPPS ${cpp})
  endforeach(f)
  set(${NAME} "${CPPS}" PARENT_SCOPE)
endfunction()

gen_json_header_and_cpp(JSON_CPPS
    data/bigint_exp_tests.json
    data/bigint_mod_tests.json
    data/bigint_mul_tests.json
    data/bigint_shift_tests.json
    data/bigint_sum_tests.json
    data/bigint_test_vectors.json
    data/libauth_expected_test_fail_reasons.json
    data/libauth_expected_test_metrics.json
)


function(gen_libauth_tests_autogen NAME)
  set(combined_vec_cpp "${CMAKE_CURRENT_BINARY_DIR}/data/libauth_test_vectors.json.cpp")
  set(combined_vec_h "${CMAKE_CURRENT_BINARY_DIR}/data/libauth_test_vectors.json.h")
  file(GLOB_RECURSE test_files LIST_DIRECTORIES false
      "${CMAKE_CURRENT_SOURCE_DIR}/data/vmb_tests/*/*.vmb_tests.json"
      "${CMAKE_CURRENT_SOURCE_DIR}/data/vmb_tests/*/*.scriptonly.json"
  )
  # We run the generate_libauth_test_vectors.py script twice, once to generate the header, and once for the .cpp file
  add_custom_command(OUTPUT ${combined_vec_cpp}
    COMMAND
      "${Python_EXECUTABLE}"
      "${CMAKE_CURRENT_SOURCE_DIR}/data/generate_libauth_test_vectors.py"
      "--encode" ${test_files} > ${combined_vec_cpp}
    DEPENDS
      "data/generate_libauth_test_vectors.py"
      ${test_files}
    VERBATIM
  )
  add_custom_command(OUTPUT ${combined_vec_h}
    COMMAND
      "${Python_EXECUTABLE}"
      "${CMAKE_CURRENT_SOURCE_DIR}/data/generate_libauth_test_vectors.py"
      "--encode" "--header-only" ${test_files} > ${combined_vec_h}
    DEPENDS
      "data/generate_libauth_test_vectors.py"
      ${test_files}
    VERBATIM
  )
  # Export both .cpp and .h files to outer scope to be added to build
  set(${NAME} "${combined_vec_cpp}" "${combined_vec_h}" PARENT_SCOPE)
endfunction()

gen_libauth_tests_autogen(LIBAUTH_TESTS_AUTOGEN)

function(gen_abla_tests_header NAME)
    set(combined_vec_h "${CMAKE_CURRENT_BINARY_DIR}/data/abla_test_vectors.json.h")
    file(GLOB vector_files "${CMAKE_CURRENT_SOURCE_DIR}/data/abla_test_vectors/config*-test*-*.json")
    add_custom_command(OUTPUT ${combined_vec_h}
      COMMAND
        "${Python_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/data/generate_abla_test_vectors.py"
        ${vector_files} > ${combined_vec_h}
      DEPENDS
        "data/generate_abla_test_vectors.py"
        ${vector_files}
      VERBATIM
    )
    set(${NAME} "${combined_vec_h}" PARENT_SCOPE)
endfunction()

gen_abla_tests_header(ABLA_HEADER)

include(TestSuite)
create_test_suite(bitcoin)
add_dependencies(check check-bitcoin)

if(BUILD_BITCOIN_WALLET)
  set(BITCOIN_WALLET_TEST_FIXTURE
    ../wallet/test/init_test_fixture.cpp
    ../wallet/test/wallet_test_fixture.cpp
  )
  set(BITCOIN_WALLET_TESTS
    ../wallet/test/db_tests.cpp
    ../wallet/test/coinselector_tests.cpp
    ../wallet/test/init_tests.cpp
    ../wallet/test/psbt_wallet_tests.cpp
    ../wallet/test/wallet_tests.cpp
    ../wallet/test/walletdb_tests.cpp
    ../wallet/test/wallet_crypto_tests.cpp
  )
endif()

if(ENABLE_PROPERTY_BASED_TESTS)
  find_package(Rapidcheck REQUIRED)

  set(BITCOIN_PROPERTY_BASED_TEST_FIXTURE
    gen/crypto_gen.cpp
  )
  set(BITCOIN_PROPERTY_BASED_TESTS
    key_properties.cpp
  )
endif()

function(gen_asmap_headers HEADERS_VAR)
  foreach(INPUT_FILE ${ARGN})
    set(OUTPUT_FILE "${CMAKE_CURRENT_BINARY_DIR}/${INPUT_FILE}.h")

    add_custom_command(
      OUTPUT "${OUTPUT_FILE}"
      COMMENT "Generate ASMAP header from ${INPUT_FILE}"
      COMMAND
        "${Python_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/data/generate_asmap.py"
        "${CMAKE_CURRENT_SOURCE_DIR}/${INPUT_FILE}"
        "${OUTPUT_FILE}"
      MAIN_DEPENDENCY "${INPUT_FILE}"
      DEPENDS
        "data/generate_header.py"
      VERBATIM
    )
    list(APPEND ${HEADERS_VAR} "${OUTPUT_FILE}")
  endforeach()
  set(${HEADERS_VAR} ${${HEADERS_VAR}} PARENT_SCOPE)
endfunction()

gen_asmap_headers(ASMAP_HEADERS
  data/asmap.raw
)

add_boost_unit_tests_to_suite(bitcoin test_bitcoin
  main.cpp

  TESTS
    abla_basic_tests.cpp
    abla_test_vectors.cpp
    activation_tests.cpp
    addrman_tests.cpp
    allocator_tests.cpp
    amount_tests.cpp
    arith_uint256_tests.cpp
    base32_tests.cpp
    base58_tests.cpp
    base64_tests.cpp
    bigint_script_property_tests.cpp
    bigint_tests.cpp
    bip32_tests.cpp
    bip69_tests.cpp
    bitmanip_tests.cpp
    blockchain_tests.cpp
    blockcheck_tests.cpp
    blockencodings_tests.cpp
    blockfilter_tests.cpp
    blockindex_tests.cpp
    blockstatus_tests.cpp
    blockstorage_tests.cpp
    bloom_tests.cpp
    bswap_tests.cpp
    cashaddrenc_tests.cpp
    cashaddr_tests.cpp
    checkdatasig_tests.cpp
    checkpoints_tests.cpp
    checkqueue_tests.cpp
    coins_tests.cpp
    compress_tests.cpp
    config_tests.cpp
    core_io_tests.cpp
    crypto_tests.cpp
    cuckoocache_tests.cpp
    dbwrapper_tests.cpp
    deadlock_tests.cpp
    denialofservice_tests.cpp
    descriptor_tests.cpp
    dsproof_dspidptr_tests.cpp
    dsproof_tests.cpp
    dstencode_tests.cpp
    ec_multiset_tests.cpp
    excessiveblock_tests.cpp
    extversion_tests.cpp
    feerate_tests.cpp
    finalization_header_tests.cpp
    finalization_tests.cpp
    flatfile_tests.cpp
    gbtlight_tests.cpp
    getarg_tests.cpp
    hash_tests.cpp
    heapoptional_tests.cpp
    inv_tests.cpp
    key_io_tests.cpp
    key_tests.cpp
    lcg_tests.cpp
    libauth_tests.cpp
    logging_tests.cpp
    mempool_tests.cpp
    merkleblock_tests.cpp
    merkle_tests.cpp
    miner_tests.cpp
    monolith_opcodes_tests.cpp
    multisig_tests.cpp
    native_introspection_tests.cpp
    netbase_tests.cpp
    net_tests.cpp
    op_reversebytes_tests.cpp
    orphanage_tests.cpp
    peerratelimiter_tests.cpp
    pmt_tests.cpp
    policyestimator_tests.cpp
    pow_tests.cpp
    prevector_tests.cpp
    raii_event_tests.cpp
    random_tests.cpp
    reverselock_tests.cpp
    rpc_server_tests.cpp
    rpc_tests.cpp
    rwcollection_tests.cpp
    sanity_tests.cpp
    scheduler_tests.cpp
    schnorr_tests.cpp
    script_bitfield_tests.cpp
    script_commitment_tests.cpp
    scriptnum_tests.cpp
    script_p2sh_tests.cpp
    script_standard_tests.cpp
    script_tests.cpp
    seedspec6_tests.cpp
    serialize_tests.cpp
    sigcache_tests.cpp
    sigcheckcount_tests.cpp
    sigencoding_tests.cpp
    sighash_tests.cpp
    sighashtype_tests.cpp
    skiplist_tests.cpp
    span_tests.cpp
    streams_tests.cpp
    sync_tests.cpp
    testlib_tests.cpp
    timedata_tests.cpp
    token_tests.cpp
    torcontrol_tests.cpp
    transaction_tests.cpp
    txindex_tests.cpp
    txrequest_tests.cpp
    txvalidationcache_tests.cpp
    txvalidation_tests.cpp
    uint256_tests.cpp
    undo_tests.cpp
    util_tests.cpp
    util_threadnames_tests.cpp
    validation_block_tests.cpp
    validation_tests.cpp
    vmlimits_tests.cpp
    work_comparator_tests.cpp

    # RPC Tests
    ../rpc/test/server_tests.cpp

    # Wallet tests
    ${BITCOIN_WALLET_TESTS}

    # Properties based tests
    ${BITCOIN_PROPERTY_BASED_TESTS}
)

add_library(test_common OBJECT EXCLUDE_FROM_ALL
    check_assert.cpp
    jsonutil.cpp
    lib/transaction_utils.cpp
    libauth_testing_setup.cpp
    scriptflags.cpp
    setup_common.cpp
    sigutil.cpp
    util.cpp

    ${ASMAP_HEADERS}

    # Tests generated from JSON
    ${JSON_HEADERS}
    ${JSON_CPPS}
    ${LIBAUTH_TESTS_AUTOGEN}
    ${ABLA_HEADER}

    # Wallet test fixture
    ${BITCOIN_WALLET_TEST_FIXTURE}

    # Properties based test fixture
    ${BITCOIN_PROPERTY_BASED_TEST_FIXTURE}
)
target_link_libraries(test_common PUBLIC server Boost::unit_test_framework ZLIB::ZLIB)

if(ENABLE_PROPERTY_BASED_TESTS)
  target_link_libraries(test_bitcoin Rapidcheck::rapidcheck)
endif()

function(add_boost_test_runners_with_upgrade_activated SUITE EXECUTABLE)
  set(SUITE_UPGRADE_ACTIVATED "${SUITE}-upgrade-activated")
  get_target_from_suite(${SUITE_UPGRADE_ACTIVATED} TARGET_UPGRADE_ACTIVATED)

  if(NOT TARGET ${TARGET_UPGRADE_ACTIVATED})
    create_test_suite_with_parent_targets(
      ${SUITE_UPGRADE_ACTIVATED}
      check-upgrade-activated
      check-upgrade-activated-extended
    )
    add_dependencies(${TARGET_UPGRADE_ACTIVATED} ${EXECUTABLE})
  endif()

  get_target_from_suite(${SUITE} SUITE_TARGET)
  get_target_property(BOOST_TESTS ${SUITE_TARGET} UNIT_TESTS)

  foreach(_test_name ${BOOST_TESTS})
    add_test_runner(
      ${SUITE_UPGRADE_ACTIVATED}
      "${_test_name}"
      ${EXECUTABLE} -t "${_test_name}"
      -- -upgrade2027activationtime=1778846400  # UTC: Fri May 15 2026 12:00:00
    )
  endforeach()
endfunction()

add_boost_test_runners_with_upgrade_activated(bitcoin test_bitcoin)

target_link_libraries(test_bitcoin rpcclient server test_common bench_data)
if(TARGET bitcoinconsensus-shared)
  target_link_libraries(test_bitcoin bitcoinconsensus-shared)
else()
  target_link_libraries(test_bitcoin bitcoinconsensus)
endif()

add_subdirectory(fuzz)
