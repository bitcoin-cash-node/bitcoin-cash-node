# Copyright (c) 2018-2026 The Bitcoin developers

project(bench_bitcoin)

add_custom_command(
  OUTPUT
    ${CMAKE_CURRENT_BINARY_DIR}/data/block413567.cpp
    ${CMAKE_CURRENT_BINARY_DIR}/data/block556034.cpp
    ${CMAKE_CURRENT_BINARY_DIR}/data/block877227.cpp
    ${CMAKE_CURRENT_BINARY_DIR}/data/coins_spent_413567.cpp
    ${CMAKE_CURRENT_BINARY_DIR}/data/coins_spent_556034.cpp
    ${CMAKE_CURRENT_BINARY_DIR}/data/recv_messages.cpp
  COMMAND
    ${CMAKE_CURRENT_SOURCE_DIR}/data/convert-raw-files.py ${CMAKE_CURRENT_SOURCE_DIR}/data ${CMAKE_CURRENT_BINARY_DIR}/data
  DEPENDS
    ${CMAKE_CURRENT_SOURCE_DIR}/data/block413567.raw.bz2
    ${CMAKE_CURRENT_SOURCE_DIR}/data/block556034.raw.bz2
    ${CMAKE_CURRENT_SOURCE_DIR}/data/block877227.raw.bz2
    ${CMAKE_CURRENT_SOURCE_DIR}/data/coins_spent_413567.raw.bz2
    ${CMAKE_CURRENT_SOURCE_DIR}/data/coins_spent_556034.raw.bz2
    ${CMAKE_CURRENT_SOURCE_DIR}/data/recv_messages.raw.bz2
    ${CMAKE_CURRENT_SOURCE_DIR}/data/convert-raw-files.py
)

add_library(bench_data OBJECT EXCLUDE_FROM_ALL
    ${CMAKE_CURRENT_BINARY_DIR}/data/block413567.cpp
    ${CMAKE_CURRENT_BINARY_DIR}/data/block556034.cpp
    ${CMAKE_CURRENT_BINARY_DIR}/data/block877227.cpp
    ${CMAKE_CURRENT_BINARY_DIR}/data/coins_spent_413567.cpp
    ${CMAKE_CURRENT_BINARY_DIR}/data/coins_spent_556034.cpp
    ${CMAKE_CURRENT_BINARY_DIR}/data/recv_messages.cpp
)

target_link_libraries(bench_data PUBLIC util)

add_executable(bench_bitcoin
	EXCLUDE_FROM_ALL
	banman.cpp
	addrman.cpp
	base58.cpp
	bench.cpp
	bench_bitcoin.cpp
	block_assemble.cpp
	blockdata.cpp
	cashaddr.cpp
	ccoins_caching.cpp
	chained_tx.cpp
	checkblock.cpp
	checkqueue.cpp
	crypto_aes.cpp
	crypto_hash.cpp
	disconnectpool.cpp
	dsproof.cpp
	duplicate_inputs.cpp
	examples.cpp
	find_tx.cpp
	gcs_filter.cpp
	json.cpp
	json_util.cpp
	libauth_bench.cpp
	lockedpool.cpp
	mediantimepast.cpp
	mempool_eviction.cpp
	merkle_root.cpp
	net_messages.cpp
	prevector.cpp
	readwriteblock.cpp
	removeforblock.cpp
	rollingbloom.cpp
	rpc_blockchain.cpp
	rpc_mempool.cpp
	script.cpp
	util_string.cpp
	util_time.cpp
	verify_script.cpp
)

target_link_libraries(bench_bitcoin common bitcoinconsensus server test_common bench_data)

if(BUILD_BITCOIN_WALLET)
	target_sources(bench_bitcoin PRIVATE coin_selection.cpp keypool.cpp)
	target_link_libraries(bench_bitcoin wallet)
endif()

add_custom_target(bench-bitcoin COMMAND bench_bitcoin USES_TERMINAL)
add_custom_target(bitcoin-bench DEPENDS bench_bitcoin)
