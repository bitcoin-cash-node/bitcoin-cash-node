# Copyright (c) 2018-2024 The Bitcoin developers

project(test_bitcoin-qt)

include(TestSuite)
create_test_suite(bitcoin-qt)
add_dependencies(check check-bitcoin-qt)

add_test_to_suite(bitcoin-qt test_bitcoin-qt
	apptests.cpp
	bitcoinaddressvalidatortests.cpp
	compattests.cpp
	guiutiltests.cpp
	rpcnestedtests.cpp
	test_main.cpp
	uritests.cpp
	util.cpp

	# Test framework
	../../test/setup_common.cpp
)

target_link_libraries(test_bitcoin-qt bitcoin-qt-base Qt5::Test)

# Wallet
if(BUILD_BITCOIN_WALLET)
	# Add wallet functionality to test_bitcoin-qt
	target_sources(test_bitcoin-qt
		PRIVATE
			addressbooktests.cpp
			wallettests.cpp
			../../wallet/test/wallet_test_fixture.cpp
	)

	target_link_libraries(test_bitcoin-qt wallet)
endif()
