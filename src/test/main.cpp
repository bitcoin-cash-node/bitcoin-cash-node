// Copyright (c) 2011-2016 The Bitcoin Core developers
// Copyright (c) 2020-2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#define BOOST_TEST_MODULE Bitcoin Cash Node unit tests

#include <util/system.h>

#include <boost/test/unit_test.hpp>

#include <clocale>
#include <iostream>
#include <locale>


namespace utf = boost::unit_test::framework;

/*
 * Global fixture for passing custom arguments, and clearing them all after each
 * test case.
 */
struct CustomArgumentsFixture {
    std::string error;

    CustomArgumentsFixture() {
        const std::string testsuitename = "-testsuitename";
        const std::string force_locale = "-force_locale";

        const std::set<std::string> testArgs = {
            testsuitename,
            "-axionactivationtime",
            "-upgrade2027activationtime",
            force_locale,
        };

        for (const auto &arg : testArgs) {
            gArgs.AddArg(arg, "", ArgsManager::ALLOW_ANY, OptionsCategory::HIDDEN);
        }

        auto &master_test_suite = utf::master_test_suite();
        if (!gArgs.ParseParameters(master_test_suite.argc,
                                   master_test_suite.argv, error)) {
            throw utf::setup_error(error);
        }

        master_test_suite.p_name.value =
            gArgs.GetArg(testsuitename, master_test_suite.p_name.value);

        if (gArgs.IsArgSet(force_locale)) {
            const std::string new_locale = gArgs.GetArg(force_locale, "C");
            std::cout << "Forcing locale to \"" << new_locale << "\"" << std::endl;
            std::setlocale(LC_ALL, new_locale.c_str());
            const std::locale loc(new_locale);
            std::locale::global(loc);
            std::cout.imbue(loc);
            std::cerr.imbue(loc);
        }
    }

    ~CustomArgumentsFixture(){};
};

BOOST_GLOBAL_FIXTURE(CustomArgumentsFixture);
