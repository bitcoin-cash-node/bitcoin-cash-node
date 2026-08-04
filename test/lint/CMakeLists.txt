# Copyright (c) 2020 The Bitcoin developers

project(bitcoin-lint)

include(TestSuite)
create_test_suite(lint)
add_dependencies(check check-lint)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(NativeExecutable)
add_native_executable(unicode_src_linter unicode_src_linter.cpp)
add_dependencies(check-lint unicode_src_linter)
add_test_environment(LINT_BINDIR ${CMAKE_CURRENT_BINARY_DIR})  # e.g.: build/test/lint

add_lint_script_tests_to_suite(lint
TESTS
	check-doc.py
	check-rpc-mappings.py
	lint-arcanist.sh
	lint-assertions.sh
	lint-circular-dependencies.sh
	lint-cpp.sh
	lint-format-strings.sh
	lint-python-format.sh
	lint-python-mutable-default-parameters.sh
	lint-python-utf8-encoding.sh
	lint-python.sh
	lint-tests.sh
	lint-yaml.sh
	lint-shell-locale.sh
	lint-shell-shebang.sh
	lint-includes.sh
	lint-include-guards.sh
	lint-unicode.sh
	lint-include-cheader.py
	lint-source-filename.py
)

add_dependencies(check-lint-lint-unicode unicode_src_linter)
