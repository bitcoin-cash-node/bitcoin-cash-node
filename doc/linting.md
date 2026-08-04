# Linting

Linting is the automated checking of our source code for programmatic and
stylistic errors.

This project has a collection of linters under `test/lint`.

To run all linters, run `ninja check-lint`. To run individual linters, run
`ninja check-lint-<name of linter>`, for example `ninja check-lint-check-doc`.
It's also possible to execute linters directly from the root directory, such as
`./test/lint/check-doc-py`.

## Linter dependencies

If the linter requires external tools to be install, such as for example
`flake8`, the linter will be skipped and return success.

The following external tools are required to run all linters

| Linter        | Tool          | Install command               |
| ------------- | ------------- | ----------------------------- |
| lint-arcanist | arc           | `contrib/arcanist/install.sh` |
| lint-python   | flake8        | `pip3 install flake8`         |
| lint-python   | mypy          | `pip3 install mypy`           |
| lint-yaml     | yamllint      | `apt install yamllint`        |

## Adding a linter

Add a new script in `test/lint`. The working directory for the linters are the
project root directory.

Add your linter to `test/lint/CMakeLists.txt`.
