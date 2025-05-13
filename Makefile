# --- SETTINGS -------------------------------------------------------------

# Set this to the directory, where your code is. If you have multiple
# directories, you want to check, use a space separated list instead.
SOURCE = .

# Set this to the string used for the `--source` argument to coverage.
COVARAGE_SOURCES = .

# Should the Django test runner be used instead of unittest discovery? If
# so, set this to `1` instead of `0`. This is needed to run the tests for
# Django projects.
DJANGO = 0

# --- COMMANDS -------------------------------------------------------------

# The commands that are run by the targets… feel free to change (them).

PWD = $(shell pwd)

CFG = $(PWD)/setup.cfg

EXCLUDES = \( \
		-path './.git/*' -o \
		-path './.venv/*' -o \
		-path './venv/*' -o \
		-path './env/*' -o \
		-path './.tox/*' -o \
		-path '.*/node_modules/*' -o \
		-path '.*/bower_components/*' \
\) -prune -o

# Isort
CMD_ISORT = isort --settings-path $(CFG) --apply
CMD_ISORT_CHECK = isort --settings-path $(CFG) --check-only --quiet

# Linters
CMD_PYLAMA_ISORT_CHECK = pylama --options $(CFG) -l isort
CMD_PYLAMA_SYNTAX_CHECK = pylama --options $(CFG) -l pyflakes
CMD_PYLAMA_STYLE_CHECK_CODE = pylama --options $(CFG) -l pycodestyle
CMD_PYLAMA_STYLE_CHECK_DOCS = pylama --options $(CFG) -l pydocstyle
CMD_PYLAMA_COMPLEXITY_CHECK = pylama --options $(CFG) -l mccabe
CMD_PYLAMA_PYLINT_CHECK = pylama --options $(CFG) -l pylint
CMD_PYLINT_CHECK = find . $(EXCLUDES) -name '*.py' -print0 | xargs -0 \
pylint --rcfile $(PWD)/.pylintrc
CMD_PYLINT_REPORT = $(CMD_PYLINT_CHECK) -ry


# Test Runners
CMD_DOCTEST = find $(dir) $(EXCLUDES) -name '*.py' -print0 | xargs -0 \
python3 -m doctest

ifeq ($(DJANGO), 1)
CMD_COVERAGE_TEST = -m django test
CMD_TEST = python3 $(CMD_COVERAGE_TEST)
else
CMD_COVERAGE_TEST = -m unittest discover $(SOURCE)/tests/
CMD_TEST = python3 $(CMD_COVERAGE_TEST)
endif

CMD_COVERAGE_RUN = coverage run --append --source $(COVARAGE_SOURCES) $(CMD_COVERAGE_TEST)

# --- TARGETS --------------------------------------------------------------

.PHONY: default style_check style tests check lint full isort isort_check syntax_check style_check_code style_check_docs code_check pylama pylint doctests unittests cover build upload clean outdated update

default: style

style_check: style_check_code style_check_docs

style: syntax_check isort_check style_check

tests: doctests unittests

check: style tests

lint: complexity_check pylama

full: check lint

build: mk_build clean

isort:
	# Sort imports in all `*.py` files.
	$(foreach dir,$(SOURCE),cd $(dir); $(CMD_ISORT))

isort_check:
	# Checks for correctly sorted imports in all `*.py` files.
	$(foreach dir,$(SOURCE),cd $(dir); $(CMD_PYLAMA_ISORT_CHECK))

syntax_check:
	# Checks source files for syntax errors.
	$(foreach dir,$(SOURCE),cd $(dir); $(CMD_PYLAMA_SYNTAX_CHECK))

style_check_code:
	# Checks source files for common code style conventions.
	$(foreach dir,$(SOURCE),cd $(dir); $(CMD_PYLAMA_STYLE_CHECK_CODE))

style_check_docs:
	# Checks source files for common documentation style conventions.
	$(foreach dir,$(SOURCE),cd $(dir); $(CMD_PYLAMA_STYLE_CHECK_DOCS))

complexity_check:
	# Checks source files for too much complexity.
	$(foreach dir,$(SOURCE),cd $(dir); $(CMD_PYLAMA_COMPLEXITY_CHECK))

pylama:
	# Checks the source files for opinionated code smells.
	$(foreach dir,$(SOURCE),cd $(dir); $(CMD_PYLAMA_PYLINT_CHECK))

pylint:
	# Prints a report of _very_ opinionated code smells in the source files.
	$(foreach dir,$(SOURCE),cd $(dir); $(CMD_PYLINT_REPORT))

doctests:
	# Runs doctest found in the source files.
	$(foreach dir,$(SOURCE),$(CMD_DOCTEST))

unittests:
	# Runs all unittests that follow common naming schemes.
	$(CMD_TEST)

cover:
	# Runs all those unittests with coverage and prints a report.
	$(CMD_COVERAGE_RUN)
	coverage report -m

outdated:
	# Lists outdated packages.
	$(CMD_PIP_OUTDATED)

update:
	# Updates outdated packages.
	$(CMD_PIP_UPDATE)