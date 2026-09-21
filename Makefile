PYTHON ?= python3
SECUREBOOT := ./secureboot.py
TOOLS_DIR := tools/UEFIRomExtract
BUILD_DIR := $(TOOLS_DIR)/build

.DEFAULT_GOAL := help
.PHONY: help build-tools generate-keys extract-devices sign-variables test clean

help:
	@echo "SecureBoot Management Makefile"
	@echo ""
	@echo "Usage: make <target> [ARGS=\"...\"]"
	@echo ""
	@echo "Targets:"
	@echo "  build-tools      Build UEFIRomExtract helper binary using CMake"
	@echo "  generate-keys    Generate custom PK, KEK, and db keys/certificates"
	@echo "  extract-devices  Extract GOP firmware & hashes from TPM2 eventlog"
	@echo "  sign-variables   Merge db.esl and sign authenticated .auth variable updates"
	@echo "  test             Run pytest test suite using mock fixtures"
	@echo "  clean            Clean tools build directory and generated signed_config"

build-tools:
	cmake -B $(BUILD_DIR) $(TOOLS_DIR)
	cmake --build $(BUILD_DIR)

generate-keys:
	$(PYTHON) $(SECUREBOOT) generate-keys $(ARGS)

extract-devices: build-tools
	$(PYTHON) $(SECUREBOOT) extract-devices $(ARGS)

sign-variables:
	$(PYTHON) $(SECUREBOOT) sign-variables $(ARGS)

test:
	$(PYTHON) -m pytest -v

clean:
	rm -rf $(BUILD_DIR)
	rm -rf signed_config