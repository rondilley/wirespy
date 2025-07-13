AUTOMAKE_OPTIONS = 1.9 gnu no-dependencies
SUBDIRS = src
man_MANS = wsd.1

# Static analysis targets
.PHONY: static-analysis clang-analyzer cppcheck

static-analysis:
	@echo "Running static analysis with GCC analyzer..."
	$(MAKE) clean
	./configure --enable-static-analysis
	$(MAKE)

clang-analyzer:
	@echo "Running Clang static analyzer..."
	@if ! command -v scan-build >/dev/null 2>&1; then \
		echo "Error: scan-build not found. Install clang-tools package."; \
		exit 1; \
	fi
	$(MAKE) clean
	./configure CC=clang
	scan-build -o analysis-results --status-bugs $(MAKE)
	@echo "Results in analysis-results/ directory"

cppcheck:
	@echo "Running cppcheck static analysis..."
	@if ! command -v cppcheck >/dev/null 2>&1; then \
		echo "Error: cppcheck not found. Install cppcheck package."; \
		exit 1; \
	fi
	cppcheck --enable=all --std=c11 --platform=unix64 \
		--suppress=missingIncludeSystem \
		--suppress=unusedFunction \
		--error-exitcode=1 \
		--inline-suppr \
		--template=gcc \
		-I include/ -I src/ \
		src/

sanitizer-test:
	@echo "Building with sanitizers for testing..."
	$(MAKE) clean
	./configure --enable-sanitizers --enable-debug
	$(MAKE)
	@echo "Run './src/wsd --help' to test with sanitizers"

analysis-clean:
	@echo "Cleaning analysis artifacts..."
	rm -rf analysis-results/
	$(MAKE) clean 
