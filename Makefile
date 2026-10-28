ifeq ($(origin CC),default)
CC = gcc
endif
CC ?= gcc
AR ?= ar
PARAM ?= 160f
IMPL ?= ref
BMI2 ?= 1
PROFILE ?= 0
NGCC_CFLAGS ?=
VALGRIND ?= valgrind
VALGRIND_CPPFLAGS ?=
BUILD_DIR ?= ../sydo-build/$(PARAM)-$(IMPL)

ifneq ($(filter $(PARAM),160f 160s 256f 256s 512f 512s),$(PARAM))
$(error PARAM must be 160f, 160s, 256f, 256s, 512f or 512s)
endif
ifneq ($(filter $(IMPL),ref avx2),$(IMPL))
$(error IMPL must be ref or avx2)
endif

ifneq ($(filter $(BMI2),0 1),$(BMI2))
$(error BMI2 must be 0 or 1)
endif

CPPFLAGS += -Iinclude -Isrc -Iapi/ngcc/$(PARAM) -Ithird_party/ngcc
ifeq ($(PROFILE),1)
CPPFLAGS += -DSYDO_PROFILE
endif
SECURITY_BITS = $(patsubst %s,%,$(patsubst %f,%,$(PARAM)))
CPPFLAGS += -DSYDO_LAMBDA=$(SECURITY_BITS)
ifneq ($(filter %s,$(PARAM)),)
CPPFLAGS += -DSYDO_SHORT
endif
CFLAGS ?= -O3 -flto
override CFLAGS += -std=c11 -Wall -Wextra -Wpedantic -Werror=implicit-function-declaration

ifeq ($(SECURITY_BITS),512)
CIPHER_SOURCES = src/$(IMPL)/blake2s.c src/blake2s_keys.c src/blake2s_matrix.c
else
CIPHER_SOURCES = src/$(IMPL)/cipher.c src/$(IMPL)/matrix.c
endif

SOURCES = src/profile.c src/hash.c src/keygen.c src/prg.c src/bavc.c src/vole.c src/rsd.c src/sign.c src/verify.c src/fields.c $(CIPHER_SOURCES) api/ngcc/SIG_AlgorithmInstance.c third_party/ngcc/auxfunc.c third_party/ngcc/drng.c
ifeq ($(IMPL),avx2)
CPPFLAGS += -DSYDO_AVX2
DRIVER_CFLAGS = -mavx2 -maes -mpclmul -mssse3
ifeq ($(BMI2),1)
DRIVER_CFLAGS += -mbmi2
endif
NGCC_OPT_CFLAGS = $(DRIVER_CFLAGS) -funroll-loops -fno-tree-vectorize
$(BUILD_DIR)/third_party/ngcc/%.o $(BUILD_DIR)/allocation/third_party/ngcc/%.o: EXTRA_CFLAGS += $(NGCC_OPT_CFLAGS)
$(BUILD_DIR)/src/%.o: EXTRA_CFLAGS += $(DRIVER_CFLAGS)
else
SOURCES += src/ref/fields.c
endif

OBJECTS = $(SOURCES:%.c=$(BUILD_DIR)/%.o)
ALLOCATION_OBJECTS = $(SOURCES:%.c=$(BUILD_DIR)/allocation/%.o)

.PHONY: all clean tests check check-ct ngcc-calls benchmark components memory kat
all: $(BUILD_DIR)/libsydo.a
tests: $(BUILD_DIR)/test-ngcc $(BUILD_DIR)/test-hash $(BUILD_DIR)/test-primitives $(BUILD_DIR)/test-cipher $(BUILD_DIR)/test-validation $(BUILD_DIR)/test-keygen $(BUILD_DIR)/test-components $(BUILD_DIR)/test-transcript $(BUILD_DIR)/test-allocation $(BUILD_DIR)/test-secret-key $(BUILD_DIR)/test-security
ngcc-calls: $(BUILD_DIR)/test-ngcc-calls
benchmark: $(BUILD_DIR)/bench
components: $(BUILD_DIR)/bench-components
memory: $(BUILD_DIR)/bench-memory $(BUILD_DIR)/test-memory-tracker
kat: $(BUILD_DIR)/kat_sig

check: tests ngcc-calls
	sh tests/check_ngcc.sh
	@set -e; for name in primitives cipher hash ngcc validation allocation secret-key security ngcc-calls; do "$(BUILD_DIR)/test-$$name"; done

check-ct: $(BUILD_DIR)/test-constant-time
	$(VALGRIND) --tool=memcheck --error-exitcode=99 --track-origins=yes "$(BUILD_DIR)/test-constant-time"

$(BUILD_DIR)/libsydo.a: $(OBJECTS)
	rm -f $@
	$(AR) rcs $@ $^

$(BUILD_DIR)/%.o: %.c Makefile
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(EXTRA_CFLAGS) -MMD -MP -c $< -o $@

$(BUILD_DIR)/allocation/src/%.o: EXTRA_CFLAGS += $(DRIVER_CFLAGS) -Dmalloc=sydo_test_malloc -Dcalloc=sydo_test_calloc -Daligned_alloc=sydo_test_aligned_alloc -Dfree=sydo_test_free
$(BUILD_DIR)/allocation/third_party/ngcc/auxfunc.o $(BUILD_DIR)/allocation/third_party/ngcc/drng.o: EXTRA_CFLAGS += $(NGCC_CFLAGS)

$(BUILD_DIR)/allocation/%.o: %.c Makefile
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(EXTRA_CFLAGS) -MMD -MP -c $< -o $@

$(BUILD_DIR)/libsydo_allocation.a: $(ALLOCATION_OBJECTS)
	rm -f $@
	$(AR) rcs $@ $^

$(BUILD_DIR)/test-allocation: tests/allocation.c $(BUILD_DIR)/libsydo_allocation.a
	$(CC) $(CPPFLAGS) $(CFLAGS) $(DRIVER_CFLAGS) $< $(BUILD_DIR)/libsydo_allocation.a $(LDFLAGS) -o $@

$(BUILD_DIR)/third_party/ngcc/auxfunc.o $(BUILD_DIR)/third_party/ngcc/drng.o: EXTRA_CFLAGS += $(NGCC_CFLAGS)

$(BUILD_DIR)/test-ngcc: tests/ngcc.c $(BUILD_DIR)/libsydo.a
	$(CC) $(CPPFLAGS) $(CFLAGS) $(DRIVER_CFLAGS) $< $(BUILD_DIR)/libsydo.a $(LDFLAGS) -o $@

$(BUILD_DIR)/test-hash: tests/hash.c $(BUILD_DIR)/libsydo.a
	$(CC) $(CPPFLAGS) $(CFLAGS) $(DRIVER_CFLAGS) $< $(BUILD_DIR)/libsydo.a $(LDFLAGS) -o $@

$(BUILD_DIR)/test-primitives: tests/primitives.c $(BUILD_DIR)/libsydo.a
	$(CC) $(CPPFLAGS) $(CFLAGS) $(DRIVER_CFLAGS) $< $(BUILD_DIR)/libsydo.a $(LDFLAGS) -o $@

$(BUILD_DIR)/test-cipher: tests/cipher.c $(BUILD_DIR)/libsydo.a
	$(CC) $(CPPFLAGS) $(CFLAGS) $(DRIVER_CFLAGS) $< $(BUILD_DIR)/libsydo.a $(LDFLAGS) -o $@

$(BUILD_DIR)/test-validation: tests/validation.c $(BUILD_DIR)/libsydo.a
	$(CC) $(CPPFLAGS) $(CFLAGS) $(DRIVER_CFLAGS) $< $(BUILD_DIR)/libsydo.a $(LDFLAGS) -o $@

$(BUILD_DIR)/test-keygen: tests/keygen.c $(BUILD_DIR)/libsydo.a
	$(CC) $(CPPFLAGS) $(CFLAGS) $(DRIVER_CFLAGS) $< $(BUILD_DIR)/libsydo.a $(LDFLAGS) -o $@

$(BUILD_DIR)/test-secret-key: tests/secret_key.c $(BUILD_DIR)/libsydo.a
	$(CC) $(CPPFLAGS) $(CFLAGS) $(DRIVER_CFLAGS) $< $(BUILD_DIR)/libsydo.a $(LDFLAGS) -o $@

$(BUILD_DIR)/test-constant-time: tests/constant_time.c $(BUILD_DIR)/libsydo.a
	$(CC) $(CPPFLAGS) $(VALGRIND_CPPFLAGS) $(CFLAGS) $(DRIVER_CFLAGS) $< $(BUILD_DIR)/libsydo.a $(LDFLAGS) -o $@

$(BUILD_DIR)/test-security: tests/security.c $(BUILD_DIR)/libsydo.a
	$(CC) $(CPPFLAGS) $(CFLAGS) $(DRIVER_CFLAGS) $< $(BUILD_DIR)/libsydo.a $(LDFLAGS) -o $@

$(BUILD_DIR)/test-components: tests/components.c $(BUILD_DIR)/libsydo.a
	$(CC) $(CPPFLAGS) $(CFLAGS) $(DRIVER_CFLAGS) $< $(BUILD_DIR)/libsydo.a $(LDFLAGS) -o $@

$(BUILD_DIR)/test-transcript: tests/transcript.c $(BUILD_DIR)/libsydo.a
	$(CC) $(CPPFLAGS) $(CFLAGS) $(DRIVER_CFLAGS) $< $(BUILD_DIR)/libsydo.a $(LDFLAGS) -o $@

$(BUILD_DIR)/bench: benchmark/bench.c $(BUILD_DIR)/libsydo.a
	$(CC) $(CPPFLAGS) $(CFLAGS) $(DRIVER_CFLAGS) $< $(BUILD_DIR)/libsydo.a $(LDFLAGS) -o $@

$(BUILD_DIR)/bench-components: benchmark/components.c benchmark/component_ops.c benchmark/component_api.h $(BUILD_DIR)/libsydo.a
	$(CC) $(CPPFLAGS) $(CFLAGS) $(DRIVER_CFLAGS) benchmark/components.c benchmark/component_ops.c $(BUILD_DIR)/libsydo.a $(LDFLAGS) -o $@

$(BUILD_DIR)/libsydo_memory.so: benchmark/memory_alloc.c benchmark/memory_alloc.h Makefile
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -fPIC -shared benchmark/memory_alloc.c -o $@

$(BUILD_DIR)/bench-memory: benchmark/memory.c benchmark/memory_alloc.h $(BUILD_DIR)/libsydo.a $(BUILD_DIR)/libsydo_memory.so
	$(CC) $(CPPFLAGS) $(CFLAGS) $(DRIVER_CFLAGS) benchmark/memory.c $(BUILD_DIR)/libsydo.a -L$(BUILD_DIR) -lsydo_memory -Wl,-rpath,'$$ORIGIN' $(LDFLAGS) -o $@

$(BUILD_DIR)/test-memory-tracker: tests/memory_tracker.c benchmark/memory_alloc.h $(BUILD_DIR)/libsydo_memory.so
	$(CC) $(CFLAGS) -Ibenchmark $< -L$(BUILD_DIR) -lsydo_memory -Wl,-rpath,'$$ORIGIN' -o $@

$(BUILD_DIR)/kat_sig: third_party/ngcc/KAT_SIG.c $(BUILD_DIR)/libsydo.a
	$(CC) $(CPPFLAGS) $(CFLAGS) $(DRIVER_CFLAGS) $< $(BUILD_DIR)/libsydo.a $(LDFLAGS) -o $@

$(BUILD_DIR)/ngcc-calls/auxfunc.o: third_party/ngcc/auxfunc.c Makefile
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(filter-out -flto%,$(CFLAGS)) $(NGCC_OPT_CFLAGS) $(NGCC_CFLAGS) -c $< -o $@

$(BUILD_DIR)/ngcc-calls/drng.o: third_party/ngcc/drng.c Makefile
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(filter-out -flto%,$(CFLAGS)) $(NGCC_OPT_CFLAGS) $(NGCC_CFLAGS) -c $< -o $@

$(BUILD_DIR)/test-ngcc-calls: tests/ngcc_calls.c $(BUILD_DIR)/libsydo.a $(BUILD_DIR)/ngcc-calls/auxfunc.o $(BUILD_DIR)/ngcc-calls/drng.o
	$(CC) $(CPPFLAGS) $(CFLAGS) $(DRIVER_CFLAGS) $< $(BUILD_DIR)/ngcc-calls/auxfunc.o $(BUILD_DIR)/ngcc-calls/drng.o $(BUILD_DIR)/libsydo.a $(LDFLAGS) -Wl,--wrap=pseudoXOF -Wl,--wrap=get_random_number -o $@

clean:
	rm -f $(BUILD_DIR)/test-constant-time
	rm -f $(BUILD_DIR)/test-secret-key $(BUILD_DIR)/test-security
	rm -f $(BUILD_DIR)/test-ngcc-calls $(BUILD_DIR)/ngcc-calls/auxfunc.o $(BUILD_DIR)/ngcc-calls/drng.o
	rm -f $(OBJECTS) $(OBJECTS:.o=.d) $(BUILD_DIR)/libsydo.a $(BUILD_DIR)/test-ngcc $(BUILD_DIR)/test-hash $(BUILD_DIR)/test-primitives $(BUILD_DIR)/test-cipher $(BUILD_DIR)/test-validation $(BUILD_DIR)/test-memory-tracker $(BUILD_DIR)/test-keygen $(BUILD_DIR)/test-components $(BUILD_DIR)/test-transcript $(BUILD_DIR)/bench $(BUILD_DIR)/bench-components $(BUILD_DIR)/bench-memory $(BUILD_DIR)/libsydo_memory.so $(BUILD_DIR)/kat_sig
	rm -f $(ALLOCATION_OBJECTS) $(ALLOCATION_OBJECTS:.o=.d) $(BUILD_DIR)/libsydo_allocation.a $(BUILD_DIR)/test-allocation

-include $(OBJECTS:.o=.d)
-include $(ALLOCATION_OBJECTS:.o=.d)
