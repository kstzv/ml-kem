CC ?= gcc

CFLAGS = -std=c11 \
          -Wall \
          -Wextra \
          -Wpedantic \
          -O0 \
          -g \
          -fsanitize=address \
          -I../../userspace

# --------------------------------------------------------------------
# Shared ML-KEM sources
# --------------------------------------------------------------------

LIB_SRC = \
	../../userspace/keccak1600.c \
	../../userspace/math_operations.c \
	../../userspace/ml_kem.c \
	../../userspace/ml_kem_create_keys.c \
	../../userspace/ml_kem_decrypt.c \
	../../userspace/ml_kem_encaps.c \
	../../userspace/ml_kem_ntt_main.c \
	../../userspace/ml_kem_pool.c \
	../../userspace/ml_kem_sha3.c \
	../../userspace/ml_kem_shake.c

LIB_OBJ = $(LIB_SRC:.c=.o)

# --------------------------------------------------------------------
# Test targets
# --------------------------------------------------------------------

TEST_CREATE = test_create_keys
TEST_ENCAPS = test_encaps
TEST_DECAPS = test_decaps

# --------------------------------------------------------------------
# Default target
# --------------------------------------------------------------------

all: $(TEST_CREATE) $(TEST_ENCAPS) $(TEST_DECAPS)

# --------------------------------------------------------------------
# Create object test
# --------------------------------------------------------------------

$(TEST_CREATE): test_ml_kem_create_object.o $(LIB_OBJ)
	$(CC) $(CFLAGS) -o $@ $^

# --------------------------------------------------------------------
# Encaps core test
# --------------------------------------------------------------------

$(TEST_ENCAPS): test_ml_kem_encaps_core.o $(LIB_OBJ)
	$(CC) $(CFLAGS) -o $@ $^

# --------------------------------------------------------------------
# Decaps core test
# --------------------------------------------------------------------

$(TEST_DECAPS): test_ml_kem_decaps_core.o $(LIB_OBJ)
	$(CC) $(CFLAGS) -o $@ $^

# --------------------------------------------------------------------
# Generic object build rule
# --------------------------------------------------------------------

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# --------------------------------------------------------------------
# Run helpers
# --------------------------------------------------------------------

run_create: $(TEST_CREATE)
	./$(TEST_CREATE)

run_encaps: $(TEST_ENCAPS)
	./$(TEST_ENCAPS)

run_decaps: $(TEST_DECAPS)
	./$(TEST_DECAPS)

# --------------------------------------------------------------------
# Valgrind helpers
# --------------------------------------------------------------------

valgrind_create: $(TEST_CREATE)
	valgrind ./$(TEST_CREATE)

valgrind_encaps: $(TEST_ENCAPS)
	valgrind ./$(TEST_ENCAPS)

valgrind_decaps: $(TEST_DECAPS)
	valgrind ./$(TEST_DECAPS)

# --------------------------------------------------------------------
# Cleanup
# --------------------------------------------------------------------

clean:
	rm -f \
	$(LIB_OBJ) \
	test_ml_kem_create_object.o \
	test_ml_kem_encaps_core.o \
	test_ml_kem_decaps_core.o \
	$(TEST_CREATE) \
	$(TEST_ENCAPS) \
	$(TEST_DECAPS)

rebuild: clean all

.PHONY: \
	all \
	run_create \
	run_encaps \
	run_decaps \
	valgrind_create \
	valgrind_encaps \
	valgrind_decaps \
	clean \
	rebuild
