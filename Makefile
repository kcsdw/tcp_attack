# Compiler
CC = gcc

# Compiler flags
CFLAGS = -Wall -Wextra -O2 -I./lib/include

# Source files (shared library)
LIB_SRC = lib/tcp.c
LIB_OBJ = $(LIB_SRC:.c=.o)

# Executables
TARGETS = syn_attack

# Default target
all: $(TARGETS)

# Rule to build each executable
$(TARGETS): %: %.o $(LIB_OBJ)
	$(CC) $(CFLAGS) -o $@ $^

# Rule to compile object files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean up build files
clean:
	rm -f $(TARGETS) $(LIB_OBJ) *.o