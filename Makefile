# Variables for easy updates
CC = gcc
CFLAGS = -Wall -Wextra -O2 -Wno-unused-parameter
LDFLAGS = -lsodium
TARGET = main

# Get all .c files and convert their names to .o
SRCS = $(shell find . -name "*.c")
OBJS = $(SRCS:.c=.o)

# The default rule (what happens when you just type 'make')
$(TARGET): $(OBJS)
	$(CC) $(OBJS) $(LDFLAGS) -o $(TARGET)

# Rule for how to turn a .c file into a .o file
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean up the directory
clean:
	rm -f $(OBJS) $(TARGET)