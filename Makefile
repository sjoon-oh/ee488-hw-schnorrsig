CC=g++
CFLAGS=-g -Wall -std=c++17 -O2
SSL_FLAGS=-lssl -lcrypto

TARGET=schnorr.run
OBJS=app.o schnorr.o
HDRS=schnorr.h
SRC=app.cc schnorr.cc

TEST_TARGET=api-test.run
TEST_OBJS=api_test.o schnorr.o
TEST_SRC=api_test.cc schnorr.cc

#
# MAIN
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(SSL_FLAGS)

#
# TESTS
$(TEST_TARGET): $(TEST_OBJS)
	$(CC) $(CFLAGS) -o $@ $(TEST_OBJS) $(SSL_FLAGS)

run: $(TARGET)
	./$(TARGET)

test: $(TEST_TARGET)
run-test: test
	./$(TEST_TARGET)

all: $(TARGET) $(TEST_TARGET)

# CLEAN
clean:
	rm -f *.o *.run
	rm -f *.log
	