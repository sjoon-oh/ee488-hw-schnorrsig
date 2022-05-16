CC=g++
CFLAGS=-g -Wall -std=c++17
SSL_FLAGS=-lssl -lcrypto

TARGET=schnorr-exec
OBJS=app.o schnorr.o
HDRS=schnorr.h
SRC=app.cc schnorr.cc

TEST_TARGET=api-test-exec
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

# test: $(TEST_OBJS)
# 	$(CC) -o $(TEST_TARGET) $(TEST_OBJS) $(SSL_FLAGS)

# CLEAN
clean:
	rm -f *o $(TARGET) $(TEST_TARGET)
	rm -f *.log