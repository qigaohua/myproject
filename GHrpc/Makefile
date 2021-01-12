CC = gcc

CFLAGS = -Wall -O2 -s

#CFLAGS += -DDEBUG

OBJS = $(patsubst %.c,%.o,$(wildcard *.c ./event/*.c ./hashmap/*.c ./workq/*.c))

DEPS = $(patsubst %.o,%.d,$(OBJS))
CFLAGS += -MD
MISSING_DEPS = $(filter-out $(wildcard $(DEPS)),$(DEPS))
MISSING_DEPS_SOURCES = $(wildcard $(patsubst %.d,%.c,$(MISSING_DEPS)))

LIBS=-lpthread

TARGET1=test_client
TARGET2=test_server

all : $(TARGET)

ifneq ($(MISSING_DEPS),)
$(MISSING_DEPS) :
	@$(RM) $(patsubst %.d,%.o,$@)
endif

-include $(DEPS)

$(TARGET1):$(OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LIBS)

$(TARGET2):$(OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LIBS)

$(OBJS):%.o:%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.d *.s *.o $(TARGET) $(OBJS)

