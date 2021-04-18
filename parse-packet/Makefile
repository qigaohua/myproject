CC = gcc

# CFLAGS =-g -rdynamic -Wall -O2 -s -std=gnu99
CFLAGS =-g -Wall  -std=gnu99

#CFLAGS += -DDEBUG

OBJS = $(patsubst %.c,%.o,$(wildcard *.c ./packet/*.c))

DEPS = $(patsubst %.o,%.d,$(OBJS))
CFLAGS += -MD
MISSING_DEPS = $(filter-out $(wildcard $(DEPS)),$(DEPS))
MISSING_DEPS_SOURCES = $(wildcard $(patsubst %.d,%.c,$(MISSING_DEPS)))

# LIBS=-lpthread -L/usr/lib64/mysql -lmysqlclient
LIBS=-lpcap -lpthread

TARGET=parse-pkt

all : $(TARGET)

ifneq ($(MISSING_DEPS),)
$(MISSING_DEPS) :
	@$(RM) $(patsubst %.d,%.o,$@)
endif

-include $(DEPS)

$(TARGET):$(OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LIBS)

$(OBJS):%.o:%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.d *.s *.o  $(TARGET)

