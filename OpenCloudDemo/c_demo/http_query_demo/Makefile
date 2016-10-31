EXECUTABLE := http_query_tool
JSONPATH := ../../lib/json
AESPATH := ../../lib

LIBS :=	json64 crypto tinyxml2
INCS := . /usr/include ${JSONPATH} ${AESPATH}/include64
LIBPATHS :=  ${JSONPATH}/lib ${AESPATH}/lib64

USER_MARCOS := _POSIX_THREADS _LINUX_OS_ _FILE_OFFSET_BITS=64

CFLAGS = -g -static --no-strict-aliasing  -fPIC
CC = g++


SOURCE := $(wildcard *.cpp)
OBJS := $(patsubst %.cpp,%.o,$(SOURCE))

%.o:%.cpp
	$(CC) $(CFLAGS) $(addprefix -D,$(USER_MARCOS)) $(addprefix -I,$(INCS)) -c $< -o $@

$(EXECUTABLE): $(OBJS)
	$(CC) $(CFLAGS) $(addprefix -L,$(LIBPATHS))  -o $(EXECUTABLE) $(OBJS) $(addprefix -l,$(LIBS))
clean :
	rm -rf *.d *.o *.lo $(EXECUTABLE)
# DO NOT DELETE
