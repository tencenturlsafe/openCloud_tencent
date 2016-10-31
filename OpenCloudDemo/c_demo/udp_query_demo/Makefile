EXECUTABLE = udp_query_tool

LIB_PATH=../../lib/

LIBS :=	 protobuf z m crypto ssl pthread
INCS := . ${LIB_PATH}/include64
LIBPATHS := . ${LIB_PATH}/lib64

USER_MARCOS := _POSIX_THREADS _LINUX_OS_ _FILE_OFFSET_BITS=64 USE_MYSQL 
CFLAGS =-m64 -Wall -g -O2 -static --no-strict-aliasing
CC = g++

SOURCE := $(wildcard *.cpp)
OBJS := $(patsubst %.cpp,%.o,$(SOURCE))

SOURCE_CC := $(wildcard *.cc)
OBJS_CC := $(patsubst %.cc,%.o,$(SOURCE_CC))

%.o:%.cpp
	$(CC) $(CFLAGS) $(addprefix -D,$(USER_MARCOS)) $(addprefix -I,$(INCS)) -c $< -o $@

%.o:%.cc
	$(CC) $(CFLAGS) $(addprefix -D,$(USER_MARCOS)) $(addprefix -I,$(INCS)) -c $< -o $@


$(EXECUTABLE): $(OBJS) ${OBJS_CC}
	$(CC) $(CFLAGS) $(addprefix -L,$(LIBPATHS))  -o $(EXECUTABLE) $(OBJS) ${OBJS_CC} $(addprefix -l,$(LIBS))

clean :
	rm -rf *.d *.o *.lo $(EXECUTABLE)
pb :
	protoc *.proto --cpp_out=.
