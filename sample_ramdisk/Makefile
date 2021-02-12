PROJECT_ROOT = $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

OBJS = dblock_sample_ramdisk.o

	CFLAGS += -O2

all:	dblock_sample_ramdisk

dblock_sample_ramdisk:	$(OBJS)
	$(CXX) -o $@ $^

%.o:	$(PROJECT_ROOT)%.cpp
	$(CXX) -c $(CFLAGS) $(CXXFLAGS) $(CPPFLAGS) -o $@ $<


clean:
	rm -fr dblock_sample_ramdisk $(OBJS)
