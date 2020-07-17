NVCC = nvcc
NVCCFLAGS += -O3 -std=c++14 --compiler-options -Wall,-Wextra
INC = `pkg-config --cflags libgcrypt`
LIBS = `pkg-config --libs libgcrypt` -lgcrypt -lnvrtc -lcuda

.PHONY: all clean

all: gpg-fingerprint-filter-gpu

key_test_sha1.o: key_test_sha1.cu
	$(NVCC) -c -o $@ $(NVCCFLAGS) $(INC) $^

key_test_pattern.o: key_test_pattern.cpp
	$(NVCC) -c -o $@ $(NVCCFLAGS) $(INC) $^

key_test.o: key_test.cpp
	$(NVCC) -c -o $@ $(NVCCFLAGS) $(INC) $^

gpg_helper.o: gpg_helper.cpp
	$(NVCC) -c -o $@ $(NVCCFLAGS) $(INC) $^

gpg-fingerprint-filter-gpu: main.cpp key_test.o key_test_sha1.o key_test_pattern.o gpg_helper.o
	$(NVCC) -o $@ $(NVCCFLAGS) $(LIBS) $(INC) $^

clean:
	-rm -f *.o gpg-fingerprint-filter-gpu
