NVCC = nvcc
NVCCFLAGS += -O2 -std=c++14
INC = `gpgme-config --cflags`
LIBS = `gpgme-config --libs` -lstdc++fs

.PHONY: all clean

all: gpg-fingerprint-filter-gpu

gpgme_helper.o: gpgme_helper.cpp gpgme_helper.hpp
	$(NVCC) -c -o $@ $(NVCCFLAGS) $(INC) $<

key_test_sha1.o: key_test_sha1.cu key_test.hpp
	$(NVCC) -c -o $@ $(NVCCFLAGS) $(INC) $<

key_test_pattern.o: key_test_pattern.cu key_test.hpp
	$(NVCC) -c -o $@ $(NVCCFLAGS) $(INC) $<

main.o: main.cu
	$(NVCC) -c -o $@ $(NVCCFLAGS) $(INC) $<

gpg-fingerprint-filter-gpu: main.o key_test_sha1.o key_test_pattern.o gpgme_helper.o
	$(NVCC) -o $@ $(NVCCFLAGS) $(LIBS) $(INC) $^

clean:
	-rm *.o gpg-fingerprint-filter-gpu
