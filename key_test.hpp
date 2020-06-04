#ifndef _KEY_TEST_HPP_
#define _KEY_TEST_HPP_

#include <vector>

#include "error_check.hpp"

void load_patterns(const std::string &input);
size_t load_key(const std::vector<uint8_t> &pubkey);

__global__
void gpu_pattern_check(
        uint32_t *retval,
        uint32_t *h0,
        uint32_t *h1,
        uint32_t *h2,
        uint32_t *h3,
        uint32_t *h4);

__global__
void proc_chunk(
        size_t chunk_idx,
        uint32_t keytime,
        uint32_t *h0,
        uint32_t *h1,
        uint32_t *h2,
        uint32_t *h3,
        uint32_t *h4);

#endif
