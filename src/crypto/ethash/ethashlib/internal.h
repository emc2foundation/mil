#pragma once
#include "crypto/ethash/ethashlib/endian.h"
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

// compile time settings
#define NODE_WORDS (64/4)
#define MIX_WORDS (ETHASH_MIX_BYTES/4)
#define MIX_NODES (MIX_WORDS / NODE_WORDS)

typedef union node {
	uint8_t bytes[NODE_WORDS * 4];
	uint32_t words[NODE_WORDS];
	uint64_t double_words[NODE_WORDS / 2];

#if defined(_M_X64) && ENABLE_SSE
	__m128i xmm[NODE_WORDS/4];
#elif defined(__MIC__)
	__m512i zmm[NODE_WORDS/16];
#endif

} node;

static inline void ethash_h256_reset(ethash_h256_t* hash)
{
	memset(hash, 0, 32);
}

struct ethash_light {
	void* cache;
	uint64_t cache_size;
	uint64_t block_number;
};

/**
 * Allocate and initialize a new ethash_light handler. Internal version
 *
 * @param cache_size    The size of the cache in bytes
 * @param seed          Block seedhash to be used during the computation of the
 *                      cache nodes
 * @return              Newly allocated ethash_light handler or NULL in case of
 *                      ERRNOMEM or invalid parameters used for @ref ethash_compute_cache_nodes()
 */
ethash_light_t ethash_light_new_internal(uint64_t cache_size, ethash_h256_t const* seed);

struct ethash_full {
	FILE* file;
	uint64_t file_size;
	node* data;
};

/**
 * Allocate and initialize a new ethash_full handler. Internal version.
 *
 * @param dirname        The directory in which to put the DAG file.
 * @param seedhash       The seed hash of the block. Used in the DAG file naming.
 * @param full_size      The size of the full data in bytes.
 * @param cache          A cache object to use that was allocated with @ref ethash_cache_new().
 *                       Iff this function succeeds the ethash_full_t will take memory
 *                       memory ownership of the cache and free it at deletion. If
 *                       not then the user still has to handle freeing of the cache himself.
 * @param callback       A callback function with signature of @ref ethash_callback_t
 *                       It accepts an unsigned with which a progress of DAG calculation
 *                       can be displayed. If all goes well the callback should return 0.
 *                       If a non-zero value is returned then DAG generation will stop.
 * @return               Newly allocated ethash_full handler or NULL in case of
 *                       ERRNOMEM or invalid parameters used for @ref ethash_compute_full_data()
 */
ethash_full_t ethash_full_new_internal(
	char const* dirname,
	ethash_h256_t const seed_hash,
	uint64_t full_size,
	ethash_light_t const light,
	ethash_callback_t callback
);

void ethash_calculate_dag_item(
	node* const ret,
	uint32_t node_index,
	ethash_light_t const cache
);

uint64_t ethash_get_datasize(uint64_t const block_number);
uint64_t ethash_get_cachesize(uint64_t const block_number);

/**
 * Compute the memory data for a full node's memory
 *
 * @param mem         A pointer to an ethash full's memory
 * @param full_size   The size of the full data in bytes
 * @param cache       A cache object to use in the calculation
 * @param callback    The callback function. Check @ref ethash_full_new() for details.
 * @return            true if all went fine and false for invalid parameters
 */
bool ethash_compute_full_data(
	void* mem,
	uint64_t full_size,
	ethash_light_t const light,
	ethash_callback_t callback
);

#ifdef __cplusplus
}
#endif