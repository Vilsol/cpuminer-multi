#include <memory.h>

#include "sha3/sph_blake.h"
#include "sha3/sph_groestl.h"
#include "sha3/sph_skein.h"
#include "sha3/sph_keccak.h"
#include "sha3/sph_luffa.h"

#include "lyra2/Lyra2.h"

#include "miner.h"

void allium_hash(void *state, const void *input)
{
    sph_blake512_context     ctx_blake;
    sph_keccak512_context    ctx_keccak;
    sph_skein512_context     ctx_skein;
    sph_groestl512_context   ctx_groestl;
    sph_luffa512_context     ctx_luffa;

    uint32_t hashA[8], hashB[8];

    sph_blake512_init(&ctx_blake);
    sph_blake512(&ctx_blake, input, 80);
    sph_blake512_close(&ctx_blake, hashA);

    sph_keccak512_init(&ctx_keccak);
    sph_keccak512(&ctx_keccak, hashA, 32);
    sph_keccak512_close(&ctx_keccak, hashB);

    LYRA2(hashA, 32, hashB, 32, hashB, 32, 1, 8, 8);

    sph_skein512_init(&ctx_skein);
    sph_skein512(&ctx_skein, hashA, 32);
    sph_skein512_close(&ctx_skein, hashB);

    LYRA2(hashA, 32, hashB, 32, hashB, 32, 1, 8, 8);

    sph_keccak512_init(&ctx_keccak);
    sph_keccak512(&ctx_keccak, hashA, 32);
    sph_keccak512_close(&ctx_keccak, hashB);

    LYRA2(hashA, 32, hashB, 32, hashB, 32, 1, 8, 8);

    sph_luffa512_init(&ctx_luffa);
    sph_luffa512(&ctx_luffa, hashA, 32);
    sph_luffa512_close(&ctx_luffa, hashB);

    LYRA2(hashA, 32, hashB, 32, hashB, 32, 1, 8, 8);

    sph_groestl512_init(&ctx_groestl);
    sph_groestl512(&ctx_groestl, hashA, 32);
    sph_groestl512_close(&ctx_groestl, hashB);

    memcpy(state, hashB, 32);
}

int scanhash_allium(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
{
    uint32_t _ALIGN(128) hash[8];
    uint32_t _ALIGN(128) endiandata[20];
    uint32_t *pdata = work->data;
    uint32_t *ptarget = work->target;

    const uint32_t Htarg = ptarget[7];
    const uint32_t first_nonce = pdata[19];
    uint32_t nonce = first_nonce;

    if (opt_benchmark) {
        ptarget[7] = 0x006fff;
    }

    for (int i=0; i < 19; i++) {
        be32enc(&endiandata[i], pdata[i]);
    }

    do {
        be32enc(&endiandata[19], nonce);
        allium_hash(hash, endiandata);

        if (hash[7] <= Htarg && fulltest(hash, ptarget)) {
            work_set_target_ratio(work, hash);
            pdata[19] = nonce;
            *hashes_done = pdata[19] - first_nonce;
            return 1;
        }
        nonce++;

    } while (nonce < max_nonce && !work_restart[thr_id].restart);

    pdata[19] = nonce;
    *hashes_done = pdata[19] - first_nonce + 1;
    return 0;
}