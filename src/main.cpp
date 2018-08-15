#include <iostream>

#include "crypto/CryptoNight_x86.h"
#include "xmrig.h"





typedef void (*cn_hash_fun)(const uint8_t *input, size_t size, uint8_t *output, cryptonight_ctx **ctx);

cn_hash_fun hash_fun_select(Algo algorithm, AlgoVariant av, Variant variant)
{
    assert(variant >= VARIANT_0 && variant < VARIANT_MAX);

    static const cn_hash_fun func_table[VARIANT_MAX * 10 * 3] = {
            cryptonight_single_hash<CRYPTONIGHT, false, VARIANT_0>,
            cryptonight_double_hash<CRYPTONIGHT, false, VARIANT_0>,
            cryptonight_single_hash<CRYPTONIGHT, true,  VARIANT_0>,
            cryptonight_double_hash<CRYPTONIGHT, true,  VARIANT_0>,
            cryptonight_triple_hash<CRYPTONIGHT, false, VARIANT_0>,
            cryptonight_quad_hash<CRYPTONIGHT,   false, VARIANT_0>,
            cryptonight_penta_hash<CRYPTONIGHT,  false, VARIANT_0>,
            cryptonight_triple_hash<CRYPTONIGHT, true,  VARIANT_0>,
            cryptonight_quad_hash<CRYPTONIGHT,   true,  VARIANT_0>,
            cryptonight_penta_hash<CRYPTONIGHT,  true,  VARIANT_0>,

            cryptonight_single_hash<CRYPTONIGHT, false, VARIANT_1>,
            cryptonight_double_hash<CRYPTONIGHT, false, VARIANT_1>,
            cryptonight_single_hash<CRYPTONIGHT, true,  VARIANT_1>,
            cryptonight_double_hash<CRYPTONIGHT, true,  VARIANT_1>,
            cryptonight_triple_hash<CRYPTONIGHT, false, VARIANT_1>,
            cryptonight_quad_hash<CRYPTONIGHT,   false, VARIANT_1>,
            cryptonight_penta_hash<CRYPTONIGHT,  false, VARIANT_1>,
            cryptonight_triple_hash<CRYPTONIGHT, true,  VARIANT_1>,
            cryptonight_quad_hash<CRYPTONIGHT,   true,  VARIANT_1>,
            cryptonight_penta_hash<CRYPTONIGHT,  true,  VARIANT_1>,

            nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, // VARIANT_TUBE

            cryptonight_single_hash<CRYPTONIGHT, false, VARIANT_XTL>,
            cryptonight_double_hash<CRYPTONIGHT, false, VARIANT_XTL>,
            cryptonight_single_hash<CRYPTONIGHT, true,  VARIANT_XTL>,
            cryptonight_double_hash<CRYPTONIGHT, true,  VARIANT_XTL>,
            cryptonight_triple_hash<CRYPTONIGHT, false, VARIANT_XTL>,
            cryptonight_quad_hash<CRYPTONIGHT,   false, VARIANT_XTL>,
            cryptonight_penta_hash<CRYPTONIGHT,  false, VARIANT_XTL>,
            cryptonight_triple_hash<CRYPTONIGHT, true,  VARIANT_XTL>,
            cryptonight_quad_hash<CRYPTONIGHT,   true,  VARIANT_XTL>,
            cryptonight_penta_hash<CRYPTONIGHT,  true,  VARIANT_XTL>,

            cryptonight_single_hash<CRYPTONIGHT, false, VARIANT_MSR>,
            cryptonight_double_hash<CRYPTONIGHT, false, VARIANT_MSR>,
            cryptonight_single_hash<CRYPTONIGHT, true,  VARIANT_MSR>,
            cryptonight_double_hash<CRYPTONIGHT, true,  VARIANT_MSR>,
            cryptonight_triple_hash<CRYPTONIGHT, false, VARIANT_MSR>,
            cryptonight_quad_hash<CRYPTONIGHT,   false, VARIANT_MSR>,
            cryptonight_penta_hash<CRYPTONIGHT,  false, VARIANT_MSR>,
            cryptonight_triple_hash<CRYPTONIGHT, true,  VARIANT_MSR>,
            cryptonight_quad_hash<CRYPTONIGHT,   true,  VARIANT_MSR>,
            cryptonight_penta_hash<CRYPTONIGHT,  true,  VARIANT_MSR>,

            nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, // VARIANT_XHV

            cryptonight_single_hash<CRYPTONIGHT, false, VARIANT_XAO>,
            cryptonight_double_hash<CRYPTONIGHT, false, VARIANT_XAO>,
            cryptonight_single_hash<CRYPTONIGHT, true,  VARIANT_XAO>,
            cryptonight_double_hash<CRYPTONIGHT, true,  VARIANT_XAO>,
            cryptonight_triple_hash<CRYPTONIGHT, false, VARIANT_XAO>,
            cryptonight_quad_hash<CRYPTONIGHT,   false, VARIANT_XAO>,
            cryptonight_penta_hash<CRYPTONIGHT,  false, VARIANT_XAO>,
            cryptonight_triple_hash<CRYPTONIGHT, true,  VARIANT_XAO>,
            cryptonight_quad_hash<CRYPTONIGHT,   true,  VARIANT_XAO>,
            cryptonight_penta_hash<CRYPTONIGHT,  true,  VARIANT_XAO>,

            cryptonight_single_hash<CRYPTONIGHT, false, VARIANT_RTO>,
            cryptonight_double_hash<CRYPTONIGHT, false, VARIANT_RTO>,
            cryptonight_single_hash<CRYPTONIGHT, true,  VARIANT_RTO>,
            cryptonight_double_hash<CRYPTONIGHT, true,  VARIANT_RTO>,
            cryptonight_triple_hash<CRYPTONIGHT, false, VARIANT_RTO>,
            cryptonight_quad_hash<CRYPTONIGHT,   false, VARIANT_RTO>,
            cryptonight_penta_hash<CRYPTONIGHT,  false, VARIANT_RTO>,
            cryptonight_triple_hash<CRYPTONIGHT, true,  VARIANT_RTO>,
            cryptonight_quad_hash<CRYPTONIGHT,   true,  VARIANT_RTO>,
            cryptonight_penta_hash<CRYPTONIGHT,  true,  VARIANT_RTO>,

#       ifndef XMRIG_NO_AEON
            cryptonight_single_hash<CRYPTONIGHT_LITE, false, VARIANT_0>,
            cryptonight_double_hash<CRYPTONIGHT_LITE, false, VARIANT_0>,
            cryptonight_single_hash<CRYPTONIGHT_LITE, true,  VARIANT_0>,
            cryptonight_double_hash<CRYPTONIGHT_LITE, true,  VARIANT_0>,
            cryptonight_triple_hash<CRYPTONIGHT_LITE, false, VARIANT_0>,
            cryptonight_quad_hash<CRYPTONIGHT_LITE,   false, VARIANT_0>,
            cryptonight_penta_hash<CRYPTONIGHT_LITE,  false, VARIANT_0>,
            cryptonight_triple_hash<CRYPTONIGHT_LITE, true,  VARIANT_0>,
            cryptonight_quad_hash<CRYPTONIGHT_LITE,   true,  VARIANT_0>,
            cryptonight_penta_hash<CRYPTONIGHT_LITE,  true,  VARIANT_0>,

            cryptonight_single_hash<CRYPTONIGHT_LITE, false, VARIANT_1>,
            cryptonight_double_hash<CRYPTONIGHT_LITE, false, VARIANT_1>,
            cryptonight_single_hash<CRYPTONIGHT_LITE, true,  VARIANT_1>,
            cryptonight_double_hash<CRYPTONIGHT_LITE, true,  VARIANT_1>,
            cryptonight_triple_hash<CRYPTONIGHT_LITE, false, VARIANT_1>,
            cryptonight_quad_hash<CRYPTONIGHT_LITE,   false, VARIANT_1>,
            cryptonight_penta_hash<CRYPTONIGHT_LITE,  false, VARIANT_1>,
            cryptonight_triple_hash<CRYPTONIGHT_LITE, true,  VARIANT_1>,
            cryptonight_quad_hash<CRYPTONIGHT_LITE,   true,  VARIANT_1>,
            cryptonight_penta_hash<CRYPTONIGHT_LITE,  true,  VARIANT_1>,

            nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, // VARIANT_TUBE
            nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, // VARIANT_XTL
            nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, // VARIANT_MSR
            nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, // VARIANT_XHV
            nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, // VARIANT_XAO
            nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, // VARIANT_RTO
#       else
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
#       endif

#       ifndef XMRIG_NO_SUMO
            cryptonight_single_hash<CRYPTONIGHT_HEAVY, false, VARIANT_0>,
            cryptonight_double_hash<CRYPTONIGHT_HEAVY, false, VARIANT_0>,
            cryptonight_single_hash<CRYPTONIGHT_HEAVY, true,  VARIANT_0>,
            cryptonight_double_hash<CRYPTONIGHT_HEAVY, true,  VARIANT_0>,
            cryptonight_triple_hash<CRYPTONIGHT_HEAVY, false, VARIANT_0>,
            cryptonight_quad_hash<CRYPTONIGHT_HEAVY,   false, VARIANT_0>,
            cryptonight_penta_hash<CRYPTONIGHT_HEAVY,  false, VARIANT_0>,
            cryptonight_triple_hash<CRYPTONIGHT_HEAVY, true,  VARIANT_0>,
            cryptonight_quad_hash<CRYPTONIGHT_HEAVY,   true,  VARIANT_0>,
            cryptonight_penta_hash<CRYPTONIGHT_HEAVY,  true,  VARIANT_0>,

            nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, // VARIANT_1

            cryptonight_single_hash<CRYPTONIGHT_HEAVY, false, VARIANT_TUBE>,
            cryptonight_double_hash<CRYPTONIGHT_HEAVY, false, VARIANT_TUBE>,
            cryptonight_single_hash<CRYPTONIGHT_HEAVY, true,  VARIANT_TUBE>,
            cryptonight_double_hash<CRYPTONIGHT_HEAVY, true,  VARIANT_TUBE>,
            cryptonight_triple_hash<CRYPTONIGHT_HEAVY, false, VARIANT_TUBE>,
            cryptonight_quad_hash<CRYPTONIGHT_HEAVY,   false, VARIANT_TUBE>,
            cryptonight_penta_hash<CRYPTONIGHT_HEAVY,  false, VARIANT_TUBE>,
            cryptonight_triple_hash<CRYPTONIGHT_HEAVY, true,  VARIANT_TUBE>,
            cryptonight_quad_hash<CRYPTONIGHT_HEAVY,   true,  VARIANT_TUBE>,
            cryptonight_penta_hash<CRYPTONIGHT_HEAVY,  true,  VARIANT_TUBE>,

            nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, // VARIANT_XTL
            nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, // VARIANT_MSR

            cryptonight_single_hash<CRYPTONIGHT_HEAVY, false, VARIANT_XHV>,
            cryptonight_double_hash<CRYPTONIGHT_HEAVY, false, VARIANT_XHV>,
            cryptonight_single_hash<CRYPTONIGHT_HEAVY, true,  VARIANT_XHV>,
            cryptonight_double_hash<CRYPTONIGHT_HEAVY, true,  VARIANT_XHV>,
            cryptonight_triple_hash<CRYPTONIGHT_HEAVY, false, VARIANT_XHV>,
            cryptonight_quad_hash<CRYPTONIGHT_HEAVY,   false, VARIANT_XHV>,
            cryptonight_penta_hash<CRYPTONIGHT_HEAVY,  false, VARIANT_XHV>,
            cryptonight_triple_hash<CRYPTONIGHT_HEAVY, true,  VARIANT_XHV>,
            cryptonight_quad_hash<CRYPTONIGHT_HEAVY,   true,  VARIANT_XHV>,
            cryptonight_penta_hash<CRYPTONIGHT_HEAVY,  true,  VARIANT_XHV>,

            nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, // VARIANT_XAO
            nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, // VARIANT_RTO
#       else
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
#       endif
    };

    const size_t index = VARIANT_MAX * 10 * algorithm + 10 * variant + av - 1;

#   ifndef NDEBUG
    cn_hash_fun func = func_table[index];

    assert(index < sizeof(func_table) / sizeof(func_table[0]));
    assert(func != nullptr);

    return func;
#   else
    return func_table[index];
#   endif
}




int main() {

    cn_hash_fun f = hash_fun_select(CRYPTONIGHT,AV_AUTO,VARIANT_0)

    return 0;
}