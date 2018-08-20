//
// Created by Smalinuxer on 2018/8/20.
//

#ifndef XMRIG_CRYPTONIGHT_LIB_H
#define XMRIG_CRYPTONIGHT_LIB_H


#include <assert.h>
#include <inttypes.h>
#include <iostream>

#include "crypto/CryptoNight_x86.h"
#include "utils/Mem.h"





namespace xmrig {


    typedef void (*cn_hash_fun)(const uint8_t *input, size_t size, uint8_t *output, cryptonight_ctx **ctx);

    cn_hash_fun hash_fun_select(xmrig::Algo algorithm, xmrig::AlgoVariant av, xmrig::Variant variant)
    {

        static const cn_hash_fun func_table[xmrig::VARIANT_MAX * 10 * 3] = {
                cryptonight_single_hash<xmrig::CRYPTONIGHT, false, xmrig::VARIANT_0>,
                cryptonight_double_hash<xmrig::CRYPTONIGHT, false, xmrig::VARIANT_0>,
                cryptonight_single_hash<xmrig::CRYPTONIGHT, true,  xmrig::VARIANT_0>,
                cryptonight_double_hash<xmrig::CRYPTONIGHT, true,  xmrig::VARIANT_0>,
                cryptonight_triple_hash<xmrig::CRYPTONIGHT, false, xmrig::VARIANT_0>,
                cryptonight_quad_hash<xmrig::CRYPTONIGHT,   false, xmrig::VARIANT_0>,
                cryptonight_penta_hash<xmrig::CRYPTONIGHT,  false, xmrig::VARIANT_0>,
                cryptonight_triple_hash<xmrig::CRYPTONIGHT, true,  xmrig::VARIANT_0>,
                cryptonight_quad_hash<xmrig::CRYPTONIGHT,   true,  xmrig::VARIANT_0>,
                cryptonight_penta_hash<xmrig::CRYPTONIGHT,  true,  xmrig::VARIANT_0>,

                cryptonight_single_hash<xmrig::CRYPTONIGHT, false, xmrig::VARIANT_1>,
                cryptonight_double_hash<xmrig::CRYPTONIGHT, false, xmrig::VARIANT_1>,
                cryptonight_single_hash<xmrig::CRYPTONIGHT, true,  xmrig::VARIANT_1>,
                cryptonight_double_hash<xmrig::CRYPTONIGHT, true,  xmrig::VARIANT_1>,
                cryptonight_triple_hash<xmrig::CRYPTONIGHT, false, xmrig::VARIANT_1>,
                cryptonight_quad_hash<xmrig::CRYPTONIGHT,   false, xmrig::VARIANT_1>,
                cryptonight_penta_hash<xmrig::CRYPTONIGHT,  false, xmrig::VARIANT_1>,
                cryptonight_triple_hash<xmrig::CRYPTONIGHT, true,  xmrig::VARIANT_1>,
                cryptonight_quad_hash<xmrig::CRYPTONIGHT,   true,  xmrig::VARIANT_1>,
                cryptonight_penta_hash<xmrig::CRYPTONIGHT,  true,  xmrig::VARIANT_1>,

                nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, // VARIANT_TUBE

                cryptonight_single_hash<xmrig::CRYPTONIGHT, false, xmrig::VARIANT_XTL>,
                cryptonight_double_hash<xmrig::CRYPTONIGHT, false, xmrig::VARIANT_XTL>,
                cryptonight_single_hash<xmrig::CRYPTONIGHT, true,  xmrig::VARIANT_XTL>,
                cryptonight_double_hash<xmrig::CRYPTONIGHT, true,  xmrig::VARIANT_XTL>,
                cryptonight_triple_hash<xmrig::CRYPTONIGHT, false, xmrig::VARIANT_XTL>,
                cryptonight_quad_hash<xmrig::CRYPTONIGHT,   false, xmrig::VARIANT_XTL>,
                cryptonight_penta_hash<xmrig::CRYPTONIGHT,  false, xmrig::VARIANT_XTL>,
                cryptonight_triple_hash<xmrig::CRYPTONIGHT, true,  xmrig::VARIANT_XTL>,
                cryptonight_quad_hash<xmrig::CRYPTONIGHT,   true,  xmrig::VARIANT_XTL>,
                cryptonight_penta_hash<xmrig::CRYPTONIGHT,  true,  xmrig::VARIANT_XTL>,

                cryptonight_single_hash<xmrig::CRYPTONIGHT, false, xmrig::VARIANT_MSR>,
                cryptonight_double_hash<xmrig::CRYPTONIGHT, false, xmrig::VARIANT_MSR>,
                cryptonight_single_hash<xmrig::CRYPTONIGHT, true,  xmrig::VARIANT_MSR>,
                cryptonight_double_hash<xmrig::CRYPTONIGHT, true,  xmrig::VARIANT_MSR>,
                cryptonight_triple_hash<xmrig::CRYPTONIGHT, false, xmrig::VARIANT_MSR>,
                cryptonight_quad_hash<xmrig::CRYPTONIGHT,   false, xmrig::VARIANT_MSR>,
                cryptonight_penta_hash<xmrig::CRYPTONIGHT,  false, xmrig::VARIANT_MSR>,
                cryptonight_triple_hash<xmrig::CRYPTONIGHT, true,  xmrig::VARIANT_MSR>,
                cryptonight_quad_hash<xmrig::CRYPTONIGHT,   true,  xmrig::VARIANT_MSR>,
                cryptonight_penta_hash<xmrig::CRYPTONIGHT,  true,  xmrig::VARIANT_MSR>,

                nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, // VARIANT_XHV

                cryptonight_single_hash<xmrig::CRYPTONIGHT, false, xmrig::VARIANT_XAO>,
                cryptonight_double_hash<xmrig::CRYPTONIGHT, false, xmrig::VARIANT_XAO>,
                cryptonight_single_hash<xmrig::CRYPTONIGHT, true,  xmrig::VARIANT_XAO>,
                cryptonight_double_hash<xmrig::CRYPTONIGHT, true,  xmrig::VARIANT_XAO>,
                cryptonight_triple_hash<xmrig::CRYPTONIGHT, false, xmrig::VARIANT_XAO>,
                cryptonight_quad_hash<xmrig::CRYPTONIGHT,   false, xmrig::VARIANT_XAO>,
                cryptonight_penta_hash<xmrig::CRYPTONIGHT,  false, xmrig::VARIANT_XAO>,
                cryptonight_triple_hash<xmrig::CRYPTONIGHT, true,  xmrig::VARIANT_XAO>,
                cryptonight_quad_hash<xmrig::CRYPTONIGHT,   true,  xmrig::VARIANT_XAO>,
                cryptonight_penta_hash<xmrig::CRYPTONIGHT,  true,  xmrig::VARIANT_XAO>,

                cryptonight_single_hash<xmrig::CRYPTONIGHT, false, xmrig::VARIANT_RTO>,
                cryptonight_double_hash<xmrig::CRYPTONIGHT, false, xmrig::VARIANT_RTO>,
                cryptonight_single_hash<xmrig::CRYPTONIGHT, true,  xmrig::VARIANT_RTO>,
                cryptonight_double_hash<xmrig::CRYPTONIGHT, true,  xmrig::VARIANT_RTO>,
                cryptonight_triple_hash<xmrig::CRYPTONIGHT, false, xmrig::VARIANT_RTO>,
                cryptonight_quad_hash<xmrig::CRYPTONIGHT,   false, xmrig::VARIANT_RTO>,
                cryptonight_penta_hash<xmrig::CRYPTONIGHT,  false, xmrig::VARIANT_RTO>,
                cryptonight_triple_hash<xmrig::CRYPTONIGHT, true,  xmrig::VARIANT_RTO>,
                cryptonight_quad_hash<xmrig::CRYPTONIGHT,   true,  xmrig::VARIANT_RTO>,
                cryptonight_penta_hash<xmrig::CRYPTONIGHT,  true,  xmrig::VARIANT_RTO>,

#ifndef XMRIG_NO_AEON
                cryptonight_single_hash<xmrig::CRYPTONIGHT_LITE, false, xmrig::VARIANT_0>,
                cryptonight_double_hash<xmrig::CRYPTONIGHT_LITE, false, xmrig::VARIANT_0>,
                cryptonight_single_hash<xmrig::CRYPTONIGHT_LITE, true,  xmrig::VARIANT_0>,
                cryptonight_double_hash<xmrig::CRYPTONIGHT_LITE, true,  xmrig::VARIANT_0>,
                cryptonight_triple_hash<xmrig::CRYPTONIGHT_LITE, false, xmrig::VARIANT_0>,
                cryptonight_quad_hash<xmrig::CRYPTONIGHT_LITE,   false, xmrig::VARIANT_0>,
                cryptonight_penta_hash<xmrig::CRYPTONIGHT_LITE,  false, xmrig::VARIANT_0>,
                cryptonight_triple_hash<xmrig::CRYPTONIGHT_LITE, true,  xmrig::VARIANT_0>,
                cryptonight_quad_hash<xmrig::CRYPTONIGHT_LITE,   true,  xmrig::VARIANT_0>,
                cryptonight_penta_hash<xmrig::CRYPTONIGHT_LITE,  true,  xmrig::VARIANT_0>,

                cryptonight_single_hash<xmrig::CRYPTONIGHT_LITE, false, xmrig::VARIANT_1>,
                cryptonight_double_hash<xmrig::CRYPTONIGHT_LITE, false, xmrig::VARIANT_1>,
                cryptonight_single_hash<xmrig::CRYPTONIGHT_LITE, true,  xmrig::VARIANT_1>,
                cryptonight_double_hash<xmrig::CRYPTONIGHT_LITE, true,  xmrig::VARIANT_1>,
                cryptonight_triple_hash<xmrig::CRYPTONIGHT_LITE, false, xmrig::VARIANT_1>,
                cryptonight_quad_hash<xmrig::CRYPTONIGHT_LITE,   false, xmrig::VARIANT_1>,
                cryptonight_penta_hash<xmrig::CRYPTONIGHT_LITE,  false, xmrig::VARIANT_1>,
                cryptonight_triple_hash<xmrig::CRYPTONIGHT_LITE, true,  xmrig::VARIANT_1>,
                cryptonight_quad_hash<xmrig::CRYPTONIGHT_LITE,   true,  xmrig::VARIANT_1>,
                cryptonight_penta_hash<xmrig::CRYPTONIGHT_LITE,  true,  xmrig::VARIANT_1>,

                nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, // VARIANT_TUBE
                nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, // VARIANT_XTL
                nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, // VARIANT_MSR
                nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, // VARIANT_XHV
                nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, // VARIANT_XAO
                nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, // VARIANT_RTO
#else
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
#endif

#ifndef XMRIG_NO_SUMO
                cryptonight_single_hash<xmrig::CRYPTONIGHT_HEAVY, false, xmrig::VARIANT_0>,
                cryptonight_double_hash<xmrig::CRYPTONIGHT_HEAVY, false, xmrig::VARIANT_0>,
                cryptonight_single_hash<xmrig::CRYPTONIGHT_HEAVY, true,  xmrig::VARIANT_0>,
                cryptonight_double_hash<xmrig::CRYPTONIGHT_HEAVY, true,  xmrig::VARIANT_0>,
                cryptonight_triple_hash<xmrig::CRYPTONIGHT_HEAVY, false, xmrig::VARIANT_0>,
                cryptonight_quad_hash<xmrig::CRYPTONIGHT_HEAVY,   false, xmrig::VARIANT_0>,
                cryptonight_penta_hash<xmrig::CRYPTONIGHT_HEAVY,  false, xmrig::VARIANT_0>,
                cryptonight_triple_hash<xmrig::CRYPTONIGHT_HEAVY, true,  xmrig::VARIANT_0>,
                cryptonight_quad_hash<xmrig::CRYPTONIGHT_HEAVY,   true,  xmrig::VARIANT_0>,
                cryptonight_penta_hash<xmrig::CRYPTONIGHT_HEAVY,  true,  xmrig::VARIANT_0>,

                nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, // VARIANT_1

                cryptonight_single_hash<xmrig::CRYPTONIGHT_HEAVY, false, xmrig::VARIANT_TUBE>,
                cryptonight_double_hash<xmrig::CRYPTONIGHT_HEAVY, false, xmrig::VARIANT_TUBE>,
                cryptonight_single_hash<xmrig::CRYPTONIGHT_HEAVY, true,  xmrig::VARIANT_TUBE>,
                cryptonight_double_hash<xmrig::CRYPTONIGHT_HEAVY, true,  xmrig::VARIANT_TUBE>,
                cryptonight_triple_hash<xmrig::CRYPTONIGHT_HEAVY, false, xmrig::VARIANT_TUBE>,
                cryptonight_quad_hash<xmrig::CRYPTONIGHT_HEAVY,   false, xmrig::VARIANT_TUBE>,
                cryptonight_penta_hash<xmrig::CRYPTONIGHT_HEAVY,  false, xmrig::VARIANT_TUBE>,
                cryptonight_triple_hash<xmrig::CRYPTONIGHT_HEAVY, true,  xmrig::VARIANT_TUBE>,
                cryptonight_quad_hash<xmrig::CRYPTONIGHT_HEAVY,   true,  xmrig::VARIANT_TUBE>,
                cryptonight_penta_hash<xmrig::CRYPTONIGHT_HEAVY,  true,  xmrig::VARIANT_TUBE>,

                nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, // VARIANT_XTL
                nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, // VARIANT_MSR

                cryptonight_single_hash<xmrig::CRYPTONIGHT_HEAVY, false, xmrig::VARIANT_XHV>,
                cryptonight_double_hash<xmrig::CRYPTONIGHT_HEAVY, false, xmrig::VARIANT_XHV>,
                cryptonight_single_hash<xmrig::CRYPTONIGHT_HEAVY, true,  xmrig::VARIANT_XHV>,
                cryptonight_double_hash<xmrig::CRYPTONIGHT_HEAVY, true,  xmrig::VARIANT_XHV>,
                cryptonight_triple_hash<xmrig::CRYPTONIGHT_HEAVY, false, xmrig::VARIANT_XHV>,
                cryptonight_quad_hash<xmrig::CRYPTONIGHT_HEAVY,   false, xmrig::VARIANT_XHV>,
                cryptonight_penta_hash<xmrig::CRYPTONIGHT_HEAVY,  false, xmrig::VARIANT_XHV>,
                cryptonight_triple_hash<xmrig::CRYPTONIGHT_HEAVY, true,  xmrig::VARIANT_XHV>,
                cryptonight_quad_hash<xmrig::CRYPTONIGHT_HEAVY,   true,  xmrig::VARIANT_XHV>,
                cryptonight_penta_hash<xmrig::CRYPTONIGHT_HEAVY,  true,  xmrig::VARIANT_XHV>,

                nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, // VARIANT_XAO
                nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, // VARIANT_RTO
#else
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
#endif
        };
        const size_t index = xmrig::VARIANT_MAX * 10 * algorithm + 10 * variant + av - 1;
        return func_table[index];
    }


}

#endif //XMRIG_CRYPTONIGHT_LIB_H

