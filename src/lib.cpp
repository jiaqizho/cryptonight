//
// Created by Smalinuxer on 2018/8/20.
//
#include "lib.h"


#include <iostream>
using namespace std;


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

inline char hf_bin2hex(unsigned char c)
{
    if (c <= 0x9) {
        return '0' + c;
    }

    return 'a' - 0xA + c;
}


inline unsigned char hf_hex2bin(char c, bool &err)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    else if (c >= 'a' && c <= 'f') {
        return c - 'a' + 0xA;
    }
    else if (c >= 'A' && c <= 'F') {
        return c - 'A' + 0xA;
    }

    err = true;
    return 0;
}


void toHex(const unsigned char* in, unsigned int len, char* out)
{
    for (unsigned int i = 0; i < len; i++) {
        out[i * 2] = hf_bin2hex((in[i] & 0xF0) >> 4);
        out[i * 2 + 1] = hf_bin2hex(in[i] & 0x0F);
    }
}



bool fromHex(const char* in, unsigned int len, unsigned char* out)
{
    bool error = false;
    for (unsigned int i = 0; i < len; i += 2) {
        out[i / 2] = (hf_hex2bin(in[i], error) << 4) | hf_hex2bin(in[i + 1], error);

        if (error) {
            return false;
        }
    }
    return true;
}

inline uint64_t toDiff(uint64_t target) { return 0xFFFFFFFFFFFFFFFFULL / target; }

bool getTarget(const char *target,uint64_t* m_target)
{
    uint64_t m_diff;
    if (!target) {
        return false;
    }

    const size_t len = strlen(target);

    if (len <= 8) {
        uint32_t tmp = 0;
        char str[8];
        memcpy(str, target, len);

        if (!fromHex(str, 8, reinterpret_cast<unsigned char*>(&tmp)) || tmp == 0) {
            return false;
        }

        *m_target = 0xFFFFFFFFFFFFFFFFULL / (0xFFFFFFFFULL / static_cast<uint64_t>(tmp));
    }
    else if (len <= 16) {
        *m_target = 0;
        char str[16];
        memcpy(str, target, len);

        if (!fromHex(str, 16, reinterpret_cast<unsigned char*>(&m_target)) || *m_target == 0) {
            return false;
        }
    }
    else {
        return false;
    }

    m_diff = toDiff(*m_target);
    return true;
}

bool getBlob(const char *blob,uint8_t * out)
{
    size_t m_size;
    if (!blob) {
        return false;
    }

    m_size = strlen(blob);
    if (m_size % 2 != 0) {
        return false;
    }

    m_size /= 2;

    // pointer don't need check length
//    if (m_size < 76 || m_size >= sizeof(out)) {
//        return false;
//    }

    if (!fromHex(blob, (unsigned int) m_size * 2, out)) {
        return false;
    }
    return true;
}

uint32_t * nonce(uint8_t * m_blob)
{
    return reinterpret_cast<uint32_t*>(m_blob + 39);
}


extern "C"  void cryptonight_pow(const char *blob,const char *target,char *output,uint32_t* outnonce){

    alignas(16) uint8_t m_blob[96];
    uint64_t m_target;
    uint8_t m_hash[32];

    printf("boolean: %d\n", getBlob(blob,m_blob));
    getTarget(target,&m_target);

    cryptonight_ctx *m_ctx[1];
    Mem::create(m_ctx, xmrig::CRYPTONIGHT, 1);
    cn_hash_fun f = hash_fun_select(xmrig::CRYPTONIGHT,xmrig::AV_SINGLE,xmrig::VARIANT_1);


    *nonce(m_blob) = 0xffffffffU / 1 * (0 + 0);
    while (true){
        f(m_blob, 76, m_hash, m_ctx);

        printf("mhash : %llu  , distinct : %llu  , ", *reinterpret_cast<uint64_t*>(m_hash + 24) , (*reinterpret_cast<uint64_t*>(m_hash + 24) - m_target)  );
        printf("nonce : %d \n" , *nonce(m_blob));

        if (*reinterpret_cast<uint64_t*>(m_hash + 24) < m_target) {

            // output
            toHex(m_hash, 32, output);
            memcpy(outnonce,nonce(m_blob),sizeof(uint32_t));
            break;
        }

        *nonce(m_blob) += 1;

    }

}




extern "C" void test_cryptonight_pow(const char *blob,const char *target,char *output,uint32_t* outnonce){

    alignas(16) uint8_t m_blob[96];
    uint64_t m_target;
    uint8_t m_hash[32];

    printf("boolean: %d\n", getBlob(blob,m_blob));
    getTarget(target,&m_target);

    cryptonight_ctx *m_ctx[1];
    Mem::create(m_ctx, xmrig::CRYPTONIGHT, 1);
    cn_hash_fun f = hash_fun_select(xmrig::CRYPTONIGHT,xmrig::AV_SINGLE,xmrig::VARIANT_1);


    *nonce(m_blob) = 0xffffffffU / 1 * (0 + 0);
    *nonce(m_blob) += 100;

    f(m_blob, 76, m_hash, m_ctx);

    toHex(m_hash, 32, output);

    memcpy(outnonce,nonce(m_blob),sizeof(uint32_t));
}

