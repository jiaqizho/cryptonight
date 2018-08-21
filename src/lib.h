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

#include <stdint.h>

typedef void (*cn_hash_fun)(const uint8_t *input, size_t size, uint8_t *output, cryptonight_ctx **ctx);

cn_hash_fun hash_fun_select(xmrig::Algo algorithm, xmrig::AlgoVariant av, xmrig::Variant variant);

inline unsigned char hf_hex2bin(char c, bool &err);

bool fromHex(const char* in, unsigned int len, unsigned char* out);

bool getTarget(const char *target,uint64_t* m_target);

bool getBlob(const char *blob,uint8_t * out);

uint32_t * nonce(size_t index);

void cryptonight_pow(const char *blob,const char *target,char *output,long* outnonce);

#endif //XMRIG_CRYPTONIGHT_LIB_H

