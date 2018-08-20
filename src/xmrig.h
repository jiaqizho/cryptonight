//
// Created by root on 18-8-15.
//

#ifndef XMRIG_CRYPTONIGHT_XMRIG_H
#define XMRIG_CRYPTONIGHT_XMRIG_H



namespace xmrig {

    enum Algo {
        INVALID_ALGO = -1,
        CRYPTONIGHT,       /* CryptoNight (Monero) */
        CRYPTONIGHT_LITE,  /* CryptoNight-Lite (AEON) */
        CRYPTONIGHT_HEAVY  /* CryptoNight-Heavy (SUMO) */
    };


    enum AlgoVariant {
        AV_AUTO,        // --av=0 Automatic mode.
        AV_SINGLE,      // --av=1  Single hash mode
        AV_DOUBLE,      // --av=2  Double hash mode
        AV_SINGLE_SOFT, // --av=3  Single hash mode (Software AES)
        AV_DOUBLE_SOFT, // --av=4  Double hash mode (Software AES)
        AV_TRIPLE,      // --av=5  Triple hash mode
        AV_QUAD,        // --av=6  Quard hash mode
        AV_PENTA,       // --av=7  Penta hash mode
        AV_TRIPLE_SOFT, // --av=8  Triple hash mode (Software AES)
        AV_QUAD_SOFT,   // --av=9  Quard hash mode  (Software AES)
        AV_PENTA_SOFT,  // --av=10 Penta hash mode  (Software AES)
        AV_MAX
    };


    enum Variant {
        VARIANT_AUTO = -1, // Autodetect
        VARIANT_0    = 0,  // Original CryptoNight or CryptoNight-Heavy
        VARIANT_1    = 1,  // CryptoNight variant 1 also known as Monero7 and CryptoNightV7
        VARIANT_TUBE = 2,  // Modified CryptoNight-Heavy (TUBE only)
        VARIANT_XTL  = 3,  // Modified CryptoNight variant 1 (Stellite only)
        VARIANT_MSR  = 4,  // Modified CryptoNight variant 1 (Masari only)
        VARIANT_XHV  = 5,  // Modified CryptoNight-Heavy (Haven Protocol only)
        VARIANT_XAO  = 6,  // Modified CryptoNight variant 1 (Alloy only)
        VARIANT_RTO  = 7,  // Modified CryptoNight variant 1 (Arto only)
        VARIANT_MAX
    };


}

#endif //XMRIG_CRYPTONIGHT_XMRIG_H
