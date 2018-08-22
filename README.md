# Cryptonight

------
**an cryptonight implemention from xmrig.**

> * An independent and decoupling cryptonight implement.
> * Very efficient , cause it from xmrig.
> * It support Monero7 and others origin cryptonight such as CryptoNight-Heavy(but don't has access now). 


## Why

> * xmrig is a **bad design** application , it has bad scalability.
> * provide an **pure cryptonight libaray** to help others design an application whichever language he used.

## Build

```
cmake .
make .
```


## Use

```
#include "lib.h"
cryptonight_pow(blob,target,output,outnonce);

```
