# ST Ports

Support for the STM32 L4, F1, F2, F4 and F7 on-board crypto hardware acceleration for symmetric AES (ECB/CBC/CTR/GCM) and MD5/SHA1/SHA224/SHA256.

Support for the STSAFE-A100 crypto hardware accelerator co-processor via I2C for ECC supporting NIST or Brainpool 256-bit and 384-bit curves. It requires the ST-Safe SDK including wolf stsafe_interface.c/.h files. Please contact ST for these.

Support for the STA1385 Telemaco3P Automotive Dual Core (A7/M3) CPU with hardware eHSM.

For details see our [wolfSSL ST](https://www.wolfssl.com/docs/stm32/) page.


## STM32 Symmetric Acceleration

We support using the STM32 CubeMX and Standard Peripheral Library.

### Building

To enable support define one of the following:

```
#define WOLFSSL_STM32L4
#define WOLFSSL_STM32F1
#define WOLFSSL_STM32F2
#define WOLFSSL_STM32F4
#define WOLFSSL_STM32F7
```

To use CubeMX define `WOLFSSL_STM32_CUBEMX` otherwise StdPeriLib is used.

To disable portions of the hardware acceleration you can optionally define:

```
#define NO_STM32_RNG
#define NO_STM32_CRYPTO
#define NO_STM32_HASH
```

### Coding

In your application you must include <wolfssl/wolfcrypt/settings.h> before any other wolfSSL headers. If building the sources directly we recommend defining `WOLFSSL_USER_SETTINGS` and adding your own `user_settings.h` file. You can find a good reference for this in `IDE/GCC-ARM/Header/user_settings.h`.


### Benchmarks

See our [benchmarks](https://www.wolfssl.com/docs/benchmarks/) on the wolfSSL website.



## STSAFE-A100 ECC Acceleration

Using the wolfSSL PK callbacks and the reference ST Safe reference API's we support an ECC only cipher suite such as ECDHE-ECDSA-AES128-SHA256 for TLS client or server.

At the wolfCrypt level we also support ECC native API's for `wc_ecc_*` using the ST-Safe.

### Building

`./configure --enable-pkcallbacks CFLAGS="-DWOLFSSL_STSAFEA100"`

or

`#define HAVE_PK_CALLBACKS`
`#define WOLFSSL_STSAFEA100`


### Coding

Setup the PK callbacks for TLS using:

```
/* Setup PK Callbacks for STSAFE-A100 */
WOLFSSL_CTX* ctx;
wolfSSL_CTX_SetEccKeyGenCb(ctx, SSL_STSAFE_CreateKeyCb);
wolfSSL_CTX_SetEccSignCb(ctx, SSL_STSAFE_SignCertificateCb);
wolfSSL_CTX_SetEccVerifyCb(ctx, SSL_STSAFE_VerifyPeerCertCb);
wolfSSL_CTX_SetEccSharedSecretCb(ctx, SSL_STSAFE_SharedSecretCb);
wolfSSL_CTX_SetDevId(ctx, 0); /* enables wolfCrypt `wc_ecc_*` ST-Safe use */
```

The reference STSAFE-A100 PK callback functions are located in the `wolfcrypt/src/port/st/stsafe.c` file.

Adding a custom context to the callbacks:

```
/* Setup PK Callbacks context */
WOLFSSL* ssl;
void* myOwnCtx;
wolfSSL_SetEccKeyGenCtx(ssl, myOwnCtx);
wolfSSL_SetEccVerifyCtx(ssl, myOwnCtx);
wolfSSL_SetEccSignCtx(ssl, myOwnCtx);
wolfSSL_SetEccSharedSecretCtx(ssl, myOwnCtx);
```

### Benchmarks and Memory Use

Software only implementation (STM32L4 120Mhz, Cortex-M4, Fast Math):

```
ECDHE    256 key gen       SW    4 ops took 1.278 sec, avg 319.500 ms,  3.130 ops/sec
ECDHE    256 agree         SW    4 ops took 1.306 sec, avg 326.500 ms,  3.063 ops/sec
ECDSA    256 sign          SW    4 ops took 1.298 sec, avg 324.500 ms,  3.082 ops/sec
ECDSA    256 verify        SW    2 ops took 1.283 sec, avg 641.500 ms,  1.559 ops/sec
```

Memory Use:

```
Peak Stack: 18456
Peak Heap: 2640
Total: 21096
```


STSAFE-A100 acceleration:

```
ECDHE    256 key gen       HW    8 ops took 1.008 sec, avg 126.000 ms,  7.937 ops/sec
ECDHE    256 agree         HW    6 ops took 1.051 sec, avg 175.167 ms,  5.709 ops/sec
ECDSA    256 sign          HW   14 ops took 1.161 sec, avg  82.929 ms, 12.059 ops/sec
ECDSA    256 verify        HW    8 ops took 1.184 sec, avg 148.000 ms,  6.757 ops/sec
```

Memory Use:

```
Peak Stack: 9592
Peak Heap: 170
Total: 9762
```


## ST Telemaco3P

Platform is a dual CPU Cortex-A7 (armv7l) and Cortex-M3.

### Documentation Setup

```sh
sudo apt install apache2 php5 php5-cli php5-mysql mysql-server libapache2-mod-php5
mysql -u root -p -e "show databases;"

# Edit install_linux.sh and modify:
MYSQL_PWD=""
USERGUIDE_LINUX_DIR=""

chmod +x install_linux.sh
sudo ./install_linux.sh

http://localhost/telemaco3P_user_guide/index.php/Main_Page
```

### Building Telemaco3P Linux Release Platform

```sh
cd yocto-bsp
source envsetup.sh
#choose sta1385-mtp-mmc
bitbake core-image-st-carproc
```

### Packaging Image

```sh
cd $BUILDDIR/tmp/deploy/images
rm -f sta1385-mtp-mmc_extraction.tar.gz
./sta_extract_deploy.sh sta1385-mtp-mmc
1 image(s) available:
    st-carproc
Images available in sta1385-mtp-mmc_extraction.tar.gz
```

### Loading Image

1. Install STA_FlashLoader `sudo ./INSTALL.pl`
2. Run flash loader `./flashLoad.pl`
3. Load configuration file `./tmp/deploy/images/sta1385-mtp-mmc/config-core-image-st-carproc-sta1385-mtp-mmc.txt`
4. Choose USB DFU and USB FastBoot
5. Set DIP to On-Off-On
6. Power Cycle board
7. Check root and click Erase
8. Select All and click Flash
9. Set DIP to all ON
10. Power Cycle

### Adding wolfSSL Yocto Recipe

1. Clone the wolfSSL meta repo

```sh
cd yocto-bsp
git clone https://github.com/wolfSSL/meta-wolfssl.git
```

2. Update the wolfssl library meta package in `meta-openembedded/meta-networking/recipes-connectivity` dir.

```sh
cp -r ./meta-wolfssl/recipes-wolfssl/* ./meta-openembedded/meta-networking/recipes-connectivity
cp -r ./meta-wolfssl/recipes-examples/wolfcrypt/* ./meta-openembedded/meta-networking/recipes-connectivity
```

3. Add wolfssl and wolfcrypttest to the install list

```
vim ./meta-st/meta-st-carproc/recipes-core/images/core-image-st-carproc.inc
# Add "wolfssl" to the STCORE list.
# Add "wolfcrypttest wolfcryptbenchmark" to the DEBUG_TOOLS list.
```

4. Add build settings required:

    a. Add new file "wolfssl_%.bbappend" in wolfcrypttest folder.
    b. Place this into the file `EXTRA_OECONF += "--enable-st-ehsm"`

    ```sh
    vim ./meta-openembedded/meta-networking/recipes-connectivity/wolfcrypttest/wolfssl_%.bbappend
    ```

5. Repeat packaging image and loading image instructions above.


### Debugging Yocto Recipe

```sh
# Steps to force clean / build / install wolfSSL library
bitbake -v -c clean wolfssl
bitbake -v -f -c compile wolfssl
bitbake -v -f -c install wolfssl

# Steps to force clean / build / install wolfCryptTest
bitbake -v -c clean wolfcrypttest
bitbake -v -f -c compile wolfcrypttest
bitbake -v -f -c install wolfcrypttest

# Open shell with wolfssl build environment
bitbake -c devshell wolfssl
```

### wolfCrypt Software Tests on STA1385 (Cortex A7)

```sh
root@sta1385-mtp-mmc:~# wolfcrypttest
------------------------------------------------------------------------------
 wolfSSL version 4.2.0
------------------------------------------------------------------------------
Sizeof mismatch (build) 0 != (run) 2
error    test passed!
MEMORY   test passed!
base64   test passed!
asn      test passed!
MD5      test passed!
SHA      test passed!
SHA-256  test passed!
SHA-384  test passed!
SHA-512  test passed!
Hash     test passed!
HMAC-MD5 test passed!
HMAC-SHA test passed!
HMAC-SHA256 test passed!
HMAC-SHA384 test passed!
HMAC-SHA512 test passed!
X963-KDF    test passed!
GMAC     test passed!
Chacha   test passed!
POLY1305 test passed!
ChaCha20-Poly1305 AEAD test passed!
AES      test passed!
AES192   test passed!
AES256   test passed!
AES-GCM  test passed!
AES Key Wrap test passed!
RANDOM   test passed!
RSA      test passed!
DH       test passed!
ECC      test passed!
ECC buffer test passed!
PKCS7encrypted  test passed!
PKCS7signed     test passed!
PKCS7enveloped  test passed!
PKCS7authenveloped  test passed!
wolfcprime    test passed!
logging  test passed!
mutex    test passed!
memcb    test passed!
ryptbenchmark
crypto callback test passed!
Test complete

root@sta1385-mtp-mmc:~# wolfcryptbenchmark
------------------------------------------------------------------------------
 wolfSSL version 4.2.0
------------------------------------------------------------------------------
wolfCrypt Benchmark (block bytes 1024, min 1.0 sec each)
RNG                  5 MB took 1.001 seconds,    5.464 MB/s
AES-128-CBC-enc     10 MB took 1.001 seconds,   10.004 MB/s
AES-128-CBC-dec     10 MB took 1.002 seconds,   10.206 MB/s
AES-192-CBC-enc      8 MB took 1.001 seconds,    8.489 MB/s
AES-192-CBC-dec      9 MB took 1.002 seconds,    8.670 MB/s
AES-256-CBC-enc      7 MB took 1.001 seconds,    7.364 MB/s
AES-256-CBC-dec      8 MB took 1.001 seconds,    7.509 MB/s
AES-128-GCM-enc      2 MB took 1.008 seconds,    1.840 MB/s
AES-128-GCM-dec      2 MB took 1.000 seconds,    1.855 MB/s
AES-192-GCM-enc      2 MB took 1.002 seconds,    1.754 MB/s
AES-192-GCM-dec      2 MB took 1.002 seconds,    1.754 MB/s
AES-256-GCM-enc      2 MB took 1.005 seconds,    1.676 MB/s
AES-256-GCM-dec      2 MB took 1.005 seconds,    1.676 MB/s
AES-128-ECB-enc     10 MB took 1.000 seconds,   10.153 MB/s
AES-128-ECB-dec     10 MB took 1.000 seconds,   10.417 MB/s
AES-192-ECB-enc      9 MB took 1.000 seconds,    8.598 MB/s
AES-192-ECB-dec      9 MB took 1.000 seconds,    8.825 MB/s
AES-256-ECB-enc      7 MB took 1.000 seconds,    7.457 MB/s
AES-256-ECB-dec      8 MB took 1.000 seconds,    7.653 MB/s
CHACHA              16 MB took 1.000 seconds,   16.010 MB/s
CHA-POLY            12 MB took 1.002 seconds,   12.063 MB/s
MD5                 58 MB took 1.000 seconds,   58.305 MB/s
POLY1305            64 MB took 1.000 seconds,   64.150 MB/s
SHA                 24 MB took 1.001 seconds,   23.976 MB/s
SHA-256             13 MB took 1.001 seconds,   12.855 MB/s
SHA-384              5 MB took 1.001 seconds,    5.441 MB/s
SHA-512              5 MB took 1.001 seconds,    5.439 MB/s
HMAC-MD5            57 MB took 1.000 seconds,   57.359 MB/s
HMAC-SHA            24 MB took 1.001 seconds,   23.713 MB/s
HMAC-SHA256         13 MB took 1.001 seconds,   12.729 MB/s
HMAC-SHA384          5 MB took 1.003 seconds,    5.355 MB/s
HMAC-SHA512          5 MB took 1.003 seconds,    5.354 MB/s
RSA     2048 public        492 ops took 1.000 sec, avg 2.033 ms, 491.770 ops/sec
RSA     2048 private        14 ops took 1.001 sec, avg 71.527 ms, 13.981 ops/sec
DH      2048 key gen        31 ops took 1.005 sec, avg 32.425 ms, 30.840 ops/sec
DH      2048 agree          32 ops took 1.037 sec, avg 32.402 ms, 30.862 ops/sec
ECC      256 key gen       935 ops took 1.000 sec, avg 1.070 ms, 934.541 ops/sec
ECDHE    256 agree         224 ops took 1.001 sec, avg 4.468 ms, 223.814 ops/sec
ECDSA    256 sign          568 ops took 1.002 sec, avg 1.765 ms, 566.612 ops/sec
ECDSA    256 verify        176 ops took 1.003 sec, avg 5.700 ms, 175.428 ops/sec
Benchmark complete
```

### OPTEE Support (for eHSM)

```sh
# Enable OPTEE using
source envsetup.sh --optee
# Answer (Y)es to enable OPTEE
bitbake core-image-st-carproc

# Flash board
# Message prior to UBoot should output such as "I/TC: OP-TEE "
```

#### Testing eHSM on Target

```sh
# Asymmetric Tests
xtest -l 15 4004 # get random
xtest -l 15 4006 # Asym Crypto
xtest -l 15 4007 # Key Gen
xtest -l 15 4009 # Derive ECDH key
xtest -l 15 4090_plat

# HSM PTA Tests
xtest -l 15 1090_plat

# Run all tests
xtest -l 15
```



## STM32 Cross Compiling

Specify your build output:

```sh
export WOLFSSL_PREFIX="`pwd`/../build"
```

### Cortex-A7 Baremetal:

```sh
./configure \
    --host=arm-none-eabi \
    CFLAGS="-mcpu=cortex-a7 --specs=nosys.specs -DNO_WOLFSSL_DIR -DWOLFSSL_USER_IO -DNO_WRITEV" \
    --prefix=$WOLFSSL_PREFIX/wolfssl-a7-baremetal \
    --disable-shared \
    --disable-examples
make
make dist
```

### Cortex-A7 Linux

```sh
./configure \
    --host=arm-linux-gnueabi \
    CFLAGS="-mcpu=cortex-a7" \
    --prefix=$WOLFSSL_PREFIX/wolfssl-a7-linux \
    --disable-shared
make
make dist
```

Cortex-M3 Baremetal

```sh
./configure \
    --host=arm-none-eabi \
    CFLAGS="-mcpu=cortex-m3 --specs=nano.specs -DNO_WOLFSSL_DIR -DWOLFSSL_USER_IO -DNO_WRITEV" \
    --prefix=$WOLFSSL_PREFIX/wolfssl-m3-baremetal \
    --disable-examples
make
make dist
```


## Support

Email us at [support@wolfssl.com](mailto:support@wolfssl.com).
