# Microchip Harmony Support

## Examples

The MPLAB X IDE examples for wolfCrypt/wolfSSL are located in `<wolfssl-root>/mplabx`

## Updating Harmony

```sh
export WOLFSSL_DIR=~/wolfssl
export HARMONY_DIR=~/microchip/harmony/v2_06
```

### wolfCrypt

1. Copy the library

```sh
cp $(WOLFSSL_DIR)/wolfcrypt/src/*.c 				$(HARMONY_DIR)/framework/crypto/src
cp $(WOLFSSL_DIR)/wolfcrypt/src/port/atmel/*.c 		$(HARMONY_DIR)/framework/crypto/src
cp $(WOLFSSL_DIR)/wolfcrypt/src/port/pic32/*.c 		$(HARMONY_DIR)/framework/crypto/src
cp $(WOLFSSL_DIR)/wolfssl/wolfcrypt/*.h 			$(HARMONY_DIR)/framework/crypto/src
cp $(WOLFSSL_DIR)/wolfssl/wolfcrypt/port/atmel/*.h 	$(HARMONY_DIR)/framework/crypto/src
cp $(WOLFSSL_DIR)/wolfssl/wolfcrypt/port/pic32/*.h 	$(HARMONY_DIR)/framework/crypto/src
cp $(WOLFSSL_DIR)/mcapi/crypto.* 					$(HARMONY_DIR)/framework/crypto/src
```

### wolfSSL

1. Copy the library

```sh
cp -r $(WOLFSSL_DIR)/certs 		$(HARMONY_DIR)/third_party/tcpip/wolfssl
cp -r $(WOLFSSL_DIR)/ctaocrypt 	$(HARMONY_DIR)/third_party/tcpip/wolfssl
cp -r $(WOLFSSL_DIR)/cyassl 	$(HARMONY_DIR)/third_party/tcpip/wolfssl
cp -r $(WOLFSSL_DIR)/doc 		$(HARMONY_DIR)/third_party/tcpip/wolfssl
cp -r $(WOLFSSL_DIR)/examples 	$(HARMONY_DIR)/third_party/tcpip/wolfssl
cp -r $(WOLFSSL_DIR)/IDE 		$(HARMONY_DIR)/third_party/tcpip/wolfssl
cp -r $(WOLFSSL_DIR)/IPP 		$(HARMONY_DIR)/third_party/tcpip/wolfssl
cp -r $(WOLFSSL_DIR)/mcapi 		$(HARMONY_DIR)/third_party/tcpip/wolfssl
cp -r $(WOLFSSL_DIR)/mplabx 	$(HARMONY_DIR)/third_party/tcpip/wolfssl
cp -r $(WOLFSSL_DIR)/mqx 		$(HARMONY_DIR)/third_party/tcpip/wolfssl
cp -r $(WOLFSSL_DIR)/rpm 		$(HARMONY_DIR)/third_party/tcpip/wolfssl
cp -r $(WOLFSSL_DIR)/scripts 	$(HARMONY_DIR)/third_party/tcpip/wolfssl
cp -r $(WOLFSSL_DIR)/src 		$(HARMONY_DIR)/third_party/tcpip/wolfssl
cp -r $(WOLFSSL_DIR)/sslSniffer $(HARMONY_DIR)/third_party/tcpip/wolfssl
cp -r $(WOLFSSL_DIR)/support 	$(HARMONY_DIR)/third_party/tcpip/wolfssl
cp -r $(WOLFSSL_DIR)/swig 		$(HARMONY_DIR)/third_party/tcpip/wolfssl
cp -r $(WOLFSSL_DIR)/tests 		$(HARMONY_DIR)/third_party/tcpip/wolfssl
cp -r $(WOLFSSL_DIR)/testsuite 	$(HARMONY_DIR)/third_party/tcpip/wolfssl
cp -r $(WOLFSSL_DIR)/tirtos 	$(HARMONY_DIR)/third_party/tcpip/wolfssl
cp -r $(WOLFSSL_DIR)/wolfcrypt 	$(HARMONY_DIR)/third_party/tcpip/wolfssl
cp -r $(WOLFSSL_DIR)/wolfssl 	$(HARMONY_DIR)/third_party/tcpip/wolfssl
cp -r $(WOLFSSL_DIR)/wrapper 	$(HARMONY_DIR)/third_party/tcpip/wolfssl
cp -r $(WOLFSSL_DIR)/README* 	$(HARMONY_DIR)/third_party/tcpip/wolfssl
cp -r $(WOLFSSL_DIR)/AUTHORS* 	$(HARMONY_DIR)/third_party/tcpip/wolfssl
cp -r $(WOLFSSL_DIR)/ChangeLog* $(HARMONY_DIR)/third_party/tcpip/wolfssl
```


## Support

For questions please email us at support@wolfssl.com
