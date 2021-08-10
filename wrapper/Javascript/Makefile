LEVEL := .
include $(LEVEL)/Makefile.config

all: wolfssl wcjs.js wcjsgen

help:
	@echo "--------------------------------"
	@echo "           help"
	@echo "--------------------------------"
	@echo "source emsdk/emsdk_env.sh"
	@echo "emmake make"

dep: clean
	rm -rf $(PREFIX)

emsdk-portable:
	git clone https://github.com/emscripten-core/emsdk.git
	cd emsdk \
		&& ./emsdk install sdk-master-32bit \
		&& ./emsdk activate sdk-master-32bit

emsdk-portable64:
	git clone https://github.com/emscripten-core/emsdk.git
	cd emsdk \
		&& ./emsdk install latest \
		&& ./emsdk activate latest

wolfssl:
	cd $(WOLFSSL) ; \
		$(EMCONFIGURE) ./configure --prefix=$(PREFIX) \
		--enable-singlethreaded \
		--disable-shared --disable-filesystem \
		--disable-asm \
		--disable-poly1305 --disable-chacha --disable-sha3 \
		--enable-pkcs7 \
		--enable-keygen --enable-certgen --enable-certext --enable-aeskeywrap \
		--enable-debug \
		CFLAGS="-DWOLFSSL_LOG_PRINTF -DWOLFSSL_PUB_PEM_TO_DER"

	$(MAKE) -C $(WOLFSSL)
	$(MAKE) -C $(WOLFSSL) install

wcjs.js:
	mkdir wcjs/objects
	$(MAKE) -C wcjs wcjs.js

wcjsgen:
	$(MAKE) -C wcjs wcjsgen

tester:
	$(MAKE) -C wcjs tester

clean:
	$(MAKE) -C $(WOLFSSL) clean ;\
	$(MAKE) -C $(WRAPPER) clean ;\
	$(MAKE) -C wcjs clean ;\
