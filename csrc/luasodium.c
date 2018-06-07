#define LUASODIUM_VERSION "luasodium-0.1"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sodium.h>

#include "lua.h"
#include "lauxlib.h"


// Compatibility with Lua 5.2 onwards
#if (LUA_VERSION_NUM >= 502)
#undef luaL_register
#define luaL_register(L, n, f) \
	{ if ((n) == NULL) luaL_setfuncs(L, f, 0); else luaL_newlib(L, f); }
#endif


static int ls_sodium_version(lua_State *L) {
	lua_pushstring(L, sodium_version_string());
	return 1;
}


static int ls_randombytes(lua_State *L) {
	size_t bufln; 
	unsigned char buf[256];
	lua_Integer byteslen = luaL_checkinteger(L, 1);
	if ((byteslen > 256 ) || (byteslen < 0)) {
		lua_pushnil(L);
		lua_pushstring(L, "Invalid number of bytes");
		return 2;
	}
	randombytes_buf(buf, byteslen);
	lua_pushlstring(L, buf, byteslen);
	return 1;
}


static int ls_sign_keypair(lua_State *L) {
	unsigned char pk[crypto_sign_PUBLICKEYBYTES];
	unsigned char sk[crypto_sign_SECRETKEYBYTES];
	if (crypto_sign_keypair(pk, sk)) {
		lua_pushnil(L);
		lua_pushstring(L, "Key creation failed");
		return 2;
	}
	lua_pushlstring(L, (char*)pk, crypto_sign_PUBLICKEYBYTES);
	lua_pushlstring(L, (char*)sk, crypto_sign_SECRETKEYBYTES);
	return 2;
}


static int ls_generichash(lua_State *L) {
	size_t msglen, keylen;
	const unsigned char *msg = luaL_checklstring(L, 1, &msglen);
	const unsigned char *key = luaL_checklstring(L, 2, &keylen);
	const lua_Integer hashlen = luaL_checkinteger(L, 3);
	if ((hashlen > crypto_generichash_BYTES_MAX) || (hashlen < crypto_generichash_BYTES_MIN)) {
		lua_pushnil(L);
		lua_pushstring(L, "Invalid hash size");
		return 2;
	}
	unsigned char hash[hashlen];
	crypto_generichash(hash, hashlen, msg, msglen, key, keylen);
	lua_pushlstring(L, (char*)hash, hashlen);
	return 1;
}


static int ls_aead_encrypt(lua_State *L) {
	size_t msglen, adlen, noncelen, keylen;
	const unsigned char *msg = luaL_checklstring(L, 1, &msglen);
	const unsigned char *ad = luaL_checklstring(L, 2, &adlen);
	const unsigned char *nonce = luaL_checklstring(L, 3, &noncelen);
	const unsigned char *key = luaL_checklstring(L, 4, &keylen);
	if (noncelen != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES) {
		lua_pushnil(L);
		lua_pushstring(L, "Invalid nonce size");
		return 2;
	}
	if (keylen != crypto_aead_xchacha20poly1305_ietf_KEYBYTES) {
		lua_pushnil(L);
		lua_pushstring(L, "Invalid key size");
		return 2;
	}
	unsigned char ciphertext[msglen + crypto_aead_xchacha20poly1305_ietf_ABYTES];
	unsigned long long ciphertextlen;
	crypto_aead_xchacha20poly1305_ietf_encrypt(ciphertext, &ciphertextlen, msg, msglen, ad, adlen, NULL, nonce, key);
	lua_pushlstring(L, (char*)ciphertext, ciphertextlen);
	return 1;
}


static int ls_aead_decrypt(lua_State *L) {
	size_t ciphertextlen, adlen, noncelen, keylen;
	const unsigned char *ciphertext = luaL_checklstring(L, 1, &ciphertextlen);
	const unsigned char *ad = luaL_checklstring(L, 2, &adlen);
	const unsigned char *nonce = luaL_checklstring(L, 3, &noncelen);
	const unsigned char *key = luaL_checklstring(L, 4, &keylen);
	unsigned char decrypted[ciphertextlen];
	unsigned long long decryptedlen;
	if (crypto_aead_xchacha20poly1305_ietf_decrypt(decrypted, &decryptedlen, NULL, ciphertext, ciphertextlen, ad, adlen, nonce, key) != 0) {
		lua_pushnil(L);
		lua_pushstring(L, "Message forged");
		return 2;
	}
	lua_pushlstring(L, (char*)decrypted, decryptedlen);
	return 1;
}


static int ls_sign_detached(lua_State *L) {
	size_t msglen, sklen;
	const unsigned char *msg = luaL_checklstring(L, 1, &msglen);
	const unsigned char *sk = luaL_checklstring(L, 2, &sklen);
	if (sklen != crypto_sign_SECRETKEYBYTES) {
		lua_pushnil(L);
		lua_pushstring(L, "Invalid secret key size");
		return 2;
	}
	unsigned char sig[crypto_sign_BYTES];
	crypto_sign_detached(sig, NULL, msg, msglen, sk);
	lua_pushlstring(L, (char*)sig, crypto_sign_BYTES);
	return 1;
}


static int ls_sign_verify_detached(lua_State *L) {
	size_t msglen, siglen, pklen;
	const unsigned char *msg = luaL_checklstring(L, 1, &msglen);
	const unsigned char *sig = luaL_checklstring(L, 2, &siglen);
	const unsigned char *pk = luaL_checklstring(L, 3, &pklen);
	if (pklen != crypto_sign_PUBLICKEYBYTES) {
		lua_pushnil(L);
		lua_pushstring(L, "Invalid public key size");
		return 2;
	}
	if (crypto_sign_verify_detached(sig, msg, msglen, pk) != 0) {
		lua_pushnil(L);
		lua_pushstring(L, "Incorrect signature");
		return 2;
	}
	lua_pushlstring(L, (char*)msg, msglen);
	return 1;
}


static const struct luaL_Reg luasodiumlib[] = {
	{"sodium_version", ls_sodium_version},
	{"randombytes", ls_randombytes},
	{"sign_keypair", ls_sign_keypair},
	{"generichash", ls_generichash},
	{"aead_encrypt", ls_aead_encrypt},
	{"aead_decrypt", ls_aead_decrypt},
	{"sign_detached", ls_sign_detached},
	{"sign_verify_detached", ls_sign_verify_detached},
	{NULL, NULL},
};


LUALIB_API int luaopen_luasodium(lua_State *L) {
	if (sodium_init() < 0) {
		lua_pushstring(L, "Failed to initialise libsodium");
		return lua_error(L);
	}
	
	luaL_register(L, "luasodium", luasodiumlib);

	lua_pushliteral(L, "VERSION");
	lua_pushliteral(L, LUASODIUM_VERSION);
	lua_settable(L, -3);

	lua_pushliteral(L, "SYMMETRIC_KEYBYTES");
	lua_pushnumber(L, crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
	lua_settable(L, -3);

	lua_pushliteral(L, "SYMMETRIC_NONCEBYTES");
	lua_pushnumber(L, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
	lua_settable(L, -3);

	lua_pushliteral(L, "SIGN_PUBLICKEYBYTES");
	lua_pushnumber(L, crypto_sign_PUBLICKEYBYTES);
	lua_settable(L, -3);

	lua_pushliteral(L, "SIGN_SECRETKEYBYTES");
	lua_pushnumber(L, crypto_sign_SECRETKEYBYTES);
	lua_settable(L, -3);

	lua_pushliteral(L, "SIGN_BYTES");
	lua_pushnumber(L, crypto_sign_BYTES);
	lua_settable(L, -3);

	return 1;
}
