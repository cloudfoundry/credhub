package io.pivotal.security.jna.libcrypto;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;

public interface Crypto extends Library {
  Crypto INSTANCE = (Crypto) Native.loadLibrary("crypto", Crypto.class);

  long RSA_F4 = 0x10001L;

  BIGNUM.ByReference BN_new();
  void BN_free(BIGNUM.ByReference bn);
  int BN_set_word(BIGNUM.ByReference a, long w);
  RSA.ByReference RSA_new();
  void RSA_free(RSA.ByReference r);
  int RSA_generate_key_ex(RSA.ByReference rsa, int bits, BIGNUM.ByReference e, Pointer cb);
  String BN_bn2hex(BIGNUM.ByReference a);
}
