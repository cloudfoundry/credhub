package io.pivotal.security.jna.libcrypto;

import com.sun.jna.Native;
import com.sun.jna.Pointer;

public class Crypto {
  static {
    Native.register("crypto");
  }

  public static final long RSA_F4 = 0x10001L;

  public native static BIGNUM.ByReference BN_new();
  public native static void BN_free(BIGNUM.ByReference bn);
  public native static int BN_set_word(BIGNUM.ByReference a, long w);
  public native static RSA.ByReference RSA_new();
  public native static void RSA_free(RSA.ByReference r);
  public native static int RSA_generate_key_ex(RSA.ByReference rsa, int bits, BIGNUM.ByReference e, Pointer cb);
  public native static Pointer BN_bn2hex(BIGNUM.ByReference a);
  public native static void CRYPTO_free(Pointer ptr);
}
