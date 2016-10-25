package io.pivotal.security.jna.libcrypto;

import com.sun.jna.Native;
import com.sun.jna.Pointer;

class Crypto {
  static {
    Native.register("crypto");
  }

  static final long RSA_F4 = 0x10001L;
  static final int RSA_NO_PADDING = 3;

  public native static BIGNUM.ByReference BN_new();
  public native static int BN_set_word(BIGNUM.ByReference a, long w);
  public native static int BN_mul_word(BIGNUM.ByReference a, long w);
  public native static void BN_set_negative(BIGNUM.ByReference b, int n);
  public native static Pointer BN_bn2hex(BIGNUM.ByReference a);
  public native static void BN_free(BIGNUM.ByReference bn);

  public native static RSA.ByReference RSA_new();
  public native static int RSA_generate_key_ex(RSA.ByReference rsa, int bits, BIGNUM.ByReference e, Pointer cb);
  public native static int RSA_size(RSA.ByReference rsa);
  public native static int RSA_private_encrypt(int flen, byte[] from, byte[] to, RSA.ByReference rsa, int padding);
  public native static void RSA_free(RSA.ByReference r);

  public native static void CRYPTO_free(Pointer ptr);

  public native static long ERR_get_error();
  public native static void ERR_error_string_n(long e, byte[] buf, int len);
}
