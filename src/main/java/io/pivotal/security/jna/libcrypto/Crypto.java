package io.pivotal.security.jna.libcrypto;

import com.sun.jna.Native;
import com.sun.jna.Pointer;

class Crypto {
  static {
    Native.register("crypto");
  }

  static final long RSA_F4 = 0x10001L;
  static final int RSA_NO_PADDING = 3;

  public native static Pointer BN_new();
  public native static int BN_set_word(Pointer a, long w);
  public native static int BN_mul_word(Pointer a, long w);
  public native static void BN_set_negative(Pointer b, int n);
  public native static Pointer BN_bn2hex(Pointer a);
  public native static void BN_free(Pointer bn);

  public native static Pointer RSA_new();
  public native static int RSA_generate_key_ex(Pointer rsa, int bits, Pointer e, Pointer cb);
  public native static int RSA_size(Pointer rsa);
  public native static int RSA_private_encrypt(int flen, byte[] from, byte[] to, Pointer rsa, int padding);
  public native static void RSA_free(Pointer r);

  public native static void CRYPTO_free(Pointer ptr);

  public native static long ERR_get_error();
  public native static void ERR_error_string_n(long e, byte[] buf, int len);
}
