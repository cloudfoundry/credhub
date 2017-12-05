package org.cloudfoundry.credhub.jna.libcrypto;

import com.sun.jna.Native;
import com.sun.jna.Pointer;

class Crypto {

  static final long RSA_F4 = 0x10001L;
  static final int RSA_PKCS1_PADDING = 1;
  static final int RSA_SSLV23_PADDING = 2;
  static final int RSA_NO_PADDING = 3;

  static {
    Native.register("crypto");
  }

  public static native Pointer BN_new();

  public static native int BN_set_word(Pointer a, long w);

  public static native int BN_mul_word(Pointer a, long w);

  public static native void BN_set_negative(Pointer b, int n);

  public static native Pointer BN_bn2hex(Pointer a);

  public static native void BN_free(Pointer bn);

  public static native Pointer RSA_new();

  public static native int RSA_generate_key_ex(Pointer rsa, int bits, Pointer e, Pointer cb);

  public static native int RSA_size(Pointer rsa);

  public static native int RSA_private_encrypt(int flen, byte[] from, byte[] to, Pointer rsa,
      int padding);

  public static native void RSA_free(Pointer r);

  public static native void CRYPTO_free(Pointer ptr);

  public static native long ERR_get_error();

  public static native void ERR_error_string_n(long e, byte[] buf, int len);

  public static native void RAND_seed(Pointer buf, int num);
}
