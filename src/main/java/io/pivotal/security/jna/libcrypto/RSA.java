package io.pivotal.security.jna.libcrypto;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;

import java.util.Arrays;
import java.util.List;

public class RSA extends Structure {
  public static class ByReference extends RSA implements Structure.ByReference {}

  public int pad;
  public long version;
  public Pointer RSA_METHOD;
  public Pointer ENGINE;
  public BIGNUM.ByReference n;
  public BIGNUM.ByReference e;
  public BIGNUM.ByReference d;
  public BIGNUM.ByReference p;
  public BIGNUM.ByReference q;
  public BIGNUM.ByReference dmp1;
  public BIGNUM.ByReference dmq1;
  public BIGNUM.ByReference iqmp;

  @Override
  protected List getFieldOrder() {
    return Arrays.asList("pad", "version", "RSA_METHOD", "ENGINE", "n", "e", "d", "p", "q", "dmp1", "dmq1", "iqmp");
  }
}
