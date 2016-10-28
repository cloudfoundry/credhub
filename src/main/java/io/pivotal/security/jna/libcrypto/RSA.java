package io.pivotal.security.jna.libcrypto;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;

import java.util.Arrays;
import java.util.List;

public class RSA extends Structure {
  public static class ByReference extends RSA implements Structure.ByReference {
    public ByReference(Pointer p) {
      super(p);
    }
  }

  public int pad;
  public long version;
  public Pointer RSA_METHOD;
  public Pointer ENGINE;
  public Pointer n;
  public Pointer e;
  public Pointer d;
  public Pointer p;
  public Pointer q;
  public Pointer dmp1;
  public Pointer dmq1;
  public Pointer iqmp;

  public RSA(Pointer p) {
    super(p);
  }

  @Override
  protected List getFieldOrder() {
    return Arrays.asList("pad", "version", "RSA_METHOD", "ENGINE", "n", "e", "d", "p", "q", "dmp1", "dmq1", "iqmp");
  }
}
