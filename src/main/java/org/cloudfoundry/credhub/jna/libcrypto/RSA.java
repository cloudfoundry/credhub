package org.cloudfoundry.credhub.jna.libcrypto;

import java.util.Arrays;
import java.util.List;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;

public class RSA extends Structure {

  public int pad;
  public long version;
  public Pointer rsaMethod;
  public Pointer engine;
  public Pointer np;
  public Pointer ep;
  public Pointer dp;
  public Pointer pp;
  public Pointer qp;
  public Pointer dmp1;
  public Pointer dmq1;
  public Pointer iqmp;

  public RSA(final Pointer pp) {
    super(pp);
  }

  @Override
  protected List getFieldOrder() {
    return Arrays
      .asList("pad", "version", "rsaMethod", "engine", "np", "ep", "dp", "pp",
        "qp", "dmp1", "dmq1", "iqmp");
  }

  public static class ByReference extends RSA implements Structure.ByReference {

    public ByReference(final Pointer p) {
      super(p);
    }
  }
}
