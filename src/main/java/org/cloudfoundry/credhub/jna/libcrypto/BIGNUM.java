package org.cloudfoundry.credhub.jna.libcrypto;

import java.util.Arrays;
import java.util.List;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;

public class BIGNUM extends Structure {

  public Pointer dp;
  public int top;
  public int dmax;
  public int neg;

  public BIGNUM(final Pointer p) {
    super(p);
  }

  @Override
  protected List getFieldOrder() {
    return Arrays.asList("dp", "top", "dmax", "neg");
  }

  public static class ByReference extends BIGNUM implements Structure.ByReference {

    public ByReference(final Pointer p) {
      super(p);
    }
  }
}
