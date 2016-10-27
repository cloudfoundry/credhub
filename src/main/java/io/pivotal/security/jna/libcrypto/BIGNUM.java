package io.pivotal.security.jna.libcrypto;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;

import java.util.Arrays;
import java.util.List;

public class BIGNUM extends Structure {
  public static class ByReference extends BIGNUM implements Structure.ByReference {}

  public Pointer d;
  public int top;
  public int dmax;
  public int neg;

  @Override
  protected List getFieldOrder() {
    return Arrays.asList("d", "top", "dmax", "neg");
  }
}
