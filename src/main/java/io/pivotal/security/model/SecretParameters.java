package io.pivotal.security.model;


public class SecretParameters {

  private int length;

  public int getLength() {
    return length;
  }

  public void setLength(int length) {
    this.length = length;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;

    SecretParameters that = (SecretParameters) o;

    return length == that.length;
  }

  @Override
  public int hashCode() {
    return length;
  }

}
