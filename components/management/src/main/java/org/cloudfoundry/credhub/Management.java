package org.cloudfoundry.credhub;

public class Management {
  private boolean readOnlyMode;

  public Management() {
    super();
    // no arg constructor required by Jackson
  }

  public Management(final Boolean readOnlyMode) {
    super();
    this.readOnlyMode = readOnlyMode;
  }

  public boolean isReadOnlyMode() {
    return readOnlyMode;
  }

  public void setReadOnlyMode(final boolean readOnlyMode) {
    this.readOnlyMode = readOnlyMode;
  }

  @Override
  public String toString() {
    return "isReadOnly: " + isReadOnlyMode();
  }
}
