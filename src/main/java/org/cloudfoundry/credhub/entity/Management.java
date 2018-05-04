package org.cloudfoundry.credhub.entity;

public class Management {
  private boolean readOnlyMode;

  public Management(){
    // no arg constructor required by Jackson
  }

  public Management(Boolean readOnlyMode){
    this.readOnlyMode = readOnlyMode;
  }

  public boolean isReadOnlyMode() {
    return readOnlyMode;
  }

  public void setReadOnlyMode(boolean readOnlyMode) {
    this.readOnlyMode = readOnlyMode;
  }

  @Override
  public String toString(){
    return "isReadOnly: " + isReadOnlyMode();
  }
}
