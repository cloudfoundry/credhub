package org.cloudfoundry.credhub.request;

import org.cloudfoundry.credhub.constants.CredentialWriteMode;

public abstract class GenerationParameters {
  private CredentialWriteMode mode;

  public void validate(){}

  public CredentialWriteMode getMode(){
    return mode;
  }

  public void setMode(CredentialWriteMode mode){
    this.mode = mode;
  }
}
