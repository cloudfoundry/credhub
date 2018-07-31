package org.cloudfoundry.credhub.request;

public abstract class GenerationParameters {
  private String mode;

  public void validate(){}

  public String getMode(){
    return mode;
  }

  public void setMode(String mode){
    this.mode = mode;
  }
}
