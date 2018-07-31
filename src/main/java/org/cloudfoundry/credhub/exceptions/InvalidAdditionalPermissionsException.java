package org.cloudfoundry.credhub.exceptions;

public class InvalidAdditionalPermissionsException extends RuntimeException{
  public InvalidAdditionalPermissionsException(String field){
    this.field = field;
  }

  private String field;

  public String getField() {
    return field;
  }
}
