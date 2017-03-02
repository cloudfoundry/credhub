package io.pivotal.security.exceptions;

import javax.validation.ValidationException;
import java.util.Arrays;

public class ParameterizedValidationException extends ValidationException {
  String parameter = null;

  public ParameterizedValidationException(String messageCode, String parameter) {
    this(messageCode);
    this.parameter = parameter;
  }

  public ParameterizedValidationException(String messageCode) {
    super(messageCode);
  }

  public String getParameter() {
    return parameter != null ? scrubSpecialCharacter(parameter) : null;
  }

  public Object[] getParameters() {
    String parameter = getParameter();
    return parameter != null ? Arrays.asList(parameter).toArray() : null;
  }

  private static String scrubSpecialCharacter(String raw) {
    return raw.replace("$[", "").replace("][", ".").replace("]", "").replace("'", "");
  }
}
