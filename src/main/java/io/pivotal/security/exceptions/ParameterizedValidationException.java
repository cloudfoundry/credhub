package io.pivotal.security.exceptions;

import javax.validation.ValidationException;
import java.util.List;
import java.util.stream.Collectors;

import static com.google.common.collect.Lists.newArrayList;

public class ParameterizedValidationException extends ValidationException {
  List<String> paramList = newArrayList();

  public ParameterizedValidationException(String messageCode, List<String> parameters) {
    this(messageCode);
    this.paramList = parameters;
  }

  public ParameterizedValidationException(String messageCode, String parameter) {
    this(messageCode);
    this.paramList = newArrayList(parameter);
  }

  public ParameterizedValidationException(String messageCode) {
    super(messageCode);
  }

  public Object[] getParameters() {
    return this.paramList.stream().map(ParameterizedValidationException::scrubSpecialCharacter).collect(Collectors.toList()).toArray();
  }

  private static String scrubSpecialCharacter(String raw) {
      return raw.replace("$[", "").replace("][", ".").replace("]", "").replace("'", "");
  }
}
