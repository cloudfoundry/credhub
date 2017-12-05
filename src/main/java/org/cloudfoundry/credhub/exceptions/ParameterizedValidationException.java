package org.cloudfoundry.credhub.exceptions;

import java.util.List;
import java.util.stream.Collectors;
import javax.validation.ValidationException;

import static com.google.common.collect.Lists.newArrayList;

public class ParameterizedValidationException extends ValidationException {

  private final List<Object> parameters;

  public ParameterizedValidationException(String messageCode) {
    this(messageCode, new Object[]{});
  }

  public ParameterizedValidationException(String messageCode, String parameter) {
    this(messageCode, new String[]{parameter});
  }

  public ParameterizedValidationException(String messageCode, Object[] parameters) {
    super(messageCode);

    this.parameters = newArrayList(parameters)
        .stream()
        .map(ParameterizedValidationException::scrubSpecialCharacter)
        .collect(Collectors.toList());
  }

  public Object[] getParameters() {
    return parameters.toArray();
  }

  private static Object scrubSpecialCharacter(Object raw) {
    if (raw instanceof String) {
      return ((String) raw).replace("$[", "").replace("][", ".").replace("]", "").replace("'", "");
    } else {
      return raw;
    }
  }
}
