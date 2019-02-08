package org.cloudfoundry.credhub.exceptions;

import java.util.List;
import java.util.stream.Collectors;

import javax.validation.ValidationException;

import com.google.common.collect.Lists;

public class ParameterizedValidationException extends ValidationException {

  private final List<Object> parameters;

  public ParameterizedValidationException(final String messageCode) {
    this(messageCode, new Object[]{});
  }

  public ParameterizedValidationException(final String messageCode, final String parameter) {
    this(messageCode, new String[]{parameter});
  }

  public ParameterizedValidationException(final String messageCode, final Object[] parameters) {
    super(messageCode);

    this.parameters = Lists.newArrayList(parameters)
      .stream()
      .map(ParameterizedValidationException::scrubSpecialCharacter)
      .collect(Collectors.toList());
  }

  private static Object scrubSpecialCharacter(final Object raw) {
    if (raw instanceof String) {
      return ((String) raw).replace("$[", "").replace("][", ".").replace("]", "").replace("'", "");
    } else {
      return raw;
    }
  }

  public Object[] getParameters() {
    return parameters.toArray();
  }
}
