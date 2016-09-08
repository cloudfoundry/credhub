package io.pivotal.security.view;

import javax.validation.ValidationException;
import java.util.List;

import static com.google.common.collect.Lists.newArrayList;

public class ParameterizedValidationException extends ValidationException {
  List<Object> paramList = newArrayList();

  public ParameterizedValidationException(String messageCode, List<Object> parameters) {
    this(messageCode);
    this.paramList = parameters;
  }

  public ParameterizedValidationException(String messageCode) {
    super(messageCode);
  }

  public Object[] getParameters() {
    return this.paramList.toArray();
  }
}
