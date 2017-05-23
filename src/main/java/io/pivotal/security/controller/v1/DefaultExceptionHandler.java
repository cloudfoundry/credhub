package io.pivotal.security.controller.v1;

import org.springframework.boot.autoconfigure.web.DefaultErrorAttributes;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.Map;
import javax.servlet.http.HttpServletRequest;

@ControllerAdvice
public class DefaultExceptionHandler {
  @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
  @ExceptionHandler(Exception.class)
  @ResponseBody
  public Map<String, Object> handleGeneralException(HttpServletRequest request, Exception exception)
      throws Exception {
    if (AnnotationUtils.findAnnotation(exception.getClass(), ResponseStatus.class) != null) {
      throw exception;
    }

    RequestAttributes requestAttributes = new ServletRequestAttributes(request);

    return new DefaultErrorAttributes()
        .getErrorAttributes(requestAttributes, false);
  }
}
