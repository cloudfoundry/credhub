package io.pivotal.security.interceptor;

import io.pivotal.security.controller.v1.CaController;
import io.pivotal.security.controller.v1.SecretsController;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.method.HandlerMethod;

import java.lang.reflect.Method;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@Component
public class OperationNameResolver {

  static Map<Class, Map<String, String>> CLASS_METHOD_TO_OPERATION;

  static {
    Map<String, String> apiMethodToOperation = new HashMap<>();
    apiMethodToOperation.put("get", "credential_access");
    apiMethodToOperation.put("delete", "credential_delete");
    apiMethodToOperation.put("set", "credential_update");
    apiMethodToOperation.put("generate", "credential_update");
    apiMethodToOperation = Collections.unmodifiableMap(apiMethodToOperation);

    OperationNameResolver.CLASS_METHOD_TO_OPERATION = new HashMap<>();
    OperationNameResolver.CLASS_METHOD_TO_OPERATION.put(SecretsController.class,apiMethodToOperation);
    OperationNameResolver.CLASS_METHOD_TO_OPERATION.put(CaController.class, apiMethodToOperation);
  }

  public String getOperationFromMethod(Object handler) {
    if (handler instanceof HandlerMethod) {

      HandlerMethod controllerWrapper = (HandlerMethod) handler;
      Object controller = controllerWrapper.getBean();
      if (controller instanceof SecretsController || controller instanceof CaController) {
        Method method = controllerWrapper.getMethod();
        if (method.isAnnotationPresent(RequestMapping.class)) {
          String name = method.getName();
          Map<String, String> map = CLASS_METHOD_TO_OPERATION.get(SecretsController.class);
          String result = map.get(name);
          if (result != null) {
            return result;
          }
        }
      }
    }
    return "unknown";
  }
}
