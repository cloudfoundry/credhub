package io.pivotal.security.interceptor;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.controller.v1.CaController;
import io.pivotal.security.controller.v1.SecretsController;
import org.hamcrest.CoreMatchers;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.method.HandlerMethod;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
public class OperationNameResolverTest {

  @Autowired
  SecretsController secretsController;

  @Autowired
  CaController caController;

  @Autowired
  OperationNameResolver subject;

  {
    wireAndUnwire(this);

    describe("all api controllers", () -> {
      describe("SecretsController ", () -> {
        it("api methods have audit operation codes", () -> {
          Method[] allMethods = secretsController.getClass().getDeclaredMethods();
          List<String> operations = Arrays.stream(allMethods)
              .filter(method -> method.isAnnotationPresent(RequestMapping.class))
              .map(method -> new HandlerMethod(secretsController, method))
              .map(handlerMethod -> subject.getOperationFromMethod(handlerMethod))
              .collect(Collectors.toList());

          assertThat(operations, containsInAnyOrder(
              "credential_access",
              "credential_delete",
              "credential_update",
              "credential_update"
          ));
        });
      });
      describe("CaController ", () -> {
        it("api methods have audit operation codes", () -> {
          Method[] allMethods = caController.getClass().getDeclaredMethods();
          List<String> operations = Arrays.stream(allMethods)
              .filter(method -> method.isAnnotationPresent(RequestMapping.class))
              .map(method -> new HandlerMethod(caController, method))
              .map(handlerMethod -> subject.getOperationFromMethod(handlerMethod))
              .collect(Collectors.toList());

          assertThat(operations, containsInAnyOrder(
              "credential_access",
              "credential_update",
              "credential_update"
          ));
        });
      });
    });

  }
}