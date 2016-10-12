package io.pivotal.security.controller.v1;

import com.greghaskins.spectrum.Spectrum;
import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.entity.NamedSecret;
import io.pivotal.security.mapper.RequestTranslator;
import io.pivotal.security.view.ParameterizedValidationException;
import io.pivotal.security.view.SecretKind;
import org.mockito.Mock;

import java.util.function.Function;
import java.util.function.Supplier;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.itThrowsWithMessage;
import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.eq;
import static org.mockito.Matchers.isA;
import static org.mockito.Mockito.verify;

public class AbstractNamedSecretHandlerTestingUtil {

  @Mock
  DocumentContext documentContext;

  RequestTranslator expectedTranslator;

  Function<NamedSecret, NamedSecret> mapFunction;

  protected Spectrum.Block behavesLikeMapper(Supplier<SecretKindMappingFactory> subject, Supplier<RequestTranslator> translatorSupplier, SecretKind secretKind, Class<? extends NamedSecret> clazz, NamedSecret mistypedSecret, NamedSecret existingEntity) {
    return () -> {
      beforeEach(() -> {
        mapFunction = secretKind.map(subject.get().make("secret-path", documentContext));
        expectedTranslator = translatorSupplier.get();
      });

      itThrowsWithMessage("checks the type", ParameterizedValidationException.class, "error.type_mismatch", () -> {
        mapFunction.apply(mistypedSecret);
      });

      it("creates the secret", () -> {
        NamedSecret namedSecret = mapFunction.apply(null);
        verify(expectedTranslator).populateEntityFromJson(isA(clazz), eq(documentContext));
        assertThat(namedSecret, instanceOf(clazz));
        assertThat(namedSecret.getName(), equalTo("secret-path"));
      });

      it("updates the secret", () -> {
        NamedSecret namedSecret = mapFunction.apply(existingEntity);
        verify(expectedTranslator).populateEntityFromJson(existingEntity, documentContext);
        assertThat(namedSecret, sameInstance(existingEntity));
      });
    };
  }
}
