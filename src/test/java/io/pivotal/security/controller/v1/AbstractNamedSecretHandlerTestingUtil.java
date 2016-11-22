package io.pivotal.security.controller.v1;

import com.greghaskins.spectrum.Spectrum;
import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.entity.NamedSecret;
import io.pivotal.security.mapper.RequestTranslator;
import io.pivotal.security.util.CheckedFunction;
import io.pivotal.security.view.SecretKind;
import org.mockito.Mock;
import org.springframework.boot.test.mock.mockito.MockBean;

import java.security.NoSuchAlgorithmException;
import java.util.function.Supplier;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.it;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.sameInstance;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.eq;
import static org.mockito.Matchers.isA;
import static org.mockito.Matchers.same;
import static org.mockito.Mockito.verify;

public abstract class AbstractNamedSecretHandlerTestingUtil {

  @Mock
  DocumentContext documentContext;

  RequestTranslator expectedTranslator;

  CheckedFunction<NamedSecret, NoSuchAlgorithmException> mapFunction;

  protected abstract void verifyExistingSecretCopying(NamedSecret mockExistingSecret);

  protected Spectrum.Block behavesLikeMapper(
      Supplier<SecretKindMappingFactory> subject,
      Supplier<RequestTranslator> translatorSupplier,
      SecretKind secretKind,
      Class<? extends NamedSecret> clazz,
      NamedSecret existingEntity,
      NamedSecret mockExistingSecret) {
    return () -> {
      beforeEach(() -> {
        mapFunction = secretKind.lift(subject.get().make("secret-path", documentContext));
        expectedTranslator = translatorSupplier.get();
      });

      it("creates the secret", () -> {
        NamedSecret namedSecret = mapFunction.apply(null);
        verify(expectedTranslator).populateEntityFromJson(isA(clazz), eq(documentContext));
        assertThat(namedSecret, instanceOf(clazz));
        assertThat(namedSecret.getName(), equalTo("secret-path"));
      });

      it("updates the secret", () -> {
        NamedSecret namedSecret = mapFunction.apply(existingEntity);
        verify(expectedTranslator).populateEntityFromJson(same(namedSecret), same(documentContext));
        assertThat(namedSecret, not(sameInstance(existingEntity)));
        assertThat(namedSecret, instanceOf(clazz));
      });

      it("pass the existing secret through only when doing generation, not set", () -> {
        mapFunction.apply(mockExistingSecret);
        verifyExistingSecretCopying(mockExistingSecret);
      });
    };
  }
}
