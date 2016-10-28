package io.pivotal.security.controller.v1;

import com.greghaskins.spectrum.Spectrum;
import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.entity.NamedValueSecret;
import io.pivotal.security.mapper.RequestTranslator;
import org.junit.Assert;
import org.junit.runner.RunWith;
import org.mockito.Mock;

import java.util.function.Function;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.injectMocks;
import static org.hamcrest.CoreMatchers.sameInstance;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(Spectrum.class)
public class SecretKindMappingFactoryTest {

  @Mock
  private RequestTranslator<NamedValueSecret> requestTranslator;

  @Mock
  private DocumentContext parsed;

  {
    SecretKindMappingFactory subject = (secretPath, parsed) -> null;

    beforeEach(injectMocks(this));

    it("creates a new object", () -> {
      NamedValueSecret existingObject = new NamedValueSecret("name");

      Function<String, NamedValueSecret> constructor = mock(Function.class);
      NamedValueSecret constructedObject = new NamedValueSecret("name");
      when(constructor.apply("name")).thenReturn(constructedObject);

      Assert.assertThat(subject.processSecret(constructor, "name", requestTranslator, parsed), sameInstance(constructedObject));
      verify(constructor).apply("name");

      verify(requestTranslator).populateEntityFromJson(constructedObject, parsed);
    });

    describe("validation", () -> {
      it("calls the request translator to validate JSON keys", () -> {
        subject.processSecret(NamedValueSecret::new, "name", requestTranslator, parsed);
        verify(requestTranslator).validateJsonKeys(parsed);
      });

      it("calls the request translator to validate path", () -> {
        subject.processSecret(NamedValueSecret::new, "/dont//do//this/", requestTranslator, parsed);
        verify(requestTranslator).validatePathName(any(String.class));
      });
    });

  }
}
