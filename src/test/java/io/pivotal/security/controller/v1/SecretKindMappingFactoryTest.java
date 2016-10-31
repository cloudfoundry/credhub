package io.pivotal.security.controller.v1;

import com.greghaskins.spectrum.Spectrum;
import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.entity.NamedPasswordSecret;
import io.pivotal.security.mapper.RequestTranslator;
import org.junit.Assert;
import org.junit.runner.RunWith;
import org.mockito.Mock;

import java.util.function.Function;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.injectMocks;
import static org.hamcrest.Matchers.sameInstance;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(Spectrum.class)
public class SecretKindMappingFactoryTest {

  @Mock
  private RequestTranslator<NamedPasswordSecret> requestTranslator;

  @Mock
  private DocumentContext parsed;

  {
    SecretKindMappingFactory subject = (secretPath, parsed) -> null;

    beforeEach(injectMocks(this));

    describe("when there is no existing entity", () -> {
      it("creates a new object", () -> {
        Function<String, NamedPasswordSecret> constructor = mock(Function.class);
        NamedPasswordSecret constructedObject = new NamedPasswordSecret("name");
        when(constructor.apply("name")).thenReturn(constructedObject);

        Assert.assertThat(subject.processSecret(null, constructor, "name", requestTranslator, parsed), sameInstance(constructedObject));
        verify(constructor).apply("name");

        verify(requestTranslator).populateEntityFromJson(constructedObject, parsed);
      });
    });

    describe("when there is an existing entity", () -> {
      it("should create a copy of the original", () -> {
        NamedPasswordSecret existingObject = spy(new NamedPasswordSecret("name"));

        Function<String, NamedPasswordSecret> constructor = mock(Function.class);
        NamedPasswordSecret constructedObject = new NamedPasswordSecret("name");
        when(constructor.apply("name")).thenReturn(constructedObject);

        Assert.assertThat(subject.processSecret(existingObject, constructor, "name", requestTranslator, parsed), sameInstance(constructedObject));
        verify(constructor).apply("name");

        verify(existingObject).copyInto(constructedObject);
        verify(requestTranslator).populateEntityFromJson(constructedObject, parsed);
      });
    });

    describe("validation", () -> {
      it("calls the request translator to validate JSON keys", () -> {
        subject.processSecret(null, NamedPasswordSecret::new, "name", requestTranslator, parsed);
        verify(requestTranslator).validateJsonKeys(parsed);
      });

      it("calls the request translator to validate path", () -> {
        subject.processSecret(null, NamedPasswordSecret::new, "/dont//do//this/", requestTranslator, parsed);
        verify(requestTranslator).validatePathName(any(String.class));
      });
    });
  }
}
