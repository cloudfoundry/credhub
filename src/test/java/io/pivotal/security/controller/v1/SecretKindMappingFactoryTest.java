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
  private DocumentContext parsedRequest;

  {
    SecretKindMappingFactory subject = (secretPath, parsed) -> null;

    beforeEach(injectMocks(this));

    describe("when there is no existing entity", () -> {
      it("creates a new object", () -> {
        Function<String, NamedPasswordSecret> constructor = mock(Function.class);
        NamedPasswordSecret constructedObject = new NamedPasswordSecret("name");
        when(constructor.apply("name")).thenReturn(constructedObject);

        Assert.assertThat(subject.createNewSecret(null, constructor, "name", requestTranslator, parsedRequest), sameInstance(constructedObject));
        verify(constructor).apply("name");

        verify(requestTranslator).populateEntityFromJson(constructedObject, parsedRequest);
      });
    });

    describe("when there is an existing entity", () -> {
      it("should create a copy of the original", () -> {
        NamedPasswordSecret existingObject = spy(new NamedPasswordSecret("name"));

        Function<String, NamedPasswordSecret> constructor = mock(Function.class);
        NamedPasswordSecret constructedObject = new NamedPasswordSecret("name");
        when(constructor.apply("name")).thenReturn(constructedObject);

        Assert.assertThat(subject.createNewSecret(existingObject, constructor, "name", requestTranslator, parsedRequest), sameInstance(constructedObject));
        verify(constructor).apply("name");

        verify(existingObject).copyInto(constructedObject);
        verify(requestTranslator).populateEntityFromJson(constructedObject, parsedRequest);
      });
    });

    describe("validation", () -> {
      it("calls the request translator to validate JSON keys", () -> {
        subject.createNewSecret(null, NamedPasswordSecret::new, "name", requestTranslator, parsedRequest);
        verify(requestTranslator).validateJsonKeys(parsedRequest);
      });

      it("calls the request translator to validate path", () -> {
        subject.createNewSecret(null, NamedPasswordSecret::new, "/dont//do//this/", requestTranslator, parsedRequest);
        verify(requestTranslator).validatePathName(any(String.class));
      });
    });
  }
}
