package io.pivotal.security.mapper;

import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.generator.SecretGenerator;
import io.pivotal.security.model.GeneratorRequest;
import io.pivotal.security.model.Secret;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.hamcrest.CoreMatchers.sameInstance;
import static org.junit.Assert.*;
import static org.mockito.Mockito.when;

public class RequestTranslatorWithGenerationTest {
  @Mock SecretGenerator secretGenerator;
  @Mock SecretGeneratorRequestTranslator requestTranslator;
  @Mock DocumentContext documentContext;
  @Mock GeneratorRequest generatorRequest;
  @Mock Secret secret;

  @Before
  public void setUp() throws Exception {
    MockitoAnnotations.initMocks(this);
  }

  @Test
  public void generatesRequestAndThenGeneratesSecret() {
    Object generatorRequestParameters = new Object();
    RequestTranslatorWithGeneration subject = new RequestTranslatorWithGeneration(secretGenerator, requestTranslator);

    when(generatorRequest.getParameters()).thenReturn(generatorRequestParameters);
    when(requestTranslator.validGeneratorRequest(documentContext)).thenReturn(generatorRequest);
    when(secretGenerator.generateSecret(generatorRequestParameters)).thenReturn(secret);

    assertThat(subject.createSecretFromJson(documentContext), sameInstance(secret));
  }
}