package io.pivotal.security.mapper;

import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.controller.v1.RequestParameters;
import io.pivotal.security.generator.SecretGenerator;
import io.pivotal.security.view.Secret;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.hamcrest.CoreMatchers.sameInstance;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.when;

public class RequestTranslatorWithGenerationTest {

  @Mock
  SecretGenerator secretGenerator;
  @Mock
  SecretGeneratorRequestTranslator requestTranslator;
  @Mock
  DocumentContext documentContext;
  @Mock
  Secret secret;
  @Mock
  RequestParameters requestParameters;

  @Before
  public void setUp() throws Exception {
    MockitoAnnotations.initMocks(this);
  }

  @Test
  public void generatesRequestAndThenGeneratesSecret() {
    RequestTranslatorWithGeneration subject = new RequestTranslatorWithGeneration(secretGenerator, requestTranslator);

    when(requestTranslator.validRequestParameters(documentContext)).thenReturn(requestParameters);
    when(secretGenerator.generateSecret(requestParameters)).thenReturn(secret);

    assertThat(subject.createSecretFromJson(documentContext), sameInstance(secret));
  }
}