package org.cloudfoundry.credhub.domain;

import org.cloudfoundry.credhub.entity.RsaCredentialVersionData;
import org.cloudfoundry.credhub.requests.RsaGenerationParameters;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class RsaCredentialVersionTest {

  private RsaCredentialVersion subject;
  private RsaCredentialVersionData credentialVersionData;

  @BeforeEach
  public void setUp() {
    credentialVersionData = mock(RsaCredentialVersionData.class);
    subject = new RsaCredentialVersion(credentialVersionData);
  }

  @Test
  public void matchesGenerationParameters_returnsFalseWhenParametersDontMatch() {
    when(credentialVersionData.getKeyLength()).thenReturn(2048);

    final RsaGenerationParameters generationParameters = new RsaGenerationParameters();
    generationParameters.setKeyLength(4096);

    assertThat(subject.matchesGenerationParameters(generationParameters), equalTo(false));
  }

  @Test
  public void matchesGenerationParameters_returnsTrueWhenParametersMatch() {
    when(credentialVersionData.getKeyLength()).thenReturn(4096);

    final RsaGenerationParameters generationParameters = new RsaGenerationParameters();
    generationParameters.setKeyLength(4096);

    assertThat(subject.matchesGenerationParameters(generationParameters), equalTo(true));
  }

}
