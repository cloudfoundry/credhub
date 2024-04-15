package org.cloudfoundry.credhub.domain;

import org.cloudfoundry.credhub.entity.SshCredentialVersionData;
import org.cloudfoundry.credhub.requests.SshGenerationParameters;
import org.cloudfoundry.credhub.utils.SshPublicKeyParser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class SshCredentialVersionTest {

  private SshCredentialVersion subject;
  private SshPublicKeyParser sshPublicKeyParser;

  @BeforeEach
  public void setUp() {
    sshPublicKeyParser = mock(SshPublicKeyParser.class);
    final SshCredentialVersionData credentialVersionData = mock(SshCredentialVersionData.class);

    subject = new SshCredentialVersion(credentialVersionData, sshPublicKeyParser);
  }

  @Test
  public void matchesGenerationParameters_returnsFalseWhenParametersDontMatch() {
    final SshGenerationParameters generationParameters = new SshGenerationParameters();
    generationParameters.setKeyLength(4096);

    assertThat(subject.matchesGenerationParameters(generationParameters), equalTo(false));
  }

  @Test
  public void matchesGenerationParameters_returnsTrueWhenParametersMatch() {
    when(sshPublicKeyParser.getKeyLength()).thenReturn(4096);
    when(sshPublicKeyParser.getComment()).thenReturn("some comment");

    final SshGenerationParameters generationParameters = new SshGenerationParameters();
    generationParameters.setKeyLength(4096);
    generationParameters.setSshComment("some comment");

    assertThat(subject.matchesGenerationParameters(generationParameters), equalTo(true));
  }

}
