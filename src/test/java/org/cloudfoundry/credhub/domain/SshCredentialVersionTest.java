package org.cloudfoundry.credhub.domain;

import org.cloudfoundry.credhub.entity.SshCredentialVersionData;
import org.cloudfoundry.credhub.request.SshGenerationParameters;
import org.cloudfoundry.credhub.util.SshPublicKeyParser;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(JUnit4.class)
public class SshCredentialVersionTest {

  private SshCredentialVersion subject;
  private SshPublicKeyParser sshPublicKeyParser;

  @Before
  public void setUp() {
    sshPublicKeyParser = mock(SshPublicKeyParser.class);
    SshCredentialVersionData credentialVersionData = mock(SshCredentialVersionData.class);

    subject = new SshCredentialVersion(credentialVersionData, sshPublicKeyParser);
  }

  @Test
  public void matchesGenerationParameters_returnsFalseWhenParametersDontMatch() {
    SshGenerationParameters generationParameters = new SshGenerationParameters();
    generationParameters.setKeyLength(4096);

    assertThat(subject.matchesGenerationParameters(generationParameters), equalTo(false));
  }

  @Test
  public void matchesGenerationParameters_returnsTrueWhenParametersMatch() {
    when(sshPublicKeyParser.getKeyLength()).thenReturn(4096);
    when(sshPublicKeyParser.getComment()).thenReturn("some comment");

    SshGenerationParameters generationParameters = new SshGenerationParameters();
    generationParameters.setKeyLength(4096);
    generationParameters.setSshComment("some comment");

    assertThat(subject.matchesGenerationParameters(generationParameters), equalTo(true));
  }

}
