package org.cloudfoundry.credhub.config;

import org.cloudfoundry.credhub.util.ResourceReader;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(JUnit4.class)
public class VersionProviderTest {
  @Test
  public void currentVersion_returnsTheCurrentVersion() throws Exception {
    final ResourceReader resourceReader = mock(ResourceReader.class);
    when(resourceReader.readFileToString("version")).thenReturn("test version");

    final VersionProvider subject = new VersionProvider(resourceReader);

    assertThat(subject.currentVersion(), equalTo("test version"));
  }

  @Test
  public void currentVersion_whenTheVersionHasExtraneousWhitespace_trimsTheWhitespace() throws Exception {
    final ResourceReader resourceReader = mock(ResourceReader.class);
    when(resourceReader.readFileToString("version")).thenReturn("   test version   ");

    final VersionProvider subject = new VersionProvider(resourceReader);

    assertThat(subject.currentVersion(), equalTo("test version"));
  }
}
