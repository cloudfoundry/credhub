package org.cloudfoundry.credhub.config

import org.cloudfoundry.credhub.utils.ResourceReader
import org.cloudfoundry.credhub.utils.VersionProvider
import org.hamcrest.CoreMatchers.equalTo
import org.junit.Assert.assertThat
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4
import org.mockito.Mockito.mock
import org.mockito.Mockito.`when`

@RunWith(JUnit4::class)
class VersionProviderTest {
    @Test
    @Throws(Exception::class)
    fun currentVersion_returnsTheCurrentVersion() {
        val resourceReader = mock(ResourceReader::class.java)
        `when`(resourceReader.readFileToString("version")).thenReturn("test version")

        val subject = VersionProvider(resourceReader)

        assertThat(subject.currentVersion(), equalTo("test version"))
    }

    @Test
    @Throws(Exception::class)
    fun currentVersion_whenTheVersionHasExtraneousWhitespace_trimsTheWhitespace() {
        val resourceReader = mock(ResourceReader::class.java)
        `when`(resourceReader.readFileToString("version")).thenReturn("   test version   ")

        val subject = VersionProvider(resourceReader)

        assertThat(subject.currentVersion(), equalTo("test version"))
    }
}
