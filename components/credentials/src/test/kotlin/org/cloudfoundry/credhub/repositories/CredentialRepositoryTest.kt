package org.cloudfoundry.credhub.repositories

import org.cloudfoundry.credhub.CredhubTestApp
import org.cloudfoundry.credhub.entities.Credential
import org.cloudfoundry.credhub.utils.DatabaseProfileResolver
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.context.ActiveProfiles
import org.springframework.test.context.junit4.SpringRunner

@RunWith(SpringRunner::class)
@ActiveProfiles(value = ["unit-test"], resolver = DatabaseProfileResolver::class)
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@SpringBootTest(classes = [CredhubTestApp::class])
class CredentialRepositoryTest {
    @Autowired
    private lateinit var subject: CredentialRepository

    @Test
    fun `findAllCertificates returns an empty list when there are no certificates in the db`() {
        val certs = subject.findAllCertificates()
        assertEquals(certs, emptyList<Credential>())
    }
}
