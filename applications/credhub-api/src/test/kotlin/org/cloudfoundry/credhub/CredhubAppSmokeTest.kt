package org.cloudfoundry.credhub

import org.cloudfoundry.credhub.utils.DatabaseProfileResolver
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.context.ActiveProfiles
import org.springframework.test.context.junit.jupiter.SpringExtension
import org.springframework.transaction.annotation.Transactional

@ExtendWith(SpringExtension::class)
@ActiveProfiles(value = ["unit-test"], resolver = DatabaseProfileResolver::class)
@SpringBootTest(classes = arrayOf(CredHubApp::class))
@Transactional
class CredhubAppSmokeTest {
    @Test
    fun contextLoads() {
    }
}
