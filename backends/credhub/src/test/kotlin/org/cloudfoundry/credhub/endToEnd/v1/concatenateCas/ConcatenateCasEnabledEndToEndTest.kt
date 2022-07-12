package org.cloudfoundry.credhub.endToEnd.v1.concatenateCas

import com.jayway.jsonpath.JsonPath
import org.cloudfoundry.credhub.CredhubTestApp
import org.cloudfoundry.credhub.helpers.RequestHelper
import org.cloudfoundry.credhub.utils.AuthConstants.Companion.ALL_PERMISSIONS_TOKEN
import org.cloudfoundry.credhub.utils.BouncyCastleFipsConfigurer
import org.cloudfoundry.credhub.utils.DatabaseProfileResolver
import org.hamcrest.CoreMatchers.equalTo
import org.hamcrest.MatcherAssert.assertThat
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.Timeout
import org.junit.runner.RunWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers
import org.springframework.test.context.ActiveProfiles
import org.springframework.test.context.TestPropertySource
import org.springframework.test.context.junit4.SpringRunner
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.setup.DefaultMockMvcBuilder
import org.springframework.test.web.servlet.setup.MockMvcBuilders
import org.springframework.transaction.annotation.Transactional
import org.springframework.web.context.WebApplicationContext

@RunWith(SpringRunner::class)
@ActiveProfiles(value = ["unit-test"], resolver = DatabaseProfileResolver::class)
@SpringBootTest(classes = [CredhubTestApp::class])
@Transactional
@TestPropertySource(properties = ["certificates.concatenate_cas=true"])
class ConcatenateCasEnabledEndToEndTest {

    @Autowired
    private lateinit var webApplicationContext: WebApplicationContext

    private lateinit var mockMvc: MockMvc

    @get:Rule
    val globalTimeout: Timeout = Timeout.seconds(10);

    @Before
    fun setUp() {
        BouncyCastleFipsConfigurer.configure()
        mockMvc = MockMvcBuilders
            .webAppContextSetup(webApplicationContext)
            .apply<DefaultMockMvcBuilder>(SecurityMockMvcConfigurers.springSecurity())
            .build()
    }

    @Test
    fun `get should return multiple CAs if the concatenate CA flag is set`() {
        val caName = "/some-ca-name"
        val certName = "/some-cert-name"

        RequestHelper.generateCa(mockMvc, caName, ALL_PERMISSIONS_TOKEN)

        RequestHelper.generateCertificate(mockMvc, certName, caName, ALL_PERMISSIONS_TOKEN)

        val caResponse = RequestHelper.getCertificate(mockMvc, caName, ALL_PERMISSIONS_TOKEN)
        val caUUID = JsonPath.parse(caResponse).read<String>("\$.certificates[0].id")

        RequestHelper.regenerateCertificate(mockMvc, caUUID, true, ALL_PERMISSIONS_TOKEN)

        var certResponse = RequestHelper.getCredential(mockMvc, certName, ALL_PERMISSIONS_TOKEN)

        var certCa = JsonPath.parse(certResponse).read<String>("\$.data[0].value.ca")

        var numCas = certCa.split("BEGIN CERTIFICATE").size - 1

        assertThat(numCas, equalTo(2))

        certResponse = RequestHelper.getCertificate(mockMvc, certName, ALL_PERMISSIONS_TOKEN)
        val certUUID = JsonPath.parse(certResponse).read<String>("\$.certificates[0].id")

        certResponse = RequestHelper.getCertificateVersions(mockMvc, certUUID, ALL_PERMISSIONS_TOKEN)
        certCa = JsonPath.parse(certResponse).read<String>("\$[0].value.ca")

        numCas = certCa.split("BEGIN CERTIFICATE").size - 1

        assertThat(numCas, equalTo(2))
    }
}
