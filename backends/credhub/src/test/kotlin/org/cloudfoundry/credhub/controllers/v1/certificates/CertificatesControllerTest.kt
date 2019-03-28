package org.cloudfoundry.credhub.controllers.v1.certificates

import com.fasterxml.jackson.databind.ObjectMapper
import org.apache.commons.lang3.RandomStringUtils
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider
import org.cloudfoundry.credhub.audit.CEFAuditRecord
import org.cloudfoundry.credhub.certificates.CertificatesController
import org.cloudfoundry.credhub.constants.CredentialType
import org.cloudfoundry.credhub.credential.CertificateCredentialValue
import org.cloudfoundry.credhub.requests.CertificateRegenerateRequest
import org.cloudfoundry.credhub.helpers.CredHubRestDocs
import org.cloudfoundry.credhub.helpers.MockMvcFactory
import org.cloudfoundry.credhub.utils.TestConstants
import org.cloudfoundry.credhub.views.CredentialView
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.skyscreamer.jsonassert.JSONAssert
import org.springframework.http.MediaType
import org.springframework.restdocs.JUnitRestDocumentation
import org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document
import org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.post
import org.springframework.restdocs.payload.JsonFieldType
import org.springframework.restdocs.payload.PayloadDocumentation
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import java.security.Security
import java.time.Instant
import java.util.UUID

class CertificatesControllerTest {
    @Rule
    @JvmField
    val restDocumentation = JUnitRestDocumentation()

    lateinit var mockMvc: MockMvc
    lateinit var spyCertificatesHandler: SpyCertificatesHandler

    @Before
    fun setUp() {
        spyCertificatesHandler = SpyCertificatesHandler()

        val certificateController = CertificatesController(
            spyCertificatesHandler,
                CEFAuditRecord()
        )

        mockMvc = MockMvcFactory.newSpringRestDocMockMvc(certificateController, restDocumentation)

        if (Security.getProvider(BouncyCastleFipsProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BouncyCastleFipsProvider())
        }
    }

    @Test
    fun POST__certificate_regenerate__returns_result() {
        val certificateId = UUID.randomUUID()
        val name = RandomStringUtils.randomAlphabetic(10)
        val certificateCredentialValue = CertificateCredentialValue(
                TestConstants.TEST_CA,
                TestConstants.TEST_CERTIFICATE,
                TestConstants.TEST_PRIVATE_KEY,
                null,
                true
        )

        val requestBodyContent = CertificateRegenerateRequest(true)
        val createdAt = Instant.ofEpochSecond(1549053472L)

        val credentialViewResponse = CredentialView(
                createdAt,
                certificateId,
                name,
                CredentialType.CERTIFICATE.type.toLowerCase(),
                certificateCredentialValue)

        spyCertificatesHandler.handleRegenerate__calledWith_request = requestBodyContent
        spyCertificatesHandler.handleRegenerate__calledWith_credentialUuid = certificateId.toString()

        val mapper = ObjectMapper()
        val requestBody = mapper.writeValueAsString(requestBodyContent)
        spyCertificatesHandler.handleRegenerate__returns_credentialView = credentialViewResponse

        val mvcResult = mockMvc
                .perform(post("${CertificatesController.ENDPOINT}/{certificateId}/regenerate", certificateId.toString())
                        .header("Authorization", "Bearer [some-token]")
                        .accept(MediaType.APPLICATION_JSON_UTF8)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestBody)
                ).andExpect(status().isOk)
                .andDo(
                        document(
                                CredHubRestDocs.DOCUMENT_IDENTIFIER,
                                PayloadDocumentation.requestFields(
                                        PayloadDocumentation.fieldWithPath("set_as_transitional")
                                                .description("Set if certificate is transitional")
                                                .type(JsonFieldType.BOOLEAN)
                                                .optional()
                                )
                        )

                ).andReturn()

        // language=json
        val expectedResponseBody = """
            {
              "type": "${CredentialType.CERTIFICATE.type.toLowerCase()}",
              "version_created_at": "${credentialViewResponse.versionCreatedAt}",
              "id": "$certificateId",
              "name": "$name",
              "value": {
                "ca": "${TestConstants.TEST_CA}",
                "certificate": "${TestConstants.TEST_CERTIFICATE}",
                "private_key": "${TestConstants.TEST_PRIVATE_KEY}",
                "transitional": true,
                "expiry_date": "${certificateCredentialValue.expiryDate}"
              }
            }
        """.trimIndent()
        JSONAssert.assertEquals(mvcResult.response.contentAsString, expectedResponseBody, true)
    }
}