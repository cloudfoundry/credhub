package org.cloudfoundry.credhub.controllers.v1.certificates

import com.fasterxml.jackson.databind.ObjectMapper
import org.apache.commons.lang3.RandomStringUtils
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider
import org.cloudfoundry.credhub.audit.CEFAuditRecord
import org.cloudfoundry.credhub.certificates.CertificatesController
import org.cloudfoundry.credhub.constants.CredentialType
import org.cloudfoundry.credhub.credential.CertificateCredentialValue
import org.cloudfoundry.credhub.domain.CertificateCredentialVersion
import org.cloudfoundry.credhub.helpers.CredHubRestDocs
import org.cloudfoundry.credhub.helpers.MockMvcFactory
import org.cloudfoundry.credhub.requests.CertificateRegenerateRequest
import org.cloudfoundry.credhub.utils.TestConstants
import org.cloudfoundry.credhub.views.CertificateCredentialView
import org.cloudfoundry.credhub.views.CertificateCredentialsView
import org.cloudfoundry.credhub.views.CertificateView
import org.cloudfoundry.credhub.views.CredentialView
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.skyscreamer.jsonassert.JSONAssert
import org.springframework.http.MediaType
import org.springframework.restdocs.JUnitRestDocumentation
import org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document
import org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.get
import org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.post
import org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.put
import org.springframework.restdocs.payload.JsonFieldType
import org.springframework.restdocs.payload.PayloadDocumentation
import org.springframework.restdocs.request.RequestDocumentation.parameterWithName
import org.springframework.restdocs.request.RequestDocumentation.requestParameters
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
    private lateinit var spyCertificatesHandler: SpyCertificatesHandler
    private lateinit var certificateCredentialValue: CertificateCredentialValue
    private lateinit var credentialViewResponse: CredentialView

    private lateinit var certificateId: UUID
    private lateinit var name: String
    private lateinit var createdAt: Instant

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


        certificateId = UUID.randomUUID()
        name = RandomStringUtils.randomAlphabetic(10)
        createdAt = Instant.ofEpochSecond(1549053472L)

        certificateCredentialValue = CertificateCredentialValue(
            TestConstants.TEST_CA,
            TestConstants.TEST_CERTIFICATE,
            TestConstants.TEST_PRIVATE_KEY,
            null,
            true
        )

        credentialViewResponse = CredentialView(
            createdAt,
            certificateId,
            name,
            CredentialType.CERTIFICATE.type.toLowerCase(),
            certificateCredentialValue)


    }

    @Test
    fun POST__certificates_uuid_regenerate__returns_certificate() {
        val requestBodyContent = CertificateRegenerateRequest(true)
        spyCertificatesHandler.handleRegenerate__calledWith_request = requestBodyContent
        spyCertificatesHandler.handleRegenerate__calledWith_credentialUuid = certificateId.toString()

        val mapper = ObjectMapper()
        val requestBody = mapper.writeValueAsString(requestBodyContent)
        spyCertificatesHandler.handleRegenerate__returns_credentialView = credentialViewResponse

        val mvcResult = mockMvc
                .perform(
                    post("${CertificatesController.ENDPOINT}/{certificateId}/regenerate", certificateId.toString())
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

    @Test
    fun GET__certificates__returns_certificates(){
        val certificateCredentialsView = CertificateCredentialsView(listOf(CertificateCredentialView(name, certificateId)))
        spyCertificatesHandler.handleGetAllRequest__returns_certificateCredentialsView = certificateCredentialsView

        val mvcResult = mockMvc
            .perform(
                get(CertificatesController.ENDPOINT)
                    .header("Authorization", "Bearer [some-token]")
                    .accept(MediaType.APPLICATION_JSON_UTF8)
            ).andExpect(status().isOk)
            .andDo(
                document(
                    CredHubRestDocs.DOCUMENT_IDENTIFIER
                )
            ).andReturn()

        // language=json
        val expectedResponse = """
        {
          "certificates":
          [
            {
              "name":"$name",
              "id":"$certificateId"
            }
          ]
        }
        """.trimIndent()

        JSONAssert.assertEquals(mvcResult.response.contentAsString, expectedResponse, true)
    }

    @Test
    fun GET__certificates_byName__returns_certificate(){
        val certificateCredentialsView = CertificateCredentialsView(listOf(CertificateCredentialView(name, certificateId)))
        spyCertificatesHandler.handleGetByNameRequest__returns_certificateCredentialsView = certificateCredentialsView

        val mvcResult = mockMvc
            .perform(
                get(CertificatesController.ENDPOINT)
                    .header("Authorization", "Bearer [some-token]")
                    .accept(MediaType.APPLICATION_JSON_UTF8)
                    .param("name", name)
            ).andExpect(status().isOk)
            .andDo(
                document(
                    CredHubRestDocs.DOCUMENT_IDENTIFIER,
                    requestParameters(parameterWithName("name").
                        description("Certificate Name"))
                )
            ).andReturn()

        // language=json
        val expectedResponse = """
        {
          "certificates":
          [
            {
              "name":"$name",
              "id":"$certificateId"
            }
          ]
        }
        """.trimIndent()

        JSONAssert.assertEquals(mvcResult.response.contentAsString, expectedResponse, true)
    }

    @Test
    fun PUT__updateTransitionalVersion__returns_certificate(){
        // language=json
        val requestBody = """
            {"version": "some-version"}
        """.trimIndent()

        val certificateCredentialVersion = CertificateCredentialVersion(certificateCredentialValue, StubEncryptor())
        val certificateView = CertificateView(certificateCredentialVersion)
        spyCertificatesHandler.handleUpdateTransitionalVersion__returns_certificateViewList = listOf(certificateView)

        mockMvc
            .perform(
                put("${CertificatesController.ENDPOINT}/{certificateId}/update_transitional_version", certificateId.toString())
                    .header("Authorization", "Bearer [some-token]")
                    .accept(MediaType.APPLICATION_JSON_UTF8)
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(requestBody)
            ).andExpect(status().isOk)
            .andDo(
                document(
                    CredHubRestDocs.DOCUMENT_IDENTIFIER,
                    PayloadDocumentation.requestFields(
                        PayloadDocumentation.fieldWithPath("version")
                            .description("Version of certificate to set as transitional. Set version to null to ensure no versions are transitional.")
                            .type(JsonFieldType.STRING)
                    )
                )

            ).andReturn()

    }
}
