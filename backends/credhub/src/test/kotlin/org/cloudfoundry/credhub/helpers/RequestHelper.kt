package org.cloudfoundry.credhub.helpers

import com.google.common.collect.ImmutableMap
import com.jayway.jsonpath.JsonPath
import org.cloudfoundry.credhub.helpers.JsonTestHelper.Companion.deserialize
import org.cloudfoundry.credhub.helpers.JsonTestHelper.Companion.serializeToString
import org.cloudfoundry.credhub.utils.AuthConstants
import org.cloudfoundry.credhub.views.PermissionsView
import org.hamcrest.core.IsEqual
import org.springframework.http.MediaType
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.ResultMatcher
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders
import org.springframework.test.web.servlet.result.MockMvcResultHandlers
import org.springframework.test.web.servlet.result.MockMvcResultMatchers

object RequestHelper {
    @Throws(Exception::class)
    @JvmStatic
    fun setPassword(
        mockMvc: MockMvc,
        credentialName: String,
        passwordValue: String?,
        token: String
    ): String {
        val passwordRequestBody: HashMap<String, Any?> = hashMapOf(
            "name" to credentialName,
            "type" to "password",
            "value" to passwordValue
        )

        val content = serializeToString(passwordRequestBody)
        val put = MockMvcRequestBuilders.put("/api/v1/data")
            .header("Authorization", "Bearer $token")
            .accept(MediaType.APPLICATION_JSON)
            .contentType(MediaType.APPLICATION_JSON)
            .content(content)
        val response: String
        response = if (credentialName.length <= 1024) {
            mockMvc.perform(put)
                .andExpect(MockMvcResultMatchers.status().isOk)
                .andDo(MockMvcResultHandlers.print())
                .andReturn().response.contentAsString
        } else {
            mockMvc.perform(put)
                .andExpect(MockMvcResultMatchers.status().isBadRequest)
                .andDo(MockMvcResultHandlers.print())
                .andReturn().response.contentAsString
        }
        return response
    }

    @Throws(Exception::class)
    @JvmStatic
    fun generatePassword(mockMvc: MockMvc, credentialName: String, overwrite: Boolean, length: Int?, token: String): String {
        val passwordRequestBody: MutableMap<String, Any> = mutableMapOf(
            "name" to credentialName,
            "type" to "password"
        )

        if (overwrite) {
            passwordRequestBody["overwrite"] = true
        }
        if (length != null) {
            passwordRequestBody["parameters"] = ImmutableMap.of("length", length)
        }
        val content = serializeToString(passwordRequestBody)
        val post = MockMvcRequestBuilders.post("/api/v1/data")
            .header("Authorization", "Bearer $token")
            .accept(MediaType.APPLICATION_JSON)
            .contentType(MediaType.APPLICATION_JSON)
            .content(content)
        val response: String
        response = if (credentialName.length <= 1024) {
            mockMvc.perform(post)
                .andExpect(MockMvcResultMatchers.status().isOk)
                .andReturn().response.contentAsString
        } else {
            mockMvc.perform(post)
                .andExpect(MockMvcResultMatchers.status().isBadRequest)
                .andReturn().response.contentAsString
        }
        return response
    }

    @Throws(Exception::class)
    @JvmStatic
    fun generateUser(
        mockMvc: MockMvc,
        credentialName: String?,
        overwrite: Boolean,
        length: Int?,
        username: String?,
        excludeUpper: Boolean
    ): String {
        val userRequestBody: MutableMap<String, Any?> = mutableMapOf(
            "name" to credentialName,
            "type" to "user"
        )

        if (overwrite) {
            userRequestBody["overwrite"] = true
        }

        val parameters: MutableMap<String, Any> = HashMap()
        if (length != null) {
            parameters["length"] = length
        }
        if (username != null) {
            parameters["username"] = username
        }
        if (excludeUpper) {
            parameters["exclude_upper"] = true
        }
        userRequestBody["parameters"] = parameters
        val content = serializeToString(userRequestBody)
        val post = MockMvcRequestBuilders.post("/api/v1/data")
            .header("Authorization", "Bearer " + AuthConstants.ALL_PERMISSIONS_TOKEN)
            .accept(MediaType.APPLICATION_JSON)
            .contentType(MediaType.APPLICATION_JSON)
            .content(content)
        return mockMvc.perform(post)
            .andExpect(MockMvcResultMatchers.status().isOk)
            .andReturn().response.contentAsString
    }

    @Throws(Exception::class)
    @JvmStatic
    fun generateSsh(
        mockMvc: MockMvc,
        credentialName: String?,
        overwrite: Boolean,
        length: Int?,
        sshComment: String?
    ): String {
        val sshRequestBody: MutableMap<String, Any?> = mutableMapOf(
            "name" to credentialName,
            "type" to "ssh"
        )

        if (overwrite) {
            sshRequestBody["overwrite"] = true
        }
        val parameters: MutableMap<String, Any> = HashMap()
        if (length != null) {
            parameters["key_length"] = length
        }
        if (sshComment != null) {
            parameters["ssh_comment"] = sshComment
        }
        sshRequestBody["parameters"] = parameters
        val content = serializeToString(sshRequestBody)
        val post = MockMvcRequestBuilders.post("/api/v1/data")
            .header("Authorization", "Bearer " + AuthConstants.ALL_PERMISSIONS_TOKEN)
            .accept(MediaType.APPLICATION_JSON)
            .contentType(MediaType.APPLICATION_JSON)
            .content(content)
        return mockMvc.perform(post)
            .andExpect(MockMvcResultMatchers.status().isOk)
            .andReturn().response.contentAsString
    }

    @Throws(Exception::class)
    @JvmStatic
    fun getCertificateCredentials(mockMvc: MockMvc, token: String): String {
        val get = MockMvcRequestBuilders.get("/api/v1/certificates")
            .header("Authorization", "Bearer $token")
            .accept(MediaType.APPLICATION_JSON)
            .contentType(MediaType.APPLICATION_JSON)
        return mockMvc.perform(get)
            .andDo(MockMvcResultHandlers.print())
            .andExpect(MockMvcResultMatchers.status().isOk)
            .andReturn().response.contentAsString
    }

    @Throws(Exception::class)
    @JvmStatic
    fun getCertificateCredentialsByName(mockMvc: MockMvc, token: String, name: String): String {
        val get = MockMvcRequestBuilders.get("/api/v1/certificates?name=$name")
            .header("Authorization", "Bearer $token")
            .accept(MediaType.APPLICATION_JSON)
            .contentType(MediaType.APPLICATION_JSON)
        return mockMvc.perform(get)
            .andDo(MockMvcResultHandlers.print())
            .andExpect(MockMvcResultMatchers.status().isOk)
            .andReturn().response.contentAsString
    }

    @Throws(Exception::class)
    @JvmStatic
    fun getCertificateId(mockMvc: MockMvc, certificateName: String): String {
        val response = getCertificateCredentialsByName(mockMvc, AuthConstants.ALL_PERMISSIONS_TOKEN, certificateName)
        return JsonPath.parse(response)
            .read("$.certificates[0].id")
    }

    @Throws(Exception::class)
    @JvmStatic
    fun generateCertificateCredential(mockMvc: MockMvc, credentialName: String?, overwrite: Boolean, commonName: String?, caName: String?, token: String): String {
        val certRequestBody: MutableMap<String, Any?> = HashMap()
        certRequestBody["name"] = credentialName
        certRequestBody["type"] = "certificate"

        if (overwrite) {
            certRequestBody["overwrite"] = true
        }
        val parameters: MutableMap<String, Any?> = HashMap()
        if (caName == null) {
            parameters["self_sign"] = true
            parameters["is_ca"] = true
        } else {
            parameters["ca"] = caName
        }
        parameters["common_name"] = commonName
        certRequestBody["parameters"] = parameters
        val content = serializeToString(certRequestBody)
        val post = MockMvcRequestBuilders.post("/api/v1/data")
            .header("Authorization", "Bearer $token")
            .accept(MediaType.APPLICATION_JSON)
            .contentType(MediaType.APPLICATION_JSON)
            .content(content)
        return mockMvc.perform(post)
            .andExpect(MockMvcResultMatchers.status().isOk)
            .andReturn().response.contentAsString
    }

    @Throws(Exception::class)
    @JvmStatic
    fun generateRsa(
        mockMvc: MockMvc,
        credentialName: String?,
        overwrite: Boolean,
        length: Int?
    ): String {
        val rsaRequestBody: MutableMap<String, Any?> = HashMap()
        rsaRequestBody["name"] = credentialName
        rsaRequestBody["type"] = "rsa"

        if (overwrite) {
            rsaRequestBody["overwrite"] = true
        }
        if (length != null) {
            rsaRequestBody["parameters"] = ImmutableMap.of("key_length", length)
        }
        val content = serializeToString(rsaRequestBody)
        val post = MockMvcRequestBuilders.post("/api/v1/data")
            .header("Authorization", "Bearer " + AuthConstants.ALL_PERMISSIONS_TOKEN)
            .accept(MediaType.APPLICATION_JSON)
            .contentType(MediaType.APPLICATION_JSON)
            .content(content)
        return mockMvc.perform(post)
            .andExpect(MockMvcResultMatchers.status().isOk)
            .andReturn().response.contentAsString
    }

    @Throws(Exception::class)
    @JvmStatic
    fun generateCa(mockMvc: MockMvc, caName: String, token: String): String {
        val caPost = MockMvcRequestBuilders.post("/api/v1/data")
            .header("Authorization", "Bearer $token")
            .accept(MediaType.APPLICATION_JSON)
            .contentType(MediaType.APPLICATION_JSON)
            //language=JSON
            .content(
                """{
                "name" : "$caName",
                "type" : "certificate",
                "overwrite": true,
                "parameters" : 
                  {
                    "common_name" : "federation",
                    "is_ca" : true,
                    "self_sign": true
                  }
              }
                """.trimIndent()
            )

        return mockMvc.perform(caPost)
            .andExpect(MockMvcResultMatchers.status().isOk)
            .andReturn().response.contentAsString
    }

    @JvmStatic
    private fun createRequestForGenerateCertificate(
        certName: String,
        caName: String,
        token: String
    ): MockHttpServletRequestBuilder {
        return MockMvcRequestBuilders.post("/api/v1/data")
            .header("Authorization", "Bearer $token")
            .accept(MediaType.APPLICATION_JSON)
            .contentType(MediaType.APPLICATION_JSON)
            //language=JSON
            .content(
                """{
                "name" : "$certName",
                "type" : "certificate",
                "parameters" : 
                  {
                    "common_name" : "federation",
                    "ca" : "$caName"
                  }
              }
                """.trimIndent()
            )
    }

    @Throws(Exception::class)
    @JvmStatic
    fun generateCertificate(
        mockMvc: MockMvc,
        certName: String,
        caName: String,
        token: String
    ) {
        val certPost = createRequestForGenerateCertificate(certName, caName, token)
        mockMvc.perform(certPost)
            .andDo(MockMvcResultHandlers.print())
            .andExpect(MockMvcResultMatchers.status().isOk)
    }

    @Throws(Exception::class)
    @JvmStatic
    fun expectErrorCodeWhileGeneratingCertificate(
        mockMvc: MockMvc,
        certName: String,
        token: String,
        expectedMessage: String,
        errCode: ResultMatcher?
    ) {
        val certPost = MockMvcRequestBuilders.post("/api/v1/data")
            .header("Authorization", "Bearer $token")
            .accept(MediaType.APPLICATION_JSON)
            .contentType(MediaType.APPLICATION_JSON)
            //language=JSON
            .content(
                """{
                "name" : "$certName",
                "type" : "certificate",
                "parameters" : 
                  {
                    "common_name" : "federation",
                    "ca" : "picard"
                  }
              }
                """.trimIndent()
            )
        mockMvc.perform(certPost)
            .andDo(MockMvcResultHandlers.print())
            .andExpect(errCode!!)
            .andExpect(MockMvcResultMatchers.jsonPath("$.error", IsEqual.equalTo(expectedMessage)))
    }

    @Throws(Exception::class)
    @JvmStatic
    fun expect404WhileRegeneratingCertificate(
        mockMvc: MockMvc,
        certName: String,
        token: String,
        message: String
    ) {
        val certPost = MockMvcRequestBuilders.post("/api/v1/data")
            .header("Authorization", "Bearer $token")
            .accept(MediaType.APPLICATION_JSON)
            .contentType(MediaType.APPLICATION_JSON) //language=JSON
            .content("{\"regenerate\":true,\"name\":\"$certName\"}")
        mockMvc.perform(certPost)
            .andDo(MockMvcResultHandlers.print())
            .andExpect(MockMvcResultMatchers.status().isNotFound)
            .andExpect(MockMvcResultMatchers.jsonPath("$.error", IsEqual.equalTo(message)))
    }

    @Throws(Exception::class)
    @JvmStatic
    fun grantPermissions(
        mockMvc: MockMvc,
        credentialName: String,
        grantorToken: String,
        granteeName: String,
        vararg permissions: String?
    ) {
        val post = createAddPermissionsRequest(
            grantorToken, credentialName, granteeName,
            *permissions
        )
        mockMvc.perform(post)
            .andExpect(MockMvcResultMatchers.status().isCreated)
    }

    @Throws(Exception::class)
    @JvmStatic
    fun expectErrorWhenAddingPermissions(
        mockMvc: MockMvc,
        status: Int,
        message: String?,
        credentialName: String,
        grantorToken: String,
        grantee: String,
        vararg permissions: String?
    ) {
        val post = createAddPermissionsRequest(
            grantorToken, credentialName, grantee,
            *permissions
        )
        mockMvc.perform(post)
            .andExpect(MockMvcResultMatchers.status().`is`(status))
            .andExpect(MockMvcResultMatchers.content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
            .andExpect(MockMvcResultMatchers.jsonPath("$.error").value(message!!))
    }

    @Throws(Exception::class)
    @JvmStatic
    fun getPermissions(
        mockMvc: MockMvc,
        credentialName: String,
        requesterToken: String
    ): PermissionsView {
        val content = mockMvc.perform(
            MockMvcRequestBuilders.get("/api/v1/permissions?credential_name=$credentialName")
                .header("Authorization", "Bearer $requesterToken")
        )
            .andExpect(MockMvcResultMatchers.status().isOk)
            .andExpect(MockMvcResultMatchers.content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
            .andReturn()
            .response
            .contentAsString
        return deserialize(content, PermissionsView::class.java)
    }

    @Throws(Exception::class)
    @JvmStatic
    fun expectErrorWhenGettingPermissions(
        mockMvc: MockMvc,
        status: Int,
        expectedErrorMessage: String,
        credentialName: String?,
        requesterToken: String
    ) {
        mockMvc.perform(
            MockMvcRequestBuilders.get(
                "/api/v1/permissions" +
                    if (credentialName == null) "" else "?credential_name=$credentialName"
            )
                .header("Authorization", "Bearer $requesterToken")
        )
            .andExpect(MockMvcResultMatchers.status().`is`(status))
            .andExpect(MockMvcResultMatchers.jsonPath("$.error", IsEqual.equalTo(expectedErrorMessage)))
    }

    @Throws(Exception::class)
    @JvmStatic
    fun revokePermissions(
        mockMvc: MockMvc,
        credentialName: String?,
        grantorToken: String,
        grantee: String?
    ) {
        expectStatusWhenDeletingPermissions(
            mockMvc, 204, credentialName, grantee,
            grantorToken
        )
    }

    @Throws(Exception::class)
    @JvmStatic
    fun expectStatusWhenDeletingPermissions(
        mockMvc: MockMvc,
        status: Int,
        credentialName: String?,
        grantee: String?,
        grantorToken: String
    ) {
        expectErrorWhenDeletingPermissions(
            mockMvc, status, null, credentialName, grantorToken, grantee
        )
    }

    @Throws(Exception::class)
    @JvmStatic
    fun expectErrorWhenDeletingPermissions(
        mockMvc: MockMvc,
        status: Int,
        expectedErrorMessage: String?,
        credentialName: String?,
        grantorToken: String,
        grantee: String?
    ) {
        val result = mockMvc.perform(
            MockMvcRequestBuilders.delete(
                "/api/v1/permissions?" +
                    (if (credentialName == null) "" else "credential_name=$credentialName") +
                    if (grantee == null) "" else "&actor=$grantee"
            ).header("Authorization", "Bearer $grantorToken")
        )
        result.andExpect(MockMvcResultMatchers.status().`is`(status))
        if (expectedErrorMessage != null) {
            result.andExpect(MockMvcResultMatchers.jsonPath("$.error", IsEqual.equalTo(expectedErrorMessage)))
        }
    }

    @JvmStatic
    private fun createAddPermissionsRequest(
        grantorToken: String,
        credentialName: String,
        grantee: String,
        vararg permissions: String?
    ): MockHttpServletRequestBuilder {
        return MockMvcRequestBuilders.post("/api/v1/permissions")
            .header("Authorization", "Bearer $grantorToken")
            .accept(MediaType.APPLICATION_JSON)
            .contentType(MediaType.APPLICATION_JSON)
            .content(
                "{" +
                    "  \"credential_name\": \"" + credentialName + "\",\n" +
                    "  \"permissions\": [\n" +
                    "     { \n" +
                    "       \"actor\": \"" + grantee + "\",\n" +
                    "       \"path\": \"" + credentialName + "\",\n" +
                    "       \"operations\": [\"" + java.lang.String.join("\", \"", *permissions) + "\"]\n" +
                    "     }]" +
                    "}"
            )
    }

    @Throws(Exception::class)
    @JvmStatic
    fun regenerateCertificate(
        mockMvc: MockMvc,
        uuid: String,
        transitional: Boolean,
        token: String
    ): String {
        val regenerateRequest = MockMvcRequestBuilders.post("/api/v1/certificates/$uuid/regenerate")
            .header("Authorization", "Bearer $token")
            .accept(MediaType.APPLICATION_JSON)
            .contentType(MediaType.APPLICATION_JSON) //language=JSON
            .content("{\"set_as_transitional\" : $transitional}")
        return mockMvc.perform(regenerateRequest)
            .andExpect(MockMvcResultMatchers.status().is2xxSuccessful)
            .andReturn().response.contentAsString
    }

    @Throws(Exception::class)
    @JvmStatic
    fun getCertificate(mockMvc: MockMvc, name: String, token: String): String {
        val regenerateRequest = MockMvcRequestBuilders.get("/api/v1/certificates?name=$name")
            .header("Authorization", "Bearer $token")
            .accept(MediaType.APPLICATION_JSON)
            .contentType(MediaType.APPLICATION_JSON)
        return mockMvc.perform(regenerateRequest)
            .andExpect(MockMvcResultMatchers.status().is2xxSuccessful)
            .andReturn().response.contentAsString
    }

    @Throws(Exception::class)
    @JvmStatic
    fun getCertificateVersions(mockMvc: MockMvc, uuid: String, token: String): String {
        val regenerateRequest = MockMvcRequestBuilders.get("/api/v1/certificates/$uuid/versions")
            .header("Authorization", "Bearer $token")
            .accept(MediaType.APPLICATION_JSON)
            .contentType(MediaType.APPLICATION_JSON)
        return mockMvc.perform(regenerateRequest)
            .andExpect(MockMvcResultMatchers.status().is2xxSuccessful)
            .andReturn().response.contentAsString
    }

    @Throws(Exception::class)
    @JvmStatic
    fun getCredential(mockMvc: MockMvc, name: String, token: String): String {
        val regenerateRequest = MockMvcRequestBuilders.get("/api/v1/data?name=$name")
            .header("Authorization", "Bearer $token")
            .accept(MediaType.APPLICATION_JSON)
            .contentType(MediaType.APPLICATION_JSON)
        return mockMvc.perform(regenerateRequest)
            .andExpect(MockMvcResultMatchers.status().is2xxSuccessful)
            .andReturn().response.contentAsString
    }
}
