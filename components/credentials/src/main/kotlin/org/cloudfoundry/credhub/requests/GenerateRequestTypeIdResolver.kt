package org.cloudfoundry.credhub.requests

import com.fasterxml.jackson.annotation.JsonTypeInfo
import com.fasterxml.jackson.databind.DatabindContext
import com.fasterxml.jackson.databind.JavaType
import com.fasterxml.jackson.databind.jsontype.TypeIdResolver
import org.cloudfoundry.credhub.entity.CertificateCredentialVersionData
import org.cloudfoundry.credhub.entity.PasswordCredentialVersionData
import org.cloudfoundry.credhub.entity.RsaCredentialVersionData
import org.cloudfoundry.credhub.entity.SshCredentialVersionData
import org.cloudfoundry.credhub.entity.UserCredentialVersionData
import java.io.IOException

class GenerateRequestTypeIdResolver : TypeIdResolver {
    private var baseType: JavaType? = null

    override fun init(baseType: JavaType) {
        this.baseType = baseType
    }

    override fun idFromValue(value: Any): String? = null

    override fun idFromValueAndType(
        value: Any,
        suggestedType: Class<*>,
    ): String? = null

    override fun idFromBaseType(): String? = null

    @Throws(IOException::class)
    override fun typeFromId(
        context: DatabindContext,
        id: String,
    ): JavaType {
        var subType: Class<*> = DefaultCredentialGenerateRequest::class.java

        when (id.lowercase()) {
            CertificateCredentialVersionData.CREDENTIAL_TYPE -> subType = CertificateGenerateRequest::class.java
            PasswordCredentialVersionData.CREDENTIAL_TYPE -> subType = PasswordGenerateRequest::class.java
            RsaCredentialVersionData.CREDENTIAL_TYPE -> subType = RsaGenerateRequest::class.java
            SshCredentialVersionData.CREDENTIAL_TYPE -> subType = SshGenerateRequest::class.java
            UserCredentialVersionData.CREDENTIAL_TYPE -> subType = UserGenerateRequest::class.java
            else -> {
            }
        }

        return context.constructSpecializedType(baseType!!, subType)
    }

    override fun getDescForKnownTypeIds(): String? = null

    override fun getMechanism(): JsonTypeInfo.Id = JsonTypeInfo.Id.CUSTOM
}
