package org.cloudfoundry.credhub.requests

import com.fasterxml.jackson.annotation.JsonTypeInfo
import com.fasterxml.jackson.databind.DatabindContext
import com.fasterxml.jackson.databind.JavaType
import com.fasterxml.jackson.databind.exc.InvalidTypeIdException
import com.fasterxml.jackson.databind.jsontype.TypeIdResolver
import org.cloudfoundry.credhub.entity.CertificateCredentialVersionData
import org.cloudfoundry.credhub.entity.JsonCredentialVersionData
import org.cloudfoundry.credhub.entity.PasswordCredentialVersionData
import org.cloudfoundry.credhub.entity.RsaCredentialVersionData
import org.cloudfoundry.credhub.entity.SshCredentialVersionData
import org.cloudfoundry.credhub.entity.UserCredentialVersionData
import org.cloudfoundry.credhub.entity.ValueCredentialVersionData
import java.io.IOException

class SetRequestTypeIdResolver : TypeIdResolver {
    private var baseType: JavaType? = null

    override fun init(baseType: JavaType) {
        this.baseType = baseType
    }

    override fun idFromValue(value: Any): String? {
        return null
    }

    override fun idFromValueAndType(value: Any, suggestedType: Class<*>): String? {
        return null
    }

    override fun idFromBaseType(): String? {
        return null
    }

    @Throws(IOException::class)
    override fun typeFromId(context: DatabindContext, id: String): JavaType {
        val subType: Class<*>
        val lowerCaseId = id.lowercase()

        when (lowerCaseId) {
            CertificateCredentialVersionData.CREDENTIAL_TYPE -> subType = CertificateSetRequest::class.java
            ValueCredentialVersionData.CREDENTIAL_TYPE -> subType = ValueSetRequest::class.java
            JsonCredentialVersionData.CREDENTIAL_TYPE -> subType = JsonSetRequest::class.java
            PasswordCredentialVersionData.CREDENTIAL_TYPE -> subType = PasswordSetRequest::class.java
            RsaCredentialVersionData.CREDENTIAL_TYPE -> subType = RsaSetRequest::class.java
            SshCredentialVersionData.CREDENTIAL_TYPE -> subType = SshSetRequest::class.java
            UserCredentialVersionData.CREDENTIAL_TYPE -> subType = UserSetRequest::class.java
            else -> {
                val message = String.format("Could not resolve type id '%s' into a subtype of %s", lowerCaseId, baseType)
                throw InvalidTypeIdException(null, message, baseType, lowerCaseId)
            }
        }

        return context.constructSpecializedType(baseType!!, subType)
    }

    override fun getDescForKnownTypeIds(): String? {
        return null
    }

    override fun getMechanism(): JsonTypeInfo.Id {
        return JsonTypeInfo.Id.CUSTOM
    }
}
