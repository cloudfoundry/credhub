package org.cloudfoundry.credhub.views

import com.fasterxml.jackson.annotation.JsonGetter
import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.annotation.JsonInclude.Include.NON_NULL
import com.fasterxml.jackson.annotation.JsonProperty
import java.time.Instant
import java.util.UUID

data class CertificateVersionView(
    val id: UUID,
    val expiryDate: Instant?,
    val transitional: Boolean,
    @JsonProperty("certificate_authority")
    val certificateAuthority: Boolean,
    @JsonProperty("self_signed")
    val selfSigned: Boolean,
    @JsonInclude(NON_NULL)
    val generated: Boolean?
) {
    @JsonProperty("expiry_date")
    @JsonGetter
    fun getExpiryDate(): String {
        return expiryDate?.toString() ?: ""
    }
}
