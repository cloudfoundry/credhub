package org.cloudfoundry.credhub.views

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.annotation.JsonInclude.Include.NON_NULL
import com.fasterxml.jackson.annotation.JsonProperty
import java.time.Instant
import java.util.UUID
import org.cloudfoundry.credhub.domain.CertificateVersionMetadata

class CertificateVersionView(
    val id: UUID,
    expiryDate: Instant?,
    val transitional: Boolean,
    @JsonProperty("certificate_authority")
    val certificateAuthority: Boolean,
    @JsonProperty("self_signed")
    val selfSigned: Boolean,
    @JsonInclude(NON_NULL)
    val generated: Boolean?
) {
    constructor(certificateVersion: CertificateVersionMetadata) : this(
        certificateVersion.id,
        certificateVersion.expiryDate,
        certificateVersion.isTransitional,
        certificateVersion.isCertificateAuthority,
        certificateVersion.isSelfSigned,
        certificateVersion.generated
    )

    @JsonProperty("expiry_date")
    val expiryDate = expiryDate?.toString() ?: ""
}
