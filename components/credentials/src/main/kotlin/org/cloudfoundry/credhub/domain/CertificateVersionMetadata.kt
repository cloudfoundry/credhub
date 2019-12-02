package org.cloudfoundry.credhub.domain

import java.time.Instant
import java.util.UUID

class CertificateVersionMetadata(
    var id: UUID?,
    var expiryDate: Instant?,
    var isTransitional: Boolean,
    var isCertificateAuthority: Boolean,
    var isSelfSigned: Boolean,
    var generated: Boolean?
)
