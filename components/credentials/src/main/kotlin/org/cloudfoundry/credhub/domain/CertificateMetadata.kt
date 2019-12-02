package org.cloudfoundry.credhub.domain

import java.util.UUID

class CertificateMetadata(
    var id: UUID?,
    var name: String?,
    var caName: String?,
    var versions: MutableList<CertificateVersionMetadata>?
)
