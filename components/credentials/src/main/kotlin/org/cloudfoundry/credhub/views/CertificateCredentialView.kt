package org.cloudfoundry.credhub.views

import com.fasterxml.jackson.annotation.JsonProperty
import java.util.UUID
import javax.validation.constraints.NotNull

class CertificateCredentialView {
    @get:JsonProperty("name")
    var name: String? = null
        private set

    @get:JsonProperty("id")
    var uUID: UUID? = null
        private set

    @get:JsonProperty("versions")
    var certificateVersionViews: List<CertificateVersionView>? = null
        private set

    @get:JsonProperty("signed_by")
    var signedBy: String? = null
        private set

    @get:JsonProperty("signs")
    var signs: List<String>? = null
        private set

    constructor() : super() {}
    constructor(
        name: String?,
        uuid: UUID?,
        certificateVersionViews: @NotNull MutableList<CertificateVersionView>?,
        signedBy: String?,
        signs: List<String>?,
    ) : super() {
        this.name = name
        uUID = uuid
        this.certificateVersionViews = certificateVersionViews
        this.signedBy = signedBy
        this.signs = signs
    }
}
