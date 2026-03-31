package org.cloudfoundry.credhub.requests

import jakarta.validation.constraints.NotNull
import org.apache.commons.lang3.StringUtils
import org.cloudfoundry.credhub.ErrorMessages

class BulkRegenerateRequest {
    @field:NotNull(message = ErrorMessages.MISSING_SIGNED_BY)
    var signedBy: String? = null
        set(value) {
            field = if (value != null) StringUtils.prependIfMissing(value, "/") else null
        }

    constructor() : super() {
        // this needs to be there for jackson to be happy
    }

    constructor(signedBy: String?) : super() {
        this.signedBy = signedBy
    }
}
