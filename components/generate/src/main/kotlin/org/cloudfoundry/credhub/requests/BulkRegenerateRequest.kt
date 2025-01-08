package org.cloudfoundry.credhub.requests

import com.fasterxml.jackson.annotation.JsonAutoDetect
import com.fasterxml.jackson.annotation.JsonProperty
import org.apache.commons.lang3.StringUtils
import org.cloudfoundry.credhub.ErrorMessages
import javax.validation.constraints.NotNull

@JsonAutoDetect
class BulkRegenerateRequest {
    @JsonProperty("signed_by")
    @NotNull(message = ErrorMessages.MISSING_SIGNED_BY)
    private lateinit var signedBy: String

    constructor() {
        // this needs to be there for jackson to be happy
    }

    constructor(signedBy: String) {
        this.signedBy = signedBy
    }

    fun getSignedBy(): String = signedBy

    fun setSignedBy(signedBy: String) {
        this.signedBy = StringUtils.prependIfMissing(signedBy, "/")
    }
}
