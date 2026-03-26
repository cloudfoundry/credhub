package org.cloudfoundry.credhub.audit

import tools.jackson.databind.SerializationFeature.FAIL_ON_EMPTY_BEANS
import tools.jackson.databind.json.JsonMapper

interface RequestDetails {
    fun toJSON(): String {
        val mapper =
            JsonMapper
                .builder()
                .disable(FAIL_ON_EMPTY_BEANS)
                .build()
        return mapper.writeValueAsString(this)
    }

    fun operation(): OperationDeviceAction
}
