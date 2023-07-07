package org.cloudfoundry.credhub.audit

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.SerializationFeature.FAIL_ON_EMPTY_BEANS
import java.io.IOException

interface RequestDetails {
    fun toJSON(): String {
        val result: String
        try {
            val mapper = ObjectMapper()
            mapper.configure(FAIL_ON_EMPTY_BEANS, false)
            result = mapper.writeValueAsString(this)
        } catch (e: IOException) {
            throw RuntimeException(e)
        }

        return result
    }

    fun operation(): OperationDeviceAction
}
