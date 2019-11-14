package org.cloudfoundry.credhub.exceptions

import com.google.common.collect.Lists
import java.util.stream.Collectors
import javax.validation.ValidationException

class ParameterizedValidationException @JvmOverloads constructor(messageCode: String, parameters: Array<Any> = arrayOf()) : ValidationException(messageCode) {

    private val parameters: List<Any>

    constructor(messageCode: String, parameter: String) : this(messageCode, arrayOf<Any>(parameter))

    init {

        this.parameters = Lists.newArrayList(*parameters)
            .stream()
            .map<Any> { scrubSpecialCharacter(it) }
            .collect(Collectors.toList())
    }

    private fun scrubSpecialCharacter(raw: Any): Any {
        return if (raw is String) {
            raw.replace("$[", "").replace("][", ".").replace("]", "").replace("'", "")
        } else {
            raw
        }
    }

    fun getParameters(): Array<Any> {
        return parameters.toTypedArray()
    }
}
