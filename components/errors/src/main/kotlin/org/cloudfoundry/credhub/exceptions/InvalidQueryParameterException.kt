package org.cloudfoundry.credhub.exceptions

class InvalidQueryParameterException(
    message: String,
    val invalidQueryParameter: String,
) : RuntimeException(message)
