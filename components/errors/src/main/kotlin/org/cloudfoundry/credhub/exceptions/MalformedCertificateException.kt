package org.cloudfoundry.credhub.exceptions

class MalformedCertificateException : RuntimeException {
    constructor(message: String) : super(message) {}

    constructor() : super() {}
}
