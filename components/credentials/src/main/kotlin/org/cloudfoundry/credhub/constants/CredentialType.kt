package org.cloudfoundry.credhub.constants

enum class CredentialType private constructor(type: String) {
    PASSWORD("password"),
    CERTIFICATE("certificate"),
    VALUE("value"),
    RSA("rsa"),
    SSH("ssh"),
    JSON("json"),
    USER("user");

    val type: String

    init {
        this.type = type.uppercase()
    }

    companion object {
        fun generatableCredentialTypes(): List<CredentialType> {
            return listOf(
                PASSWORD,
                CERTIFICATE,
                USER,
                RSA,
                SSH
            )
        }
    }
}
