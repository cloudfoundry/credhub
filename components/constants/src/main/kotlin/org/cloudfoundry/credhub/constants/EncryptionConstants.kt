package org.cloudfoundry.credhub.constants

class EncryptionConstants private constructor() {
    companion object {
        const val NONCE_SIZE = 12
        const val ENCRYPTED_BYTES = 7000
        const val SALT_SIZE = 64
        const val KEY_BIT_LENGTH = 256
        const val ITERATIONS = 100000
    }
}
