package org.cloudfoundry.credhub.helpers

class JsonHelpers {
    companion object {
        @JvmStatic
        fun escapeNewLinesForJsonSerialization(stringThatNeedsEscaping: String): String {
            return stringThatNeedsEscaping.replace("\n", "\\n")
        }
    }
}
