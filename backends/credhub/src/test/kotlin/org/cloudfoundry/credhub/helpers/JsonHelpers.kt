package org.cloudfoundry.credhub.helpers

class JsonHelpers {
    companion object {
        @JvmStatic
        fun escapeNewLinesForJsonSerialization(stringThatNeedsEscaping: String): String = stringThatNeedsEscaping.replace("\n", "\\n")
    }
}
