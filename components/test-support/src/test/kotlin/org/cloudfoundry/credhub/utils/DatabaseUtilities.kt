package org.cloudfoundry.credhub.utils

import kotlin.math.roundToInt

class DatabaseUtilities {
    private constructor()

    companion object {
        fun getExceedsMaxBlobStoreSizeBytes(): ByteArray {
            val exceedsMaxBlobStoreSize = 70000
            val exceedsMaxBlobStoreValue = ByteArray(exceedsMaxBlobStoreSize)
            for (i in 0 until exceedsMaxBlobStoreSize) {
                val randomNumber = (Math.random() * 10).roundToInt().toByte()
                exceedsMaxBlobStoreValue[i] = randomNumber
            }
            return exceedsMaxBlobStoreValue
        }
    }
}