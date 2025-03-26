package org.cloudfoundry.credhub.util

import jakarta.persistence.AttributeConverter
import jakarta.persistence.Converter
import java.time.Instant

@Converter
class InstantMillisecondsConverter : AttributeConverter<Instant, Long> {
    override fun convertToDatabaseColumn(attribute: Instant): Long? = attribute.toEpochMilli()

    override fun convertToEntityAttribute(dbData: Long?): Instant = Instant.ofEpochMilli(dbData!!)
}
