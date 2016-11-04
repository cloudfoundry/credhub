UPDATE named_certificate_authority SET uuid = UUID() WHERE uuid IS NULL;
