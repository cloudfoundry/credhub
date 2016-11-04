UPDATE named_certificate_authority SET uuid = uuid_in((md5((random())::text))::cstring) WHERE uuid IS NULL;
