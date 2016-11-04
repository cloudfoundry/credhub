-- We don't need to worry about conversions in H2 :)
ALTER TABLE NAMED_SECRET ALTER COLUMN UUID BINARY(16) NOT NULL;
