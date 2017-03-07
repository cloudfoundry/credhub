package io.pivotal.security.domain;

import com.greghaskins.spectrum.Spectrum;
import org.junit.runner.RunWith;

import java.time.Instant;
import java.util.UUID;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.not;

@RunWith(Spectrum.class)
public class NamedRsaSecretTest {
  private NamedRsaSecret subject;

  {
    beforeEach(() -> {
      subject = new NamedRsaSecret("/Foo");
    });

    it("returns type rsa", () -> {
      assertThat(subject.getSecretType(), equalTo("rsa"));
    });

    describe("#getKeyLength", () -> {
      it("should return the length of the public key", () -> {
        String publicKey = "-----BEGIN PUBLIC KEY-----\n" +
            "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAoRIqdibiYHKZhyH91xYR\n" +
            "Tpz728+A8d/t2U2e8OIhNqI7pjh5uKnbmeoAXdZAbGN3TW7xArdMAUOSRhELH0Gc\n" +
            "8XGz6ZnY+KGuTnmBO+ZamE3kltwqJBfxwV2UGV5bJIVVToLpLa1GDF4p7g8I8W/a\n" +
            "KURKCgMNlRQw38Wi8yuEWyCHWHrqon8CcA5ovUg1pyrpR9i+5NTCRadDf1JIQfKB\n" +
            "Mt/gA/s6+ZaWOB6mbWv67OUS5wHWe0tcX2g4KK3IDlkzKQulSHQoIPEf+7l+vJEJ\n" +
            "KT+C2cI+pl/qLVtbY+jsNr8acxja0ri4pUGEQPKP5009qisloEDlQMb/gMT5aHoF\n" +
            "8GORc1EloUG4CpnPUe0L63Q3uSZkLSPAiYqwCi7Wu/L7aVeynGk3CFIPALyh/hIi\n" +
            "SCOX6Jc81o9hZLADEFx4o4qaK4/MQczLaPkESO2578MI+eNwV3d02CIaUeSzK91b\n" +
            "ZlAsqUUXaxxOQ+0WcJpE1O+IUXoBJ7XSZAqfdogLVUM0A+wW8Duxthuh1j7z284B\n" +
            "NjWi9nPZnD3KT0vLv8KbwrW0XgiMzsaAdZKlexKZQuuzAOVNHb0hd3H36lBqAOPg\n" +
            "G0S+H7L3o8XAPcqkke2xs/tcfF05DX+kpD2xdeDWs9MK39FnGtYp8gTKoDkzf0vp\n" +
            "o2oUFe5cAKZHziOqNuoc7SUCAwEAAQ==\n" +
            "-----END PUBLIC KEY-----";
        subject.setPublicKey(publicKey);

        assertThat(subject.getKeyLength(), equalTo(4096));
      });

      it("should return 0 if the private key has not been set", () -> {
        assertThat(subject.getKeyLength(), equalTo(0));
      });
    });

    describe("#copyInto", () -> {
      it("should copy the correct properties into the other object", () -> {
        Instant frozenTime = Instant.ofEpochSecond(1400000000L);
        UUID uuid = UUID.randomUUID();
        UUID encryptionKeyUuid = UUID.randomUUID();

        subject = new NamedRsaSecret("/foo");
        subject.setPublicKey("fake-public-key");
        subject.setEncryptedValue("fake-private-key".getBytes());
        subject.setNonce("fake-nonce".getBytes());
        subject.setUuid(uuid);
        subject.setVersionCreatedAt(frozenTime);
        subject.setEncryptionKeyUuid(encryptionKeyUuid);

        NamedRsaSecret copy = new NamedRsaSecret();
        subject.copyInto(copy);

        assertThat(copy.getName(), equalTo("/foo"));
        assertThat(copy.getPublicKey(), equalTo("fake-public-key"));
        assertThat(copy.getEncryptedValue(), equalTo("fake-private-key".getBytes()));
        assertThat(copy.getNonce(), equalTo("fake-nonce".getBytes()));
        assertThat(copy.getEncryptionKeyUuid(), equalTo(encryptionKeyUuid));

        assertThat(copy.getUuid(), not(equalTo(uuid)));
        assertThat(copy.getVersionCreatedAt(), not(equalTo(frozenTime)));
      });
    });
  }
}
