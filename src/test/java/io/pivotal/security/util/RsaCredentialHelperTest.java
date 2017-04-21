package io.pivotal.security.util;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.entity.RsaCredentialData;
import org.junit.runner.RunWith;

import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.itThrows;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;

@RunWith(Spectrum.class)
public class RsaCredentialHelperTest {

  {
    describe("#getKeyLength", () -> {
      it("should return the length of the public key", () -> {
        RsaCredentialData rsaCredentialData = new RsaCredentialData("testRsa");
        String publicKey = "-----BEGIN PUBLIC KEY-----\n"
            + "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAoRIqdibiYHKZhyH91xYR\n"
            + "Tpz728+A8d/t2U2e8OIhNqI7pjh5uKnbmeoAXdZAbGN3TW7xArdMAUOSRhELH0Gc\n"
            + "8XGz6ZnY+KGuTnmBO+ZamE3kltwqJBfxwV2UGV5bJIVVToLpLa1GDF4p7g8I8W/a\n"
            + "KURKCgMNlRQw38Wi8yuEWyCHWHrqon8CcA5ovUg1pyrpR9i+5NTCRadDf1JIQfKB\n"
            + "Mt/gA/s6+ZaWOB6mbWv67OUS5wHWe0tcX2g4KK3IDlkzKQulSHQoIPEf+7l+vJEJ\n"
            + "KT+C2cI+pl/qLVtbY+jsNr8acxja0ri4pUGEQPKP5009qisloEDlQMb/gMT5aHoF\n"
            + "8GORc1EloUG4CpnPUe0L63Q3uSZkLSPAiYqwCi7Wu/L7aVeynGk3CFIPALyh/hIi\n"
            + "SCOX6Jc81o9hZLADEFx4o4qaK4/MQczLaPkESO2578MI+eNwV3d02CIaUeSzK91b\n"
            + "ZlAsqUUXaxxOQ+0WcJpE1O+IUXoBJ7XSZAqfdogLVUM0A+wW8Duxthuh1j7z284B\n"
            + "NjWi9nPZnD3KT0vLv8KbwrW0XgiMzsaAdZKlexKZQuuzAOVNHb0hd3H36lBqAOPg\n"
            + "G0S+H7L3o8XAPcqkke2xs/tcfF05DX+kpD2xdeDWs9MK39FnGtYp8gTKoDkzf0vp\n"
            + "o2oUFe5cAKZHziOqNuoc7SUCAwEAAQ==\n"
            + "-----END PUBLIC KEY-----";
        rsaCredentialData.setPublicKey(publicKey);
        RsaCredentialHelper rsaHelper = new RsaCredentialHelper(rsaCredentialData);

        assertThat(rsaHelper.getKeyLength(), equalTo(4096));
      });

      it("should return 0 if the public key has not been set", () -> {
        RsaCredentialData rsaCredentialData = new RsaCredentialData("testRsa");
        RsaCredentialHelper rsaHelper = new RsaCredentialHelper(rsaCredentialData);

        assertThat(rsaHelper.getKeyLength(), equalTo(0));
      });

      itThrows("a RuntimeException when an invalid key is passed to the helper",
          RuntimeException.class, () -> {
            RsaCredentialData rsaCredentialData = new RsaCredentialData("testRsa");
            String publicKey = "This is a key that is obviously incorrect. Is it not?";
            rsaCredentialData.setPublicKey(publicKey);
            RsaCredentialHelper rsaHelper = new RsaCredentialHelper(rsaCredentialData);

            rsaHelper.getKeyLength();
          });
    });

  }
}
