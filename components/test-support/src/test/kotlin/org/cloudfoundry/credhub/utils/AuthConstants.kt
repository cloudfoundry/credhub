package org.cloudfoundry.credhub.utils

class AuthConstants {
    private constructor()

    companion object {
        // Actor ID: uaa-user:df0c1a26-2875-4bf5-baf9-716c6bb5ea6d
        // Grant type: password
        // Client ID: credhub_cli
        // User ID: df0c1a26-2875-4bf5-baf9-716c6bb5ea6d

        // JWT token signed by private key for public key in `application-unit-test.yml`
        // Valid for about 50 years!!!
        // Check and change at jwt.io
        const val ALL_PERMISSIONS_ACTOR_ID: String = "uaa-client:all-permissions"

        const val ALL_PERMISSIONS_TOKEN: String =
            "eyJhbGciOiJSUzI1NiIsImtpZCI6ImxlZ2FjeS10b2tlbi1rZXkiLCJ0eXAiOiJKV" +
                "1QifQ.eyJqdGkiOiI0NWRjYTFiM2UzMGY0NDhjYjE5Y2U4YTVkYzRhMDd" +
                "mYyIsInN1YiI6ImFsbC1wZXJtaXNzaW9ucyIsImF1dGhvcml0aWVzIjpb" +
                "ImNyZWRodWIud3JpdGUiLCJjcmVkaHViLnJlYWQiXSwic2NvcGUiOlsiY" +
                "3JlZGh1Yi53cml0ZSIsImNyZWRodWIucmVhZCJdLCJjbGllbnRfaWQiOi" +
                "JhbGwtcGVybWlzc2lvbnMiLCJjaWQiOiJhbGwtcGVybWlzc2lvbnMiLCJ" +
                "henAiOiJhbGwtcGVybWlzc2lvbnMiLCJncmFudF90eXBlIjoiY2xpZW50" +
                "X2NyZWRlbnRpYWxzIiwicmV2X3NpZyI6ImRlNTQxYmEwIiwiaWF0IjoxN" +
                "DkxMjQ0NzgwLCJleHAiOjMwNjgwNDQ3ODAsImlzcyI6Imh0dHBzOi8vZX" +
                "hhbXBsZS5jb206ODQ0My9vYXV0aC90b2tlbiIsInppZCI6InVhYSIsIm" +
                "F1ZCI6WyJjcmVkaHViX3Rlc3QiLCJjcmVkaHViIl19.dx9-2uYxzKY47" +
                "mL255Fa8NlhFeS0zIotQMHGfws3hPQLx5nwmC7Ekt9A0j8zwZ8ibRrXEW" +
                "Dj9EAuzv3wd9AQiqeeCwLWkffgNK7d4WM-xVW1o-rzAq5303uu__i4nBB" +
                "kZ9FLgi_0ADmjMzo8ElC-nX9HaahYi6B30jLD8l0rEmFL9Vcrh-8Y93qh" +
                "8fKhQ1hVPyCf37IVf_alyKLUHm9OloSGLlu0ARzxGq8F1XO5cpxiSiYZp" +
                "qu8qUynBJjhNyMSNqHssQ-8aXFupAdxGk51uNZe88yyjffFHU2PDGme1A" +
                "78v3chj2MNj76JJ0gA0uvs65tCg69VmxEDH1M0iTdS2A"

        const val NO_PERMISSIONS_ACTOR_ID: String = "uaa-client:no-permissions"

        const val NO_PERMISSIONS_TOKEN: String =
            "eyJhbGciOiJSUzI1NiIsImtpZCI6ImxlZ2FjeS10b2tlbi1rZXkiLCJ0eXAiOiJK" +
                "V1QifQ.eyJqdGkiOiI0NWRjYTFiM2UzMGY0NDhjYjE5Y2U4YTVkYzRhMD" +
                "dmYyIsInN1YiI6Im5vLXBlcm1pc3Npb25zIiwiYXV0aG9yaXRpZXMiOls" +
                "iY3JlZGh1Yi53cml0ZSIsImNyZWRodWIucmVhZCJdLCJzY29wZSI6Wy" +
                "JjcmVkaHViLndyaXRlIiwiY3JlZGh1Yi5yZWFkIl0sImNsaWVudF9pZ" +
                "CI6Im5vLXBlcm1pc3Npb25zIiwiY2lkIjoibm8tcGVybWlzc2lvbnMi" +
                "LCJhenAiOiJuby1wZXJtaXNzaW9ucyIsImdyYW50X3R5cGUiOiJjbGl" +
                "lbnRfY3JlZGVudGlhbHMiLCJyZXZfc2lnIjoiZGU1NDFiYTAiLCJpYX" +
                "QiOjE0OTEyNDQ3ODAsImV4cCI6MzA2ODA0NDc4MCwiaXNzIjoiaHR0c" +
                "HM6Ly9leGFtcGxlLmNvbTo4NDQzL29hdXRoL3Rva2VuIiwiemlkIjoi" +
                "dWFhIiwiYXVkIjpbImNyZWRodWJfdGVzdCIsImNyZWRodWIiXX0.E1j" +
                "pMhOch-CjoFSHFJvenxSKApI71fgVO5QIR1M0B5EVq-McFPtLXUDU_W" +
                "LYaSIDbPO7cFDV8Ys0owDqXJ4gjrtRXRoLGS6PW5kVrPytsWI9Z0D-v" +
                "a7h80yiFD2AjwUmDot4_lPL7IxQBv1JJQ3k_l7uAkJqEADSNwuZn1-M" +
                "RhScPT9Zh2HphD9tbGTFwdHWKaALC2ElAUgETj56Ui4XlgzXg4q4UOP" +
                "pLp4UZO8kP50GIURV-YYOb42t4xK_kiM6fqBdFcTjBkiXh08IdhJssH" +
                "A2uJOahk9tl1EMzTfUqHEVsEaaPyXb7cy0b6NKDB3cTsW-kAWUB44I8" +
                "s7rMR14VA"

        const val USER_A_ACTOR_ID: String = "uaa-client:user-a"

        const val USER_A_TOKEN: String =
            "eyJhbGciOiJSUzI1NiIsImtpZCI6ImxlZ2FjeS10b2tlbi1rZXkiLCJ0e" +
                "XAiOiJKV1QifQ.eyJqdGkiOiI0NWRjYTFiM2UzMGY0NDhjYjE" +
                "5Y2U4YTVkYzRhMDdmYyIsInN1YiI6InVzZXItYSIsImF1dGhv" +
                "cml0aWVzIjpbImNyZWRodWIud3JpdGUiLCJjcmVkaHViLnJlY" +
                "WQiXSwic2NvcGUiOlsiY3JlZGh1Yi53cml0ZSIsImNyZWRodW" +
                "IucmVhZCJdLCJjbGllbnRfaWQiOiJ1c2VyLWEiLCJjaWQiOiJ" +
                "1c2VyLWEiLCJhenAiOiJ1c2VyLWEiLCJncmFudF90eXBlIjoi" +
                "Y2xpZW50X2NyZWRlbnRpYWxzIiwicmV2X3NpZyI6ImRlNTQxY" +
                "mEwIiwiaWF0IjoxNDkxMjQ0NzgwLCJleHAiOjMwNjgwNDQ3OD" +
                "AsImlzcyI6Imh0dHBzOi8vZXhhbXBsZS5jb206ODQ0My9vYXV" +
                "0aC90b2tlbiIsInppZCI6InVhYSIsImF1ZCI6WyJjcmVkaHVi" +
                "X3Rlc3QiLCJjcmVkaHViIl19.HTb34y27XKGxX3Dx5---LCNt" +
                "6RpbJzja2rB1oNsB3qdSujKrU4kt5yWROnOwkMlmXxBb7MLII" +
                "Yg3wxIWMDTdR_ltyalXwcfEuviRYx-iPzu97BPe0Y39Xdj7fW" +
                "7DtbgDOVISRpBR7I0cEsAjjZmAmQl5eLHqqxMQIYh__GpP-Kn" +
                "KuFy-wvv7Q6TnERV71kvlG7TqKzohz1zIY-vfUlxFXwZBzoBG" +
                "X8OVgjyDZtq3LmHFxe5A5dHV5hGhbe473WYR74smJ4MXa-Y8z" +
                "mkc2SQ7LQhuTFN9BOEKuNd6X-Y0zSvNf75oefvup3yC9jCTe2" +
                "gajk8m7Lw5yXeMyhiTBqdnDQ"

        const val USER_B_ACTOR_ID: String = "uaa-client:user-b"

        const val USER_B_TOKEN: String =
            "eyJhbGciOiJSUzI1NiIsImtpZCI6ImxlZ2FjeS10b2tlbi1rZXkiLC" +
                "J0eXAiOiJKV1QifQ.eyJqdGkiOiI0NWRjYTFiM2UzMGY0NDhj" +
                "YjE5Y2U4YTVkYzRhMDdmYyIsInN1YiI6InVzZXItYiIsImF1dG" +
                "hvcml0aWVzIjpbImNyZWRodWIud3JpdGUiLCJjcmVkaHViLnJlYWQ" +
                "iXSwic2NvcGUiOlsiY3JlZGh1Yi53cml0ZSIsImNyZWRodWIucmVhZ" +
                "CJdLCJjbGllbnRfaWQiOiJ1c2VyLWIiLCJjaWQiOiJ1c2VyLWIiLCJ" +
                "henAiOiJ1c2VyLWIiLCJncmFudF90eXBlIjoiY2xpZW50X2NyZWRlb" +
                "nRpYWxzIiwicmV2X3NpZyI6ImRlNTQxYmEwIiwiaWF0IjoxNDkxMjQ" +
                "0NzgwLCJleHAiOjMwNjgwNDQ3ODAsImlzcyI6Imh0dHBzOi8vZXhhb" +
                "XBsZS5jb206ODQ0My9vYXV0aC90b2tlbiIsInppZCI6InVhYSIsImF" +
                "1ZCI6WyJjcmVkaHViX3Rlc3QiLCJjcmVkaHViIl19.RtesPIQYqhcH" +
                "pH_YJttFHh5e31QNdWZTUxGMWMWUROxfM3_tK54ywM_02HzVTM0PWv" +
                "iybwDWtmda3GgwzGYXe-Of2TV2hsJk1SpiNFy2JJWligm0GiP6ft6w" +
                "T0zErRuRhfN8SJDpYQdxeTW4_onEQQfIaUXsrIopwSzV8hzVs2VAhp" +
                "3T54qPY7kNyrJdmz55AQ9X062_RPCDay6AvtzThF7rg72cLkgfeo7s" +
                "lDYYkjjZyqGC33ZpgVDzQJEsqXffz-e7LJ7jwET1DMnF823r7zxWlC" +
                "PYi8GVcoRESbeRJjnpwOWYEHl7RV80zzj57r3LRQZP2QTlvWzm2ARbMLQT6w"

        const val USER_A_PATH: String = "/user-a/"

        const val USER_B_PATH: String = "/user-b/"

        // Actor ID: uaa-user:df0c1a26-2875-4bf5-baf9-716c6bb5ea6d
        // Grant type: password
        // Client ID: credhub_cli
        // User ID: df0c1a26-2875-4bf5-baf9-716c6bb5ea6d
        const val INVALID_SCOPE_KEY_JWT: String =
            "eyJhbGciOiJSUzI1NiIsImtpZCI6ImxlZ2FjeS10b2tlbi1rZXkiLCJ0eXAiOi" +
                "JKV1QifQ.eyJqdGkiOiJlOWU1NzM5Y2QzODc0NDgzOGFjZjY4M2I3Y" +
                "WI0N2IwNCIsInN1YiI6ImRmMGMxYTI2LTI4NzUtNGJmNS1iYWY5LTc" +
                "xNmM2YmI1ZWE2ZCIsInNjb3BlIjpbImNyZWRodWIuYmFkX3Njb3BlI" +
                "l0sImNsaWVudF9pZCI6ImNyZWRodWJfY2xpIiwiY2lkIjoiY3JlZGh" +
                "1Yl9jbGkiLCJhenAiOiJjcmVkaHViX2NsaSIsImdyYW50X3R5cGUiO" +
                "iJwYXNzd29yZCIsInVzZXJfaWQiOiJkZjBjMWEyNi0yODc1LTRiZjU" +
                "tYmFmOS03MTZjNmJiNWVhNmQiLCJvcmlnaW4iOiJ1YWEiLCJ1c2VyX" +
                "25hbWUiOiJjcmVkaHViX2NsaSIsImVtYWlsIjoiY3JlZGh1Yl9jbGk" +
                "iLCJhdXRoX3RpbWUiOjE0OTA5MDMzNTMsInJldl9zaWciOiJlNDQzZ" +
                "DcxZSIsImlhdCI6MTQ5MDkwMzM1MywiZXhwIjozNDkwOTAzMzU0LCJ" +
                "pc3MiOiJodHRwczovL2V4YW1wbGUuY29tOjg0NDMvb2F1dGgvdG9rZ" +
                "W4iLCJ6aWQiOiJ1YWEiLCJhdWQiOlsiY3JlZGh1Yl9jbGkiLCJjcmV" +
                "kaHViIl19.Bo5ABjYR132PZAoPRQu4d8Oobx3FReRZHX42ZznyWMB5" +
                "gZFCfrkrkzpxl5hFO8Qo71_80KlRjciTS_xnYxLIlZL0xkh0IhNfEs" +
                "F1UlwuMt-9nyCD7BBJ3P8CJU1XS26NSTwkdxPTod4Bkq2zU6tTp5H5" +
                "YBbIjuxKm7R6qGHIe8eufvXRW_kD7urKX-fhshtilMAWRON6EbRn4" +
                "785dteNR4Hv7a6iUBwMA0RKm4S2_YYxm7wt5bUAUe5iMS8cQrqW1y" +
                "dFb-RZHtLiy03ggtSK-1nfMQtbSN6RrN7eyiNdDz1XqteIfl-UtqHq" +
                "YbFP2ZFq7M9cXs_lRKkR-csSCD40fA"

        // Actor ID: uaa-user:df0c1a26-2875-4bf5-baf9-716c6bb5ea6d
        // Grant type: password
        // Client ID: credhub_cli
        // User ID: df0c1a26-2875-4bf5-baf9-716c6bb5ea6d
        const val EXPIRED_KEY_JWT =
            "eyJhbGciOiJSUzI1NiIsImtpZCI6ImxlZ2FjeS10b2tlbi1rZXkiLCJ0eXAiOi" +
                "JKV1QifQ.eyJqdGkiOiJlOWU1NzM5Y2QzODc0NDgzOGFjZjY4M2I3Y" +
                "WI0N2IwNCIsInN1YiI6ImRmMGMxYTI2LTI4NzUtNGJmNS1iYWY5LTc" +
                "xNmM2YmI1ZWE2ZCIsInNjb3BlIjpbImNyZWRodWIud3JpdGUiLCJjc" +
                "mVkaHViLnJlYWQiXSwiY2xpZW50X2lkIjoiY3JlZGh1Yl9jbGkiLCJ" +
                "jaWQiOiJjcmVkaHViX2NsaSIsImF6cCI6ImNyZWRodWJfY2xpIiwiZ" +
                "3JhbnRfdHlwZSI6InBhc3N3b3JkIiwidXNlcl9pZCI6ImRmMGMxYTI" +
                "2LTI4NzUtNGJmNS1iYWY5LTcxNmM2YmI1ZWE2ZCIsIm9yaWdpbiI6I" +
                "nVhYSIsInVzZXJfbmFtZSI6ImNyZWRodWJfY2xpIiwiZW1haWwiOiJ" +
                "jcmVkaHViX2NsaSIsImF1dGhfdGltZSI6MTQ5MDkwMzM1MywicmV2X" +
                "3NpZyI6ImU0NDNkNzFlIiwiaWF0IjoxMDkwOTAzMzUzLCJleHAiOjE" +
                "yOTA5MDMzNTQsImlzcyI6Imh0dHBzOi8vZXhhbXBsZS5jb206ODQ0M" +
                "y9vYXV0aC90b2tlbiIsInppZCI6InVhYSIsImF1ZCI6WyJjcmVkaHV" +
                "iX2NsaSIsImNyZWRodWIiXX0.PWEChjBzs3WIM3hDG55Vgct8DE7iH" +
                "JxI83EcGI9jazM3Cip2DHo4il1k1SeQG2aqofmFZ_SObWQW-vxPc0c" +
                "SCnF8dcqeSjBsjrrBGB5T1hwE0wS_nmP4vxuz1wPTIQZKXbpVvF3m7" +
                "K9m79ogL8eWQz8rDhoo7JYEhlDJ2VyZ0dsTDpwQY4EGdvh1GtMsrun" +
                "-T5P98gav2XeAcOu1XQGQNBV2RhZ0T7olugyDxbaSLuG7AJPh2e6yg" +
                "PWcldRL7hJhG3q4Uo9iNbyp3Nmn_CXWppyQHMFYl8wwlFVZf6hU0no" +
                "sUJ8I4LjGbA3165PEmKI-ZMlcQ6LJWUloL7vJG1eUAA"

        // Actor ID: uaa-user:9302d419-79e5-474d-ae4f-252206144db6
        // Grant type: password
        // Client ID: credhub_cli
        // User ID: 9302d419-79e5-474d-ae4f-252206144db6
        const val INVALID_JSON_JWT =
            "eyJhbGciOiJSUzI1NiJ9.ewogICJqdGkiOiAiNGE3ZjY0MWVkOGExNDI1Njk2N" +
                "WQxYjNmYmFlNjcxNGUiLAogICJzdWIiOiAiOTMwMmQ0MTktNzllNS0" +
                "0NzRkLWFlNGYtMjUyMjA2MTQ0ZGI2IiwKICAic2NvcGUiOiBbCiAgI" +
                "CAiY3JlZGh1Yi53cml0ZSIsCiAgICAiY3JlZGh1Yi5yZWFkIgogIF0" +
                "sCiAgImNsaWVudF9pZCI6ICJjcmVkaHViX2NsaSIsCiAgImNpZCI6I" +
                "CJjcmVkaHViX2NsaSIsCiAgImF6cCI6ICJjcmVkaHViX2NsaSIsCiA" +
                "gInJldm9jYWJsZSI6IHRydWUsCiAgImdyYW50X3R5cGUiOiAicGFzc" +
                "3dvcmQiLAogICJ1c2VyX2lkIjogIjkzMDJkNDE5LTc5ZTUtNDc0ZC1" +
                "hZTRmLTI1MjIwNjE0NGRiNiIsCiAgIm9yaWdpbiI6ICJ1YWEiLAogI" +
                "CJ1c2VyX25hbWUiOiAiY3JlZGh1YiIsCiAgImVtYWlsIjogImNyZWR" +
                "odWIiLAogICJhdXRoX3RpbWUiOiAxNDkwODE4MzgwLAogICJyZXZfc" +
                "2lnIjogIjgzOWFhZGQ3IiwKICAiaWF0IjogMTQ5MDgxODM4MCwKICA" +
                "iZXhwIjogMTQ5MDkwNDc4MCwKICAiaXNzIjogImh0dHBzOi8vZXhhb" +
                "XBsZS5jb206ODQ0My9vYXV0aC90b2tlbiIsCiAgInppZCI6ICJ1YWE" +
                "iLAogICJhdWQiOiBbCiAgICAiY3JlZGh1Yl9jbGkiLAogICAgImNyZ" +
                "WRodWIiCiAgXQo.jrsrDFfNKKtrtBt7AqUFm2orXlCVvil_kB4eEZ0" +
                "z7FfZ29L8hLmiLGE7prVV_hvGgJnL0uco_bCCWNYZ1h69gARJj6NNY" +
                "b0Uwo_gn3kXl5DmJ2Z071BbvbQx4fQhSKYvcZJZmqlviZV6LsU12n3" +
                "1Rtbuq77CzGyWh75H3I7iR98-5dc3hVLEcIS2pHrry6LSIX5Xc-DmH" +
                "z8p-58h4hbWJf_mIgHnm-GUbH26gkt8dSw2OXfR-WLDxbldjKzKmmv" +
                "Cjg1H1GsouDNtxQUGtC5aVLdo9RnJa6e0xdzYr_g8J2jY94hbS66ml" +
                "1m1jWx_urNoI2R1w_vrrpB16jzS30o8Pg"

        // Actor ID: uaa-user:1cc4972f-184c-4581-987b-85b7d97e909c
        // Grant type: password
        // Client ID: credhub
        // User ID: 1cc4972f-184c-4581-987b-85b7d97e909c
        const val INVALID_SIGNATURE_JWT: String =
            "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJiOTc3NzIxNGI1" +
                "ZDM0Zjc4YTJlMWMxZjZkYjJlYWE3YiIsInN1YiI6IjFjYzQ5NzJmL" +
                "TE4NGMtNDU4MS05ODdiLTg1YjdkOTdlOTA5YyIsInNjb3BlIjpbIm" +
                "NyZWRodWIud3JpdGUiLCJjcmVkaHViLnJlYWQiXSwiY2xpZW50X2l" +
                "kIjoiY3JlZGh1YiIsImNpZCI6ImNyZWRodWIiLCJhenAiOiJjcmVk" +
                "aHViIiwiZ3JhbnRfdHlwZSI6InBhc3N3b3JkIiwidXNlcl9pZCI6I" +
                "jFjYzQ5NzJmLTE4NGMtNDU4MS05ODdiLTg1YjdkOTdlOTA5YyIsIm" +
                "9yaWdpbiI6InVhYSIsInVzZXJfbmFtZSI6ImNyZWRodWJfY2xpIiw" +
                "iZW1haWwiOiJjcmVkaHViX2NsaSIsImF1dGhfdGltZSI6MTQ2OTA1" +
                "MTcwNCwicmV2X3NpZyI6ImU1NGFiMzlhIiwiaWF0IjoxNDY5MDUxN" +
                "zA0LCJleHAiOjM0NjkwNTE4MjQsImlzcyI6Imh0dHBzOi8vZXhhbX" +
                "BsZS5jb206ODQ0My9vYXV0aC90b2tlbiIsInppZCI6InVhYSIsImF" +
                "1ZCI6WyJjcmVkaHViIl19.fCu86RFbzyx_GBf0Mx8SJ8HQN0JuFbn" +
                "QqodKOUl0cF3omntMIcaoowB-BhwcAc0kd1HZrn6Ba3lTI2GPtemH" +
                "6BdmGdK5Uh4u5kMku7J-bDOT4xtMwqKBmucY47sHc0hltUduLE7kf" +
                "JLjTmg-Jzw6pAjeh-W4p9ul_tgW5XDJYn47H8ho1KvpiJWWGwFral" +
                "grrZDQPte6-J-QQWhgnBX3RWs3BxBqB-5pdB0jJ41ryQMTqmZTzrt" +
                "ZF3XbvBjt2gdmUsafzTYm7Wefv0xa92CJwrrS-urOR1G4bCLO8eAV" +
                "Fzl4vKGDDtImQ-4f3N7vsuH19qvMV4lWYGLzy36TADUp4Q"

        const val INVALID_ISSUER_JWT: String =
            "eyJhbGciOiJSUzI1NiIsImtpZCI6ImxlZ2FjeS10b2tlbi1rZXkiLCJ0eXAi" +
                "OiJKV1QifQ.eyJqdGkiOiI5YTk3YWVlNjVhYWY0Yzc0ODVhMTZmZ" +
                "WU1MWY5NTVmMSIsInN1YiI6ImRmMGMxYTI2LTI4NzUtNGJmNS1iY" +
                "WY5LTcxNmM2YmI1ZWE2ZCIsInNjb3BlIjpbImNyZWRodWIud3Jpd" +
                "GUiLCJjcmVkaHViLnJlYWQiXSwiY2xpZW50X2lkIjoiY3JlZGh1Y" +
                "l9jbGkiLCJjaWQiOiJjcmVkaHViX2NsaSIsImF6cCI6ImNyZWRod" +
                "WJfY2xpIiwiZ3JhbnRfdHlwZSI6InBhc3N3b3JkIiwidXNlcl9pZ" +
                "CI6ImRmMGMxYTI2LTI4NzUtNGJmNS1iYWY5LTcxNmM2YmI1ZWE2Z" +
                "CIsIm9yaWdpbiI6InVhYSIsInVzZXJfbmFtZSI6ImNyZWRodWJfY" +
                "2xpIiwiZW1haWwiOiJjcmVkaHViX2NsaSIsImF1dGhfdGltZSI6M" +
                "TQ5MDkwNjA5MCwicmV2X3NpZyI6ImU0NDNkNzFlIiwiaWF0IjoxN" +
                "DkwOTAzMzUzLCJleHAiOjMwNjc3MDYwOTAsImlzcyI6ImlzX2lud" +
                "mFsaWQiLCJ6aWQiOiJ1YWEiLCJhdWQiOlsiY3JlZGh1Yl9jbGkiL" +
                "CJjcmVkaHViIl19.llBhxtpdpRWon-iLMopXsgOHNSqslG3PPTWn" +
                "gfsbFGaNQzbzHqqMQAJ5coDz54gUshwT8Ccvv2Qfl44KcNCpmL60" +
                "6gf72640tlUr2bftSdUhjOE4fvb3_57ViVMXj7pfuwaoDj3lFWxu" +
                "OqNw9UfwhTtf7xHCcta5TNozrJukehQ2qhLG0ZHzfj9JlVkcnN8H" +
                "G1aQCuymViSaH8KbREzaAUGDtYuqJ8CR4YYj7WVT585M2f0rf4qQ" +
                "B7AUvhybRqcjvfRSpghcCRKOtsuMs7SYhMLJH1nWOMGPbk2E-2qO" +
                "4i6GPG9ASmloogz2OGxsPzVpJTW44IuPiu5-zo-SQs4Tkg"

        const val NULL_ISSUER_JWT: String =
            "eyJhbGciOiJSUzI1NiIsImtpZCI6ImxlZ2FjeS10b2tlbi1rZXkiLCJ0eXAiOiJK" +
                "V1QifQ.eyJqdGkiOiI5YTk3YWVlNjVhYWY0Yzc0ODVhMTZmZWU1MWY5N" +
                "TVmMSIsInN1YiI6ImRmMGMxYTI2LTI4NzUtNGJmNS1iYWY5LTcxNmM2Y" +
                "mI1ZWE2ZCIsInNjb3BlIjpbImNyZWRodWIud3JpdGUiLCJjcmVkaHViL" +
                "nJlYWQiXSwiY2xpZW50X2lkIjoiY3JlZGh1Yl9jbGkiLCJjaWQiOiJjc" +
                "mVkaHViX2NsaSIsImF6cCI6ImNyZWRodWJfY2xpIiwiZ3JhbnRfdHlwZ" +
                "SI6InBhc3N3b3JkIiwidXNlcl9pZCI6ImRmMGMxYTI2LTI4NzUtNGJmN" +
                "S1iYWY5LTcxNmM2YmI1ZWE2ZCIsIm9yaWdpbiI6InVhYSIsInVzZXJfb" +
                "mFtZSI6ImNyZWRodWJfY2xpIiwiZW1haWwiOiJjcmVkaHViX2NsaSIsI" +
                "mF1dGhfdGltZSI6MTQ5MDkwNjA5MCwicmV2X3NpZyI6ImU0NDNkNzFlI" +
                "iwiaWF0IjoxNDkwOTAzMzUzLCJleHAiOjMwNjc3MDYwOTAsInppZCI6I" +
                "nVhYSIsImF1ZCI6WyJjcmVkaHViX2NsaSIsImNyZWRodWIiXX0.OsgEb" +
                "R1anAwcLAfbUuvR6E_HnQQZB08Al7rwXLzXrRtGdXCBf1BiCgGvITqfY" +
                "lh2E6rIB71kDOUL0lPGes60Hn7vnZOuhzdV7wheBwJ_hjhYL7WKzdeFA" +
                "kSTjAt8ETLW-9tM5YS8cnKeFSDN39dIzc9LtbnhOQCZByv9xIorhy_Mf" +
                "hH2EgVKFFKl9VOPn3r--XtN3g7e3t2R5bDyn7J-ROIrDbsPJxV0hR6Ur" +
                "LLyUDvc3DIxTT6KbMZrFyN292j-4MhDsbPt61_HrNzFJeZT0r8vA_UZH" +
                "3DowClEW3wGto9ftesz6G07V0IEpTUKcrb-Tgfvvd1OZorTOpHNaAkMPQ"

        const val EMPTY_ISSUER_JWT: String =
            "eyJhbGciOiJSUzI1NiIsImtpZCI6ImxlZ2FjeS10b2tlbi1rZXkiLCJ0eXAiOiJK" +
                "V1QifQ.eyJqdGkiOiI5YTk3YWVlNjVhYWY0Yzc0ODVhMTZmZWU1MWY5N" +
                "TVmMSIsInN1YiI6ImRmMGMxYTI2LTI4NzUtNGJmNS1iYWY5LTcxNmM2Y" +
                "mI1ZWE2ZCIsInNjb3BlIjpbImNyZWRodWIud3JpdGUiLCJjcmVkaHViL" +
                "nJlYWQiXSwiY2xpZW50X2lkIjoiY3JlZGh1Yl9jbGkiLCJjaWQiOiJjc" +
                "mVkaHViX2NsaSIsImF6cCI6ImNyZWRodWJfY2xpIiwiZ3JhbnRfdHlwZ" +
                "SI6InBhc3N3b3JkIiwidXNlcl9pZCI6ImRmMGMxYTI2LTI4NzUtNGJmN" +
                "S1iYWY5LTcxNmM2YmI1ZWE2ZCIsIm9yaWdpbiI6InVhYSIsInVzZXJfb" +
                "mFtZSI6ImNyZWRodWJfY2xpIiwiZW1haWwiOiJjcmVkaHViX2NsaSIsI" +
                "mF1dGhfdGltZSI6MTQ5MDkwNjA5MCwicmV2X3NpZyI6ImU0NDNkNzFlI" +
                "iwiaWF0IjoxNDkwOTAzMzUzLCJleHAiOjMwNjc3MDYwOTAsImlzcyI6I" +
                "iIsInppZCI6InVhYSIsImF1ZCI6WyJjcmVkaHViX2NsaSIsImNyZWRod" +
                "WIiXX0.TDs8kXA_QmGHaO7WMSqqjVtqZcjfbPI6ynjR2UsH2wX_c_Jaf" +
                "YTTdRDR-foaJyf9OhjrC45wWAiucn5l1CxdSbAxNtbP4M4AgQSik9tOl" +
                "0ivbW2R0T3omfZd4ZgLJZi1jSOFWyfQ8Pg1TLfI8nmtIUhMjzdGGR_hL" +
                "HuFZSEeIt0eGjtD2Y5IeqKV5-YJfJh5KZn7u-3GM5iCV7npBHRLqu9Ue" +
                "x78dZsHptbPGcePD54-_X-iu5rUHS3OSRWXUV4aCMRI7trmKjedD-yUE" +
                "RcIJa7Afm2DtdfzzVsQIbVpW_rjqny69W1mSxmp3eXQzbX5MbL-R75dc" +
                "5GS6OBz796oLA"

        const val VALID_ISSUER_JWT: String =
            "eyJhbGciOiJSUzI1NiIsImtpZCI6ImxlZ2FjeS10b2tlbi1rZXkiLCJ0eXAiOiJK" +
                "V1QifQ.eyJqdGkiOiI5YTk3YWVlNjVhYWY0Yzc0ODVhMTZmZWU1MWY5N" +
                "TVmMSIsInN1YiI6ImRmMGMxYTI2LTI4NzUtNGJmNS1iYWY5LTcxNmM2Y" +
                "mI1ZWE2ZCIsInNjb3BlIjpbImNyZWRodWIud3JpdGUiLCJjcmVkaHViL" +
                "nJlYWQiXSwiY2xpZW50X2lkIjoiY3JlZGh1Yl9jbGkiLCJjaWQiOiJjc" +
                "mVkaHViX2NsaSIsImF6cCI6ImNyZWRodWJfY2xpIiwiZ3JhbnRfdHlwZ" +
                "SI6InBhc3N3b3JkIiwidXNlcl9pZCI6ImRmMGMxYTI2LTI4NzUtNGJmN" +
                "S1iYWY5LTcxNmM2YmI1ZWE2ZCIsIm9yaWdpbiI6InVhYSIsInVzZXJfb" +
                "mFtZSI6ImNyZWRodWJfY2xpIiwiZW1haWwiOiJjcmVkaHViX2NsaSIsI" +
                "mF1dGhfdGltZSI6MTQ5MDkwNjA5MCwicmV2X3NpZyI6ImU0NDNkNzFlI" +
                "iwiaWF0IjoxNDkwOTAzMzUzLCJleHAiOjMwNjc3MDYwOTAsImlzcyI6I" +
                "mh0dHBzOi8vdmFsaWQtdWFhOjg0NDMvdWFhL29hdXRoL3Rva2VuIiwie" +
                "mlkIjoidWFhIiwiYXVkIjpbImNyZWRodWJfY2xpIiwiY3JlZGh1YiJdf" +
                "Q.YFmH-f6yJt-YyNMhQxSmiItdzOuzHwcW3WUYMaZ-XliW_vYhEg0eU7" +
                "eiCCU_pYdlnZVpXZysFyuq2gZ9MZ_wVXcvuBkVrm4WfXIyRb0tzmXp7W" +
                "qRPo70GyTYHv5vVC3kXKV7k4tekc2pys8-iGtN5C36SE6LmNDfucQYvw" +
                "WqUOTbvaH181UKVPM83tVwcJhJeT6oMiQzewBN16OqfDcRFyfb0KTxqe" +
                "4_JXZYK6uJ6t4yK7vAk-7CCiR1y0L4GfBobT8j3gM7BfHUNrRPRLvN9M" +
                "bB1-H3qMQu3mL08jHXi3m7mvU48A8e5t_pVuYQr5kXr5mLNJMzj0iK0N" +
                "iCfKhqCg"

        const val MALFORMED_TOKEN: String =
            "eyJhbGciOiJSUzI1NiIsImtpZCI6ImxlZ2FjeS10b2tlbi1rZXkiLCJ0eXAiOiJ" +
                "KV1QifQ.eyJqdGkiOiI5YTk3YWVlNjVhYWY0Yzc0ODVhMTZmZWU1MWY" +
                "5NTVmMSIsInN1YiI6ImRmMGMxYTI2LTI4NzUtNGJmNS1iYWY5LTcxNm" +
                "M2YmI1ZWE2ZCIsInNjb3BlIjpbImNyZWRodWIud3JpdGUiLCJjcmVkaH" +
                "ViLnJlYWQiXSwiY2xpZW50X2lkIjoiY3JlZGh1Yl9jbGkiLCJjaWQ" +
                "iOiJjcmVkaHViX2NsaSIsImF6cCI6ImNyZWRodWJfY2xpIiwiZ3Jhbn" +
                "RfdHlwZSI6InBhc3N3b3JkIiwidXNlcl9pZCI6ImRmMGMxYTI2LTI4Nz" +
                "UtNGJmNS1iYWY5LTcxNmM2YmI1ZWE2ZCIsIm9yaWdpbiI6InVhYSIsI" +
                "nVzZXJfbmFtZSI6ImNyZWRodWJfY2xpIiwiZW1haWwiOiJjcmVkaHViX" +
                "2NsaSIsImF1dGhfdGltZSI6MTQ5MDkwNjA5MCwicmV2X3NpZyI6ImU0" +
                "NDNkNzFlIiwiaWF0IjoxNDkwOTAzMzUzLCJleHAiOjMwNjc3MDYwOTAs" +
                "ImlzcyI6Imh0dHBzOi8vdmFsaWQtdWFhOjg0NDMvdWFhL29hdXRoL3Rv" +
                "a2VuIiwiemlkIjoidWFhIiwiYXVkIjpbImNyZWRodWJfY2xpIiwiY3Jl" +
                "ZGh1YiJdfQ.YFmH-f6yJt-YyNMhQxSmiItdzOuzHwcW3WUYMaZ-XliW_v" +
                "YhEg0eU7eiCCU_pYdlnZVpXZysFyuq2gZ9MZ_wVXcvuBkVrm4WfXIyRb0t" +
                "zmXp7WqRPo70GyTYHv5vVC3kXKV7k4tekc2pys8-iGtN5C36SE6LmNDf" +
                "ucQYvwWqUOTbvaH181UKVPM83tVwcJhJeT6oMiQzewBN16OqfDcRFyf" +
                "b0KTxqe4_JXZYK6uJ6t4yK7vAk-7CCiR1y0L4GfBobT8j3gM7BfHU" +
                "NrRPRLvN9MbB1-H3qMQu3mL08jHXi3m7mvU48A8e5t_pVuYQr5kXr5"

        const val EXPIRED_TOKEN: String =
            "eyJhbGciOiJSUzI1NiIsImtpZCI6ImxlZ2FjeS10b2tlbi1rZXkiLCJ0eXAiOiJKV" +
                "1QifQ.eyJqdGkiOiI5YTk3YWVlNjVhYWY0Yzc0ODVhMTZmZWU1MWY5NTVm" +
                "MSIsInN1YiI6ImRmMGMxYTI2LTI4NzUtNGJmNS1iYWY5LTcxNmM2YmI1" +
                "ZWE2ZCIsInNjb3BlIjpbImNyZWRodWIud3JpdGUiLCJjcmVkaHViLnJlY" +
                "WQiXSwiY2xpZW50X2lkIjoiY3JlZGh1Yl9jbGkiLCJjaWQiOiJjcmVkaHV" +
                "iX2NsaSIsImF6cCI6ImNyZWRodWJfY2xpIiwiZ3JhbnRfdHlwZSI6InBhc" +
                "3N3b3JkIiwidXNlcl9pZCI6ImRmMGMxYTI2LTI4NzUtNGJmNS1iYWY5LT" +
                "cxNmM2YmI1ZWE2ZCIsIm9yaWdpbiI6InVhYSIsInVzZXJfbmFtZSI6ImNy" +
                "ZWRodWJfY2xpIiwiZW1haWwiOiJjcmVkaHViX2NsaSIsImF1dGhfdGltZS" +
                "I6MTQ5MDkwNjA5MCwicmV2X3NpZyI6ImU0NDNkNzFlIiwiaWF0IjoxNDkw" +
                "OTAzMzUzLCJleHAiOjE1NTUzNDAwNDksImlzcyI6Imh0dHBzOi8vdmFsaW" +
                "QtdWFhOjg0NDMvdWFhL29hdXRoL3Rva2VuIiwiemlkIjoidWFhIiwiYXVkIj" +
                "pbImNyZWRodWJfY2xpIiwiY3JlZGh1YiJdfQ.lz_VGtlRtjKmB2nzTRP4ZQW" +
                "LgL5xnvVDgvYD_bbgwHL1vHRRniKLxb05UOzuCdWpH73GiJlNdLd2h" +
                "LCj5F4rkIjwHVD4nVznh9m6hnd-4-zzHC3VonjCteICu6EAc8l12nyb" +
                "kvGGODQMxJwXY4-DG3TdMx27q9eYt5FFVjZmfq-oQ0feinP5vS2Fe4VY" +
                "aEK0Vw_nPiuJagdgtPR0puSkAqJerYWNJ7vjNirafnATm5Bbnsqswt1v6" +
                "x4UiWUZeE7HB3VpwkPAnvACNXFURPcGoK04wIMOaAGKxoJEHtc77Y35gz" +
                "DeywZw9fLXYK0GAhVTFv0O9HRydc2e-zz3bsEwkg"
    }
}
