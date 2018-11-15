package contracts.v2.permissions

org.springframework.cloud.contract.spec.Contract.make {
    request {
        method 'GET'
        url '/api/v2/permissions?actor=uaa-client:user-a&path=/some-path'
        headers {
            header("Authorization": "Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6ImxlZ2FjeS10b2tlbi1rZXkiLCJ0eXAiOiJKV1QifQ.eyJqdGkiOiI0NWRjYTFiM2UzMGY0NDhjYjE5Y2U4YTVkYzRhMDdmYyIsInN1YiI6InVzZXItYSIsImF1dGhvcml0aWVzIjpbImNyZWRodWIud3JpdGUiLCJjcmVkaHViLnJlYWQiXSwic2NvcGUiOlsiY3JlZGh1Yi53cml0ZSIsImNyZWRodWIucmVhZCJdLCJjbGllbnRfaWQiOiJ1c2VyLWEiLCJjaWQiOiJ1c2VyLWEiLCJhenAiOiJ1c2VyLWEiLCJncmFudF90eXBlIjoiY2xpZW50X2NyZWRlbnRpYWxzIiwicmV2X3NpZyI6ImRlNTQxYmEwIiwiaWF0IjoxNDkxMjQ0NzgwLCJleHAiOjMwNjgwNDQ3ODAsImlzcyI6Imh0dHBzOi8vZXhhbXBsZS5jb206ODQ0My9vYXV0aC90b2tlbiIsInppZCI6InVhYSIsImF1ZCI6WyJjcmVkaHViX3Rlc3QiLCJjcmVkaHViIl19.HTb34y27XKGxX3Dx5---LCNt6RpbJzja2rB1oNsB3qdSujKrU4kt5yWROnOwkMlmXxBb7MLIIYg3wxIWMDTdR_ltyalXwcfEuviRYx-iPzu97BPe0Y39Xdj7fW7DtbgDOVISRpBR7I0cEsAjjZmAmQl5eLHqqxMQIYh__GpP-KnKuFy-wvv7Q6TnERV71kvlG7TqKzohz1zIY-vfUlxFXwZBzoBGX8OVgjyDZtq3LmHFxe5A5dHV5hGhbe473WYR74smJ4MXa-Y8zmkc2SQ7LQhuTFN9BOEKuNd6X-Y0zSvNf75oefvup3yC9jCTe2gajk8m7Lw5yXeMyhiTBqdnDQ")
        }
    }
    response {
        status 200
        body("""
            {
               "path":"/some-path",
               "operations":[
                  "read",
                  "write"
               ],
               "actor":"uaa-client:user-a",
               "uuid":"${UUID.nameUUIDFromBytes("some-permission-uuid".getBytes())}"
            }
        """)
    }
}