Using `dumpshake`
-----
At this point, `dumpshake` only handles TLS Client Hello messages. To obtain the appropriate data, you can use Wireshark
and restrict it to capture packets to and from the host in question (i.e. set your capture filter to `host <domain
name>`). Start the capture, connect to the host, and select the Client Hello you're interested in. Select the "Secure
Sockets Layer" frame in the middle section of the Wireshark window (the human-readable display), right click, and select
"Export Selected Packet Bytes". This allows you to save just the TLS client hello message.

If you `cargo run <those exported packet bytes>` you'll get something like this:

    outer version: 0x0301
    inner version: 0x303
    ciphersuites:
      0x1301(TLS_AES_128_GCM_SHA256)
      0x1303(TLS_CHACHA20_POLY1305_SHA256)
      0x1302(TLS_AES_256_GCM_SHA384)
      0xc02b(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
      0xc02f(TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
      0xcca9(TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256)
      0xcca8(TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256)
      0xc02c(TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384)
      0xc030(TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384)
      0xc00a(TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA)
      0xc009(TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA)
      0xc013(TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA)
      0xc014(TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA)
      0x0033(TLS_DHE_RSA_WITH_AES_128_CBC_SHA)
      0x0039(TLS_DHE_RSA_WITH_AES_256_CBC_SHA)
      0x002f(TLS_RSA_WITH_AES_128_CBC_SHA)
      0x0035(TLS_RSA_WITH_AES_256_CBC_SHA)
      0x000a(TLS_RSA_WITH_3DES_EDE_CBC_SHA)
    compression methods:
      TlsCompressionID::Null
    extensions:
      TlsExtension::SNI(["type=0x0,name=example.com"])
      TlsExtension::ExtendedMasterSecret
      TlsExtension::RenegotiationInfo(data=[])
      TlsExtension::EllipticCurves([
        EcdhX25519,
        Secp256r1,
        Secp384r1,
        Secp521r1,
        Ffdhe2048,
        Ffdhe3072,
      ])
      TlsExtension::EcPointFormats([0])
      TlsExtension::SessionTicket(data=[])
      TlsExtension::ALPN([
        h2,
        http/1.1,
      ])
      TlsExtension::StatusRequest(Some((1, [0, 0, 0, 0])))
      TlsExtension::KeyShare(data=[00 69 00 1d 00 20 56 3e ...])
      TlsExtension::SupportedVersions(v=["0x7f1c", "0x303", "0x302", "0x301"])
      TlsExtension::SignatureAlgorithms([
        Sha256/Ecdsa,
        Sha384/Ecdsa,
        Sha512/Ecdsa,
        <Unknown hash 0x8>/<Unknown signature 0x4>,
        <Unknown hash 0x8>/<Unknown signature 0x5>,
        <Unknown hash 0x8>/<Unknown signature 0x6>,
        Sha256/Rsa,
        Sha384/Rsa,
        Sha512/Rsa,
        Sha1/Ecdsa,
        Sha1/Rsa,
      ])
      TlsExtension::PskExchangeModes([1])
      TlsExtension::Unknown(id=0x1c,data=[64, 1])
      TlsExtension::Padding(data=[0, 0, 0, ...])

This is probably not useful on its own, particularly if you're trying to figure out why a connection succeeds in one
version of a client but not another. To that end, you can also capture the Client Hello from the version you want to
compare. Given these two files, you can use a diff tool on the output from running `dumpshake`:

`$ diff <(cargo run clientHello-1) <(cargo run clientHello-2)`

    43,44c43,44
    <   TlsExtension::KeyShare(data=[00 69 00 1d 00 20 56 3e ...])
    <   TlsExtension::SupportedVersions(v=["0x7f1c", "0x303", "0x302", "0x301"])
    ---
    >   TlsExtension::KeyShare(data=[00 69 00 1d 00 20 70 a2 ...])
    >   TlsExtension::SupportedVersions(v=["0x304", "0x303", "0x302", "0x301"])

Key shares are mostly opaque data, and in any case they're consistent with each other here, so that's probably not
causing the breakage. Looking at the supported versions, however, we see that the first Client Hello includes the draft
version `0x1c` (or 28 in base-10) whereas the second Client Hello does not include any draft versions but rather the
final TLS version 1.3. Consequently, I suspect the issue is that the server is running a prerelease version of OpenSSL
1.1.1 that fails when clients use TLS 1.3 rather than a draft version (see [this
issue](https://github.com/openssl/openssl/issues/7315)).

