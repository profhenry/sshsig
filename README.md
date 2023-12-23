<!--
![License](https://img.shields.io/github/license/profhenry/sshsig)
![Build Status](https://img.shields.io/github/actions/workflow/status/profhenry/sshsig/maven.yml)
-->

[![License][license-image]][license-url]
[![Build Status](https://github.com/profhenry/sshsig/actions/workflows/maven.yml/badge.svg?branch=main)](https://github.com/profhenry/sshsig/actions/workflows/maven.yml)



SSH signatures for Java
====

This Java library implements the OpenSSH lightweight signature (and verification) ability introduced with [OpenSSH 8.1][openssh-8.1].
It allows to sign (and verify) messages using SSH keys according to the [SSHSIG][sshsig-protocol] protocol.

With OpenSSH signing a string can be done with
```bash
echo -n "a message" | ssh-keygen -Y sign -f ~/.ssh/id_rsa -n namespace
```
For further details please take a look at the [manual][manual-ssh-keygen-sign] or read [this][blog-on-using-ssh-sigatures] blog post.

Using this Java library signing a string looks like
```java
KeyPairGenerator tKeyPairGenerator = KeyPairGenerator.getInstance("RSA");
KeyPair tKeyPair = tKeyPairGenerator.generateKeyPair();
SshSignatureGenerator.create().generateSignature(tKeyPair, "namespace", "a message");
```

Both cases will produce a SSH signature like this
```
-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAARcAAAAHc3NoLXJzYQAAAAMBAAEAAAEBALA0KowyjU+T+2fneoWjy+
E77uDPEvSR0P4fIqNdZQqIZuuMsp5pdUit7TjRSkZovi242ph4E8a48cv7SNh3f6FzNSnp
V3ezEO6loUJv9Np8R13K1UdVlKnfgIIY6p34uP1yfF0OtmDx4w1yXHRI9OBuX6fiOLtr8K
KcimBC/nj+PCRDv6j7mV0n/AaTM4AHWBAS3K57dFjN7SUaVzbgHqsO2R1S73FIUeOwqrB4
ZgEmzjgp7UAmeURIVm3Z6yb5HwLTgcm3xkg5gTfTdXLxSVy7rvrCJ/XzroRuOYZ9qZ8Ir5
SrbPrg+d/DgesVieJbPU9SoiSGJIi+g0Sqzx74NjUAAAAJbmFtZXNwYWNlAAAAAAAAAAZz
aGE1MTIAAAEUAAAADHJzYS1zaGEyLTUxMgAAAQBtJI52xDjK2YophJ2exajqXv5CijxQKF
EBRKZDwi9ubJjehW4d02PAw63TMfp79PJOMeNeZajIV2aHo/+02ngePH4ht27PbHh+a/QK
lhQMr2nTfttL0WMnJYzfpJytWYGwOfg/xJcRgY6JqSJrvNlLzFiscwzWdMY6Van0v/E0vw
Bwv1pJqVQ76emr6xHuI0w1a7Huwwc7uctVWELuR+hJFLdPbchPsvGT0fHhY8GZZmZuzXSr
orKi7Tp76vnpyea2b8DjezozO9Jaa3YP3G+HohhEZMtAtgtW7q9Ujtv1Sc1yDtZFcb+tcB
vCvdb4l8M3+27D17NHb6Fg9iID2G5W
-----END SSH SIGNATURE-----
```

Features
---

* Required minimal Java runtime: 8
* Minimal 3rd party dependencies (only [slf4j])
* Content to be signed can be provided as string, byte array, file or as input stream
* Supported ssh key types: Dsa, Rsa, Ed25519
* Pluggable signing backend: The default backend uses the [Java Cryptography Architecture (JCA)][JCA] but we also provide an alternative backend which facilitates using an SSH-Agent via [Apache MINA]. 
* Works with other JCA/JCE provider, tested with [Bouncy Castle] or [net.i2p.crypto:eddsa] 
* (OSGi bundle) still pending
* (Command line client) still pending

Usage
---

Released artifacts are available at [Maven Central][mvnrepo-sshsig].

We provide the following artifacts:

* *sshsig-core* - contains the core implementation including the default JCA signing backend 
* *sshsig-mina* - contains the Apache MINA signing backend
* (*sshsig-cli* - contains the command line interface) still pending

You need at least *sshsig-core* which contains a fully functional implementation.

For consuming via maven add the following snippet to your pom.xml
```xml
<dependency>
    <groupId>de.profhenry.sshsig</groupId>
    <artifactId>sshsig-core</artifactId>
    <version>1.0.0</version>
</dependency>
```

For consuming via gradle add the following snippet to your build.gradle
```groovy
implementation group: 'de.profhenry.sshsig', name: 'sshsig-core', version: '1.0.0'
```

All other artifacts are optional and only required in case you need their provided features. 















[license-image]: https://img.shields.io/badge/license-apache%20v2-brightgreen.svg
[license-url]: https://github.com/profhenry/sshsig/blob/master/LICENSE
[sshsig-protocol]: https://github.com/openssh/openssh-portable/blob/V_9_5_P1/PROTOCOL.sshsig
[openssh-8.1]: https://www.openssh.com/txt/release-8.1
[blog-on-using-ssh-sigatures]: https://www.agwa.name/blog/post/ssh_signatures
[manual-ssh-keygen-sign]: https://man.openbsd.org/ssh-keygen#Y~4
[slf4j]: https://www.slf4j.org/
[JCA]: https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html
[Bouncy Castle]: https://www.bouncycastle.org/
[net.i2p.crypto:eddsa]: https://github.com/str4d/ed25519-java
[Apache MINA]: https://mina.apache.org/mina-project/index.html
[mvnrepo-sshsig]: https://mvnrepository.com/artifact/de.profhenry.sshsig

