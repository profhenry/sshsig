[![License][license-image]][license-url]
[![Build Status](https://github.com/profhenry/sshsig/actions/workflows/maven.yml/badge.svg?branch=main)](https://github.com/profhenry/sshsig/actions/workflows/maven.yml)



SSH signatures for Java
====

This Java library implements the OpenSSH lightweight signature (and verification) ability introduced with [OpenSSH 8.1][openssh-8.1].
It allows to sign (and verify) messages using SSH keys according to the [SSHSIG][sshsig-protocol] protocol.

In OpenSSH signing a string can be done with `echo -n "a message" | ssh-keygen -Y sign -f ~/.ssh/id_rsa -n namespace`.
For further details please take a look at the [manual][manual-ssh-keygen-sign] or read [this][blog-on-using-ssh-sigatures] blog post.

Using this library signing a string might look like
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



























[license-image]: https://img.shields.io/badge/license-apache%20v2-brightgreen.svg
[license-url]: https://github.com/profhenry/sshsig/blob/master/LICENSE
[sshsig-protocol]: https://github.com/openssh/openssh-portable/blob/V_9_5_P1/PROTOCOL.sshsig
[openssh-8.1]: https://www.openssh.com/txt/release-8.1
[blog-on-using-ssh-sigatures]: https://www.agwa.name/blog/post/ssh_signatures
[manual-ssh-keygen-sign]: https://man.openbsd.org/ssh-keygen#Y~4

