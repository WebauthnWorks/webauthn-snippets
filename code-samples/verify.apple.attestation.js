const crypto    = require('crypto');
const base64url = require('base64url');
const cbor      = require('cbor');
const asn1      = require('@lapo/asn1js');
const jsrsasign = require('jsrsasign');

/* Apple Webauthn Root
 * Original is here https://www.apple.com/certificateauthority/Apple_WebAuthn_Root_CA.pem
 */
let appleWebAuthnRoot = 'MIICEjCCAZmgAwIBAgIQaB0BbHo84wIlpQGUKEdXcTAKBggqhkjOPQQDAzBLMR8wHQYDVQQDDBZBcHBsZSBXZWJBdXRobiBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMB4XDTIwMDMxODE4MjEzMloXDTQ1MDMxNTAwMDAwMFowSzEfMB0GA1UEAwwWQXBwbGUgV2ViQXV0aG4gUm9vdCBDQTETMBEGA1UECgwKQXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTB2MBAGByqGSM49AgEGBSuBBAAiA2IABCJCQ2pTVhzjl4Wo6IhHtMSAzO2cv+H9DQKev3//fG59G11kxu9eI0/7o6V5uShBpe1u6l6mS19S1FEh6yGljnZAJ+2GNP1mi/YK2kSXIuTHjxA/pcoRf7XkOtO4o1qlcaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUJtdk2cV4wlpn0afeaxLQG2PxxtcwDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMDA2cAMGQCMFrZ+9DsJ1PW9hfNdBywZDsWDbWFp28it1d/5w2RPkRX3Bbn/UbDTNLx7Jr3jAGGiQIwHFj+dJZYUJR786osByBelJYsVZd2GbHQu209b5RCmGQ21gpSAk9QZW4B1bWeT0vT';

let COSEKEYS = {
    'kty' : 1,
    'alg' : 3,
    'crv' : -1,
    'x'   : -2,
    'y'   : -3,
    'n'   : -1,
    'e'   : -2
}

var hash = (alg, message) => {
    return crypto.createHash(alg).update(message).digest();
}

var base64ToPem = (b64cert) => {
    let pemcert = '';
    for(let i = 0; i < b64cert.length; i += 64)
        pemcert += b64cert.slice(i, i + 64) + '\n';

    return '-----BEGIN CERTIFICATE-----\n' + pemcert + '-----END CERTIFICATE-----';
}

var findOID = (asn1object, oid) => {
    if(!asn1object.sub)
        return

    for(let sub of asn1object.sub) {
        if(sub.typeName() !== 'OBJECT_IDENTIFIER' || sub.content() !== oid) {
            let result = findOID(sub, oid);

            if(result)
                return result

        } else {
            return asn1object
        }
    }
}

let asn1ObjectToJSON = (asn1object) => {
    let JASN1 = {
        'type': asn1object.typeName()
    }

    if(!asn1object.sub) {
        if(asn1object.typeName() === 'BIT_STRING' || asn1object.typeName() === 'OCTET_STRING')
            JASN1.data = asn1object.stream.enc.slice(asn1object.posContent(), asn1object.posEnd());
        else
            JASN1.data = asn1object.content();

        return JASN1
    }

    JASN1.data = [];
    for(let sub of asn1object.sub) {
        JASN1.data.push(asn1ObjectToJSON(sub));
    }

    return JASN1
}

let containsASN1Tag = (seq, tag) => {
    for(let member of seq)
        if(member.type === '[' + tag + ']')
            return true

    return false
}

var parseAuthData = (buffer) => {
    let rpIdHash      = buffer.slice(0, 32);          buffer = buffer.slice(32);
    let flagsBuf      = buffer.slice(0, 1);           buffer = buffer.slice(1);
    let flagsInt      = flagsBuf[0];
    let flags = {
        up: !!(flagsInt & 0x01),
        uv: !!(flagsInt & 0x04),
        at: !!(flagsInt & 0x40),
        ed: !!(flagsInt & 0x80),
        flagsInt
    }

    let counterBuf    = buffer.slice(0, 4);           buffer = buffer.slice(4);
    let counter       = counterBuf.readUInt32BE(0);

    let aaguid        = undefined;
    let credID        = undefined;
    let COSEPublicKey = undefined;

    if(flags.at) {
        aaguid           = buffer.slice(0, 16);          buffer = buffer.slice(16);
        let credIDLenBuf = buffer.slice(0, 2);           buffer = buffer.slice(2);
        let credIDLen    = credIDLenBuf.readUInt16BE(0);
        credID           = buffer.slice(0, credIDLen);   buffer = buffer.slice(credIDLen);
        COSEPublicKey    = buffer;
    }

    return {rpIdHash, flagsBuf, flags, counter, counterBuf, aaguid, credID, COSEPublicKey}
}

var getCertificateSubject = (certificate) => {
    let subjectCert = new jsrsasign.X509();
    subjectCert.readCertPEM(certificate);

    let subjectString = subjectCert.getSubjectString();
    let subjectFields = subjectString.slice(1).split('/');

    let fields = {};
    for(let field of subjectFields) {
        let kv = field.split('=');
        fields[kv[0]] = kv[1];
    }

    return fields
}

var validateCertificatePath = (certificates) => {
    if((new Set(certificates)).size !== certificates.length)
        throw new Error('Failed to validate certificates path! Dublicate certificates detected!');

    for(let i = 0; i < certificates.length; i++) {
        let subjectPem  = certificates[i];
        let subjectCert = new jsrsasign.X509();
        subjectCert.readCertPEM(subjectPem);

        let issuerPem = '';
        if(i + 1 >= certificates.length)
            issuerPem = subjectPem;
        else
            issuerPem = certificates[i + 1];

        let issuerCert = new jsrsasign.X509();
        issuerCert.readCertPEM(issuerPem);

        if(subjectCert.getIssuerString() !== issuerCert.getSubjectString())
            throw new Error('Failed to validate certificate path! Issuers dont match!');

        let subjectCertStruct = jsrsasign.ASN1HEX.getTLVbyList(subjectCert.hex, 0, [0]);
        let algorithm         = subjectCert.getSignatureAlgorithmField();
        let signatureHex      = subjectCert.getSignatureValueHex()

        let Signature = new jsrsasign.crypto.Signature({alg: algorithm});
        Signature.init(issuerPem);
        Signature.updateHex(subjectCertStruct);

        if(!Signature.verify(signatureHex))
            throw new Error('Failed to validate certificate path!')
    }

    return true
}

let verifyAppleAnonymousAttestation = (webAuthnResponse) => {
    let attestationBuffer = base64url.toBuffer(webAuthnResponse.response.attestationObject);
    let attestationStruct = cbor.decodeAllSync(attestationBuffer)[0];

    let authDataStruct    = parseAuthData(attestationStruct.authData);
    let clientDataHashBuf = hash('sha256', base64url.toBuffer(webAuthnResponse.response.clientDataJSON));

/* ----- VERIFY NONCE ----- */
    let signatureBaseBuffer     = Buffer.concat([attestationStruct.authData, clientDataHashBuf]);
    let expectedNonceBuffer     = hash('sha256', signatureBaseBuffer)

    let certASN1                = asn1.decode(attestationStruct.attStmt.x5c[0]);

    let AppleNonceExtension     = findOID(certASN1, '1.2.840.113635.100.8.2');

    if(!AppleNonceExtension)
        throw new Error('The certificate is missing Apple Nonce Extension 1.2.840.113635.100.8.2!')

    /*
        [
            {
                "type": "OBJECT_IDENTIFIER",
                "data": "1.2.840.113635.100.8.2"
            },
            {
                "type": "OCTET_STRING",
                "data": [
                    {
                        "type": "SEQUENCE",
                        "data": [
                            {
                                "type": "[1]",
                                "data": [
                                    {
                                        "type": "OCTET_STRING",
                                        "data": {
                                            "type": "Buffer",
                                            "data": [92, 219, 157, 144, 115, 64, 69, 91, 99, 115, 230, 117, 43, 115, 252, 54, 132, 83, 96, 34, 21, 250, 234, 187, 124, 22, 95, 11, 173, 172, 7, 204]
                                        }
                                    }
                                ]
                            }
                        ]
                    }
                ]
            }
        ]
     */
    let appleNonceExtensionJSON = asn1ObjectToJSON(AppleNonceExtension).data;

    let certificateNonceBuffer  = appleNonceExtensionJSON[1].data[0].data[0].data[0].data;

    if(Buffer.compare(certificateNonceBuffer, expectedNonceBuffer) !== 0)
        throw new Error('Attestation certificate does not contain expected nonce!');

/* ----- VERIFY NONCE ENDS ----- */

/* ----- VERIFY CERTIFICATE PATH ----- */

    let certPath = attestationStruct.attStmt.x5c
        .map((cert) => cert.toString('base64'))
        .map((cert) => base64ToPem(cert));

    certPath.push(base64ToPem(appleWebAuthnRoot))

    validateCertificatePath(certPath);
/* ----- VERIFY CERTIFICATE PATH ENDS ----- */


/* ----- VERIFY PUBLIC KEY MATCHING ----- */
    let certJSON       = asn1ObjectToJSON(certASN1);
    let certTBS        = certJSON.data[0];
    let certPubKey     = certTBS.data[6];
    let certPubKeyBuff = certPubKey.data[1].data;

    /* CHECK PUBKEY */
    let coseKey = cbor.decodeAllSync(authDataStruct.COSEPublicKey)[0];

    /* ANSI ECC KEY is 0x04 with X and Y coefficients. But certs have it padded with 0x00 so for simplicity it easier to do it that way */
    let ansiKey = Buffer.concat([Buffer([0x00, 0x04]), coseKey.get(COSEKEYS.x), coseKey.get(COSEKEYS.y)])

    if(ansiKey.toString('hex') !== certPubKeyBuff.toString('hex'))
        throw new Error('Certificate public key does not match public key in authData')
/* ----- VERIFY PUBLIC KEY MATCHING ENDS ----- */

    return true
}


let androidKeyWebAuthnSample = {
    "id": "YZVmTA6TxoNglppCxfsiSHHWzbQ",
    "response": {
        "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiVi1RTFI4QXBCazlnVHNYUnBLWncxeWVYRlg2QW9IZHJXTnRXLWdBV1REZyIsIm9yaWdpbiI6Imh0dHBzOi8vd2ViYXV0aG53b3Jrcy5naXRodWIuaW8ifQ",
        "attestationObject": "o2NmbXRlYXBwbGVnYXR0U3RtdKJjYWxnJmN4NWOCWQJHMIICQzCCAcmgAwIBAgIGAXagcCErMAoGCCqGSM49BAMCMEgxHDAaBgNVBAMME0FwcGxlIFdlYkF1dGhuIENBIDExEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwHhcNMjAxMjI1MTkwNDMxWhcNMjAxMjI4MTkwNDMxWjCBkTFJMEcGA1UEAwxANGJiNjY4ZjRkNTZlOTZmZjQwNTc0MThhOWFmZTNlNjJmNDlhOWEyNDUyOGMwNTU4ZTkxZDA2MGQ3NDJlMDQ2ZTEaMBgGA1UECwwRQUFBIENlcnRpZmljYXRpb24xEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAR6JwnVMcs0V09NqnYLYqAQKGQLSFPjHShTIsuC0qBEOhfiABl9IGSwjn--Zez0StflHcn8KgxgWDBI8uU7OZlJo1UwUzAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB_wQEAwIE8DAzBgkqhkiG92NkCAIEJjAkoSIEIFzbnZBzQEVbY3PmdStz_DaEU2AiFfrqu3wWXwutrAfMMAoGCCqGSM49BAMCA2gAMGUCMQCRuW8mwdBiWX50NpAbT_ArXRqu_R4U1nw1qoB9-fcBKG37bLJLSzUHH3eaDn9VpgMCMCluiKlZhwcRCMkIhpeowhZZimKJWwn6XWPSYakvstRyDH935BtMCASob93RiUpOTFkCODCCAjQwggG6oAMCAQICEFYlU5XHp_tA6-Io2CYIU7YwCgYIKoZIzj0EAwMwSzEfMB0GA1UEAwwWQXBwbGUgV2ViQXV0aG4gUm9vdCBDQTETMBEGA1UECgwKQXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODM4MDFaFw0zMDAzMTMwMDAwMDBaMEgxHDAaBgNVBAMME0FwcGxlIFdlYkF1dGhuIENBIDExEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAASDLocvJhSRgQIlufX81rtjeLX1Xz_LBFvHNZk0df1UkETfm_4ZIRdlxpod2gULONRQg0AaQ0-yTREtVsPhz7_LmJH-wGlggb75bLx3yI3dr0alruHdUVta-quTvpwLJpGjZjBkMBIGA1UdEwEB_wQIMAYBAf8CAQAwHwYDVR0jBBgwFoAUJtdk2cV4wlpn0afeaxLQG2PxxtcwHQYDVR0OBBYEFOuugsT_oaxbUdTPJGEFAL5jvXeIMA4GA1UdDwEB_wQEAwIBBjAKBggqhkjOPQQDAwNoADBlAjEA3YsaNIGl-tnbtOdle4QeFEwnt1uHakGGwrFHV1Azcifv5VRFfvZIlQxjLlxIPnDBAjAsimBE3CAfz-Wbw00pMMFIeFHZYO1qdfHrSsq-OM0luJfQyAW-8Mf3iwelccboDgdoYXV0aERhdGFYmMx1DPn13vHz03OyEHQFPMYaJ0ZmXg850aiannHVUXFDRQAAAAAAAAAAAAAAAAAAAAAAAAAAABRhlWZMDpPGg2CWmkLF-yJIcdbNtKUBAgMmIAEhWCB6JwnVMcs0V09NqnYLYqAQKGQLSFPjHShTIsuC0qBEOiJYIBfiABl9IGSwjn--Zez0StflHcn8KgxgWDBI8uU7OZlJ"
    },
    "type": "public-key"
}

verifyAppleAnonymousAttestation(androidKeyWebAuthnSample)