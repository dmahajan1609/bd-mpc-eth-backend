const asn1 = require("asn1.js");

function ASN1ParseSecp256k1Signature(signature) {
    var sig = {
        R: null,
        S: null
    };
    var postfix, err;
    var result = asn1
    postfix = result[0];
    err = result[1];
    if (err !== null) {
        return [null, null, err];
    }
    if (postfix.length > 0) {
        return [null, null, new Error("trailing bytes for ASN1 ecdsa signature")];
    }
    console.log(result)
    console.log(sig.R)
    console.log(sig.S)
    return [sig.R, sig.S, null];
    
}

ASN1ParseSecp256k1Signature('304402201e2011c144d6d803ad37f85fbfbce53a3b2b3cff2130647fe1fd5e36626a4518022072661a2fad80e598a7d5302cc9f238ce476da1b10fbbc6ae64b66bf7ab009593')

