const { utils } = require('ethers');


function ASN1ParseSecp256k1Signature(signature) {
    const sig = {
        R: null,
        S: null,
    };
    var result = utils.hexlify(utils.toUtf8Bytes(signature));
    console.log(result.length)
        while (result.length < 66) { result += '0'; }
        if (result.length !== 66) { throw new Error("invalid web3 implicit bytes32"); }

    const [parsedSignature, postfix] = utils.RLP.decode(signature);

    if (postfix.length > 0) {
        throw new Error('Trailing bytes for ASN1 ecdsa signature');
    }

    sig.R = parsedSignature[0];
    sig.S = parsedSignature[1];

    console.log(parsedSignature)
    console.log(sig.R)
    console.log(sig.S)


    return [sig.R, sig.S, null];
}

ASN1ParseSecp256k1Signature('304402201e2011c144d6d803ad37f85fbfbce53a3b2b3cff2130647fe1fd5e36626a4518022072661a2fad80e598a7d5302cc9f238ce476da1b10fbbc6ae64b66bf7ab009593')