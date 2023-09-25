const { TSMClient, algorithms, curves } = require("@sepior/tsm");
const crypto = require("crypto");
const sha3 = require("js-sha3");
const keccak256 = require("keccak256");
const { encode, decode } = require("hex-encode-decode");
const credsRaw = fs.readFileSync("creds.json");
const creds = JSON.parse(credsRaw);
const { Web3 } = require("web3");
const web3 = new Web3("http://127.0.0.1:7545");
const BigInteger = require("big-integer");
const fs = require("fs");
const { Keccak } = require("sha3");
const { RawTransaction, Transaction } = require("ethereumjs-tx");
const { default: Common } = require("ethereumjs-common");

let main = async function () {
  // Initialize a separate SDK for each MPC node in the TSM
  // Remember to change player count and threshold to match you configuration
  let playerCount = 3;
  let threshold = 1;

  let tsmClient1 = await TSMClient.init(playerCount, threshold, creds.creds1);
  let tsmClient2 = await TSMClient.init(playerCount, threshold, creds.creds2);
  let tsmClient3 = await TSMClient.init(playerCount, threshold, creds.creds3);

  // Step 1: Generate a key in the TSM

  // The three SDKs need to first agree on a unique session ID.
  let sessionNum = generateRandomNumber(43);
  sessionID = "e" + sessionNum;

  // Each SDK must call keygenWithSessionID with the session ID.
  let results = await Promise.all([
    // TODO: note: understand what the KeyID here is, since each instance will have a unique keyshare
    tsmClient1.keygenWithSessionID(
      algorithms.ECDSA,
      sessionID,
      curves.SECP256K1
    ),
    tsmClient2.keygenWithSessionID(
      algorithms.ECDSA,
      sessionID,
      curves.SECP256K1
    ),
    tsmClient3.keygenWithSessionID(
      algorithms.ECDSA,
      sessionID,
      curves.SECP256K1
    ),
  ]);
  console.log("Results from keygenWithSessionID:", results);
  // As a result of the interactive protocol, each SDK receives the key ID.
  keyID = results[0];
  console.log("Generated key with key ID:", keyID);

  // Step 2: Generate five pre-signatures // TODO: why 5?

  sessionNum = generateRandomNumber(44);
  sessionID = "e" + sessionNum;

  presigCount = 5;
  results = await Promise.all([
    tsmClient1.presigGenWithSessionID(
      algorithms.ECDSA,
      sessionID,
      keyID,
      presigCount
    ),
    tsmClient2.presigGenWithSessionID(
      algorithms.ECDSA,
      sessionID,
      keyID,
      presigCount
    ),
    tsmClient3.presigGenWithSessionID(
      algorithms.ECDSA,
      sessionID,
      keyID,
      presigCount
    ),
  ]);
  presigIDs = results[0];
  //   console.log("Results from presigGenWithSessionID:", results);
  console.log("Generated presigs with IDs:", presigIDs);

  // Step 3: Create partial signatures of a message non-interactively using one of the presignatures.

  // The message hash to sign
  let msg = "Hello World!";
  let sha256 = crypto.createHash("sha256");
  sha256.update(msg);
  let msgHash = sha256.digest();

  // In this example we will not sign with the master key, but with a key derived from the
  // master key using the chain path m/0/3.
  let chainPath = new Uint32Array([0, 3]);

  // Create a set of partial signatures using one of the presignatures.
  // Note that this does not require interaction between the MPC nodes, so we don't have to do this in parallel.
  // sessionNum = generateRandomNumber(45);
  // sessionID = "e"+sessionNum;
  presigID = presigIDs[0];
  let [partialSignature1] = await tsmClient1.partialSignWithPresig(
    algorithms.ECDSA,
    keyID,
    presigID,
    chainPath,
    msgHash
  );
  let [partialSignature2] = await tsmClient2.partialSignWithPresig(
    algorithms.ECDSA,
    keyID,
    presigID,
    chainPath,
    msgHash
  );
  let [partialSignature3] = await tsmClient3.partialSignWithPresig(
    algorithms.ECDSA,
    keyID,
    presigID,
    chainPath,
    msgHash
  );

  // Step 4: Combine the partial signatures into the final signature

  let [signature] = await tsmClient1.finalize(algorithms.ECDSA, [
    partialSignature1,
    partialSignature2,
    partialSignature3,
  ]);

  tsmClient1.


  // console.log("Aggregated Signature", signature)

  // Check that the signature is valid
  let [abc, derPk] = await tsmClient1.publicKey(
    algorithms.ECDSA,
    keyID,
    chainPath
  );
  let b = Buffer.from(derPk);
  let stringifiedPk = b.toString("hex");
  console.log("pk is", stringifiedPk);

  let [, x, y] = await tsmClient1.parsePublicKey(algorithms.ECDSA, derPk);
  //   console.log('public key x-coordinates is', x);
  //   console.log('public key y-coordinates is', y);
  let hexEncodedXY = derPk.subarray(-64);
  let decodedPkValue = Buffer.from(hexEncodedXY);
  const rawPublicKey = decodedPkValue.toString("hex");
  console.log("Raw public key: 0x" + rawPublicKey);

  console.log(
    "############################ Using keccak256 package 1 to derive address ###########################"
  );
  //   console.log("concatenation of the hex encoded x and y value of the raw public key is", hexEncodedXY);

  let hashValueSha3 = sha3.keccak256(decodedPkValue);
  console.log("hashValueSha3", hashValueSha3);
  // Ethereum address is rightmost 160 bits of the hash value
  // ed35d862a35761ec340f45ee0a428da5394e2617974cb4e9edbd40561496cf33
  var address1 = hashValueSha3.slice(-40);
  console.log("address1", address1);

  console.log(
    "############################ Using keccak256 package 2 to derive address ###########################"
  );
  var hashValueKeccak = keccak256(decodedPkValue);
  console.log("hashValueKeccak", hashValueKeccak.toString("hex"));
  var address2 = Buffer.from(hashValueKeccak.slice(-20)).toString("hex");
  //   var address3 = hashValueKeccak.subarray(-20).toString("hex")
  console.log("address2", address2);
  console.log(
    "Both address1 & address2 match with the results in the test tool `https://www.rfctools.com/ethereum-address-test-tool/`. Input to the tool is `rawPublicKey`"
  );
  let balance = await getEthBalance('0x' + (address2.toUpperCase()));
  console.log("Eth account balance is:", balance)



  //   console.log("address3", address3);
  // Calculate checksum (expressed as upper/lower case in the address)
  //   var addressHash = keccak256(address2).toString("hex");
  //   console.log("addressHash", addressHash);

  //   var addressChecksum = "";
  //   for (var i = 0; i < address2.length; i++) {
  //     if (parseInt(addressHash[i], 16) > 7) {
  //       addressChecksum += address2[i].toUpperCase();
  //     } else {
  //       addressChecksum += address2[i];
  //     }
  //   }
  //   console.log("Derived: 0x" + addressChecksum);

  // console.log('public key is', curveName);
  // console.log('public key curve is', publicKey);
  // console.log('public key x-coordinates is', x);
  // console.log('public key y-coordinates is', y);

  // let address = ('0x' + keccak('keccak256').update(key).digest().slice(-20).toString('hex');)

  //     let msg = new Uint8Array(2 * 32);
  // publicKey.X.FillBytes(msg.subarray(0, 32));
  // publicKey.Y.FillBytes(msg.subarray(32, 64));
  // let h = new sha3.Keccak256();
  // h.update(msg);
  // let hashValue = h.digest();

  // let ethAddress = Buffer.from(hashValue.slice(-20)).toString('hex');
  // console.log("Ethereum address: ", ethAddress);

  let isValid = await tsmClient1.verify(
    algorithms.ECDSA,
    derPk,
    msgHash,
    signature,
    curves.SECP256K1
  );
  console.log("Is signature valid?", isValid);
  web3.eth.sendTransaction(signature);

};

main();

function generateRandomNumber(n) {
  var add = 1,
    max = 12 - add; // 12 is the min safe number Math.random() can generate without it starting to pad the end with zeros.
  if (n > max) {
    return generateRandomNumber(max) + generateRandomNumber(n - max);
  }
  max = Math.pow(10, n + add);
  var min = max / 10; // Math.pow(10, n) basically
  var number = Math.floor(Math.random() * (max - min + 1)) + min;
  return ("" + number).substring(add);
}

async function getEthBalance(address) {
  let balance =  await web3.eth.getBalance(address);
    balance = web3.utils.fromWei(balance, 'ether');
    // console.log("Balance in wei:", balanceInWei);
    console.log("Balance in ETH:", balance);
  return balance;
}



function ASN1ParseSecp256k1Signature(signature) {
    var big = require('big.js');
    var asn1 = require('asn1');

    var sig = {
        R: new big.Int(),
        S: new big.Int()
    };
    var postfix, err;
    var result = asn1.decode(signature, sig);
    postfix = result[0];
    err = result[1];
    if (err !== null) {
        return [null, null, err];
    }
    if (postfix.length > 0) {
        return [null, null, new Error("trailing bytes for ASN1 ecdsa signature")];
    }
    return [sig.R, sig.S, null];
}
