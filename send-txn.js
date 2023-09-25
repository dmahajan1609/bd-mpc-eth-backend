const { Web3 } = require("web3");
const web3 = new Web3("http://127.0.0.1:7545");
const fs = require("fs");
const keccak256 = require("keccak256");
const { TSMClient, algorithms, curves } = require("@sepior/tsm");
const crypto = require("crypto");
const credsRaw = fs.readFileSync("creds.json");
const creds = JSON.parse(credsRaw);
const { LegacyTransaction } = require("@ethereumjs/tx");
const asn = require("asn1.js");
const ethers = require("ethers");
const { Common, Hardfork } = require("@ethereumjs/common");
const chainId = 1337; // The chain ID of your local network
const txDecoder = require('ethereum-tx-decoder');

async function sendTxn() {
  const customCommon = Common.custom({
    chainId: chainId,
    networkId: chainId,
    hardfork: Hardfork.Berlin,
  });

  let playerCount = 3;
  let threshold = 1;

  let tsmClient1 = await TSMClient.init(playerCount, threshold, creds.creds1);
  let tsmClient2 = await TSMClient.init(playerCount, threshold, creds.creds2);
  let tsmClient3 = await TSMClient.init(playerCount, threshold, creds.creds3);

  let sessionNum = generateRandomNumber(43);
  sessionID = "e" + sessionNum;

  let results = await Promise.all([
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
  keyID = results[0];
  console.log("Generated key with key ID:", keyID);

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
  console.log("Generated presigs with IDs:", presigIDs);
  let chainPath = new Uint32Array([0, 3]);

  let [, derPk] = await tsmClient1.publicKey(
    algorithms.ECDSA,
    keyID,
    chainPath
  );
  // Parse ECDSA Public Key to derive address
  let b = Buffer.from(derPk);
  let stringifiedPk = b.toString("hex");
  console.log("pk is", stringifiedPk);

  let [, x, y] = await tsmClient1.parsePublicKey(algorithms.ECDSA, derPk);
  let hexEncodedXY = derPk.subarray(-64);
  let decodedPkValue = Buffer.from(hexEncodedXY);
  const rawPublicKey = decodedPkValue.toString("hex");
  console.log("Raw public key: 0x" + rawPublicKey);

  var hashValueKeccak = keccak256(decodedPkValue);
  console.log("hashValueKeccak", hashValueKeccak.toString("hex"));
  var address2 = Buffer.from(hashValueKeccak.slice(-20)).toString("hex");
  console.log("address2", address2);

  // Get Balance of the newly created account
  address2 = "0x" + address2;
  let balance = await getEthBalance(address2);
  console.log("Eth account balance before transfer:", balance);
  const accounts = await web3.eth.getAccounts();
  // Fund newly created account
  const txn = await web3.eth.sendTransaction({
    to: address2,
    from: accounts[2],
    value: web3.utils.toWei("1", "ether"),
  });
  console.log("txn", txn);
  balance = await getEthBalance(address2);
  console.log("Eth account balance after transfer:", balance);

  // Create a raw Ethereum transaction
  const addressTo = "0xE2a18e03e7fE8dc974614BA6De081cd782239424";
  let count = await web3.eth.getTransactionCount(addressTo, "latest");
  count = "0x" + count.toString(16);
  const transferAmountValue = web3.utils.numberToHex(
    web3.utils.toWei("0.1", "ether")
  );
  // const gasPrice = web3.utils.toHex(web3.utils.toWei("30", "gwei"));
  const gasPrice = await web3.eth.getGasPrice();
  const gasLimit = (await web3.eth.getBlock("latest")).gasLimit;
  // const gasLimit = web3.utils.toHex(web3.eth);

  // gasPrice: '0x09184e72a000',
  // gasLimit: '0x30000',

  let rawTxn = {
    nonce: count,
    gasPrice: web3.utils.toHex(gasPrice),
    gasLimit: web3.utils.toHex(gasLimit),
    to: addressTo,
    value: transferAmountValue,
    data: "0x",
  };

  const transaction = LegacyTransaction.fromTxData(rawTxn, { customCommon });
  let unsignedTxHash = transaction.getHashedMessageToSign();
  // unsignedTxHash = rlp.encode(unsignedTxHash);
  // unsignedTxHash = Buffer.from(unsignedTxHash).toString('hex')
  console.log("hash1 generated: ", unsignedTxHash);

  // generate partial signatureœ
  presigID = presigIDs[1];

  let [partialSignature1] = await tsmClient1.partialSignWithPresig(
    algorithms.ECDSA,
    keyID,
    presigID,
    chainPath,
    unsignedTxHash
  );
  let [partialSignature2] = await tsmClient2.partialSignWithPresig(
    algorithms.ECDSA,
    keyID,
    presigID,
    chainPath,
    unsignedTxHash
  );
  let [partialSignature3] = await tsmClient3.partialSignWithPresig(
    algorithms.ECDSA,
    keyID,
    presigID,
    chainPath,
    unsignedTxHash
  );

  let [aggregatedSignatureDER, recoveryID] = await tsmClient1.finalize(
    algorithms.ECDSA,
    [partialSignature1, partialSignature2, partialSignature3]
  );
  console.log("aggregatedSignatureDER :", aggregatedSignatureDER);
  console.log("recoveryID :", recoveryID);

  let isValidDERSig = await tsmClient1.verify(
    algorithms.ECDSA,
    derPk,
    unsignedTxHash,
    aggregatedSignatureDER,
    curves.SECP256K1
  );
  console.log("Is DER signature valid?", isValidDERSig);

  const { ecSignature, r, s, signature } = ASN1ParseSecp256k1Signature(
    aggregatedSignatureDER
  );
  console.log("R2", r);
  console.log("S2", s);

  // sign transaction
  rawTxn.v = web3.utils.toHex(
    chainId ? recoveryID + (chainId * 2 + 35) : recoveryID + 27
  );
  // rawTxn.v = "0x" + recoveryID; // Error: Legacy txs need either v = 27/28 or v >= 37 (EIP-155 replay protection), got v = 0
  rawTxn.r = "0x" + r;
  rawTxn.s = "0x" + s;
  console.log("Signed Txn", rawTxn);
  const sig = {
    r: "0x" + r,
    s: "0x" + s,
    v: web3.utils.toHex(
      chainId ? recoveryID + (chainId * 2 + 35) : recoveryID + 27
    ),
  };

  let tranxn = LegacyTransaction.fromTxData(rawTxn, { customCommon });
  txnHash = tranxn.hash();
  let signedTxn = tranxn.serialize();
  signedTxn = "0x" +  Buffer.from(signedTxn).toString("hex");
  console.log("signedTxn", signedTxn)
  console.log("decoded txn", txDecoder.decodeTx(signedTxn))

  const recoveredAddress = await ethers.utils.recoverAddress(unsignedTxHash, sig);
  console.log("recoveredAddress", recoveredAddress);

  web3.eth.sendSignedTransaction(signedTxn, function (error, hash) {
    if (!error) {
      console.log(
        "The hash of your transaction is: ",
        hash,
        "\n Check to view the status of your transaction!"
      );
    } else {
      console.log(
        "Something went wrong while submitting your transaction:",
        error
      );
    }
  });
}

sendTxn();

function ASN1ParseSecp256k1Signature(derSignature) {
  // Parse aggregated signature
  var ECSignature = asn.define("ECSignature", function () {
    this.seq().obj(this.key("R").int(), this.key("S").int());
  });
  var ecSignature = ECSignature.decode(Buffer.from(derSignature), "der");
  console.log("ecSignature", ecSignature);
  let signature =
    ecSignature.R.toString("hex").padStart(64, "0") +
    ecSignature.S.toString("hex").padStart(64, "0");
  signature = Buffer.from(signature, "hex");
  return {
    ecSignature,
    r: ecSignature.R.toString("hex"),
    s: ecSignature.S.toString("hex"),
    signature,
  };
}

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
  let balance = await web3.eth.getBalance(address);
  balance = web3.utils.fromWei(balance, "ether");
  return balance;
}
