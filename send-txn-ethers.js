const fs = require("fs");
const keccak256 = require("keccak256");
const { TSMClient, algorithms, curves } = require("@sepior/tsm");
const crypto = require("crypto");
const credsRaw = fs.readFileSync("creds.json");
const creds = JSON.parse(credsRaw);
const { LegacyTransaction } = require("@ethereumjs/tx");
const asn = require("asn1.js");
const { providers, utils } = require("ethers");
const { Common, Hardfork } = require("@ethereumjs/common");
const { ecrecover } = require("@ethereumjs/util");
const provider = new providers.JsonRpcProvider("http://127.0.0.1:7545");
const { Address, ecrecover } = require("@ethereumjs/util")

async function sendTxn() {
  const chainId = (await provider.getNetwork()).chainId;
  console.log("ChainID", chainId);
  const customCommon = Common.custom({
    chainId: chainId,
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
  const accounts = await provider.listAccounts();
  // Fund newly created account
  const txn = await provider.send("eth_sendTransaction", [
    {
      to: address2,
      from: accounts[2],
      value: utils.parseUnits("1", "ether").toHexString(),
    },
  ]);
  console.log("txn", txn);
  balance = await getEthBalance(address2);
  console.log("Eth account balance after transfer:", balance);

  // Create a raw Ethereum transaction
  const addressTo = "0xE2a18e03e7fE8dc974614BA6De081cd782239424";
  let count = await provider.getTransactionCount(addressTo, "latest");
  count = "0x" + count.toString(16);
  const transferAmountValue = utils.hexlify(utils.parseEther("0.1"));
  const gasPrice = await provider.getGasPrice();
  const gasLimit = 50000;

  let rawTxn = {
    nonce: count,
    gasPrice: utils.hexlify(gasPrice),
    gasLimit: utils.hexlify(gasLimit),
    to: addressTo,
    value: transferAmountValue,
    data: "0x7f7465737432000000000000000000000000000000000000000000000000000000600057",
    chainId: chainId
  };

  // The Txn hash to sign
  const transaction = LegacyTransaction.fromTxData(rawTxn, { customCommon });
  let unsignedTxHash = transaction.getHashedMessageToSign();
  console.log("hash generated: ", unsignedTxHash);

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
  console.log("Signed Txn", rawTxn);
  const sig = {
    r: "0x" + r,
    s: "0x" + s,
    v: "0x" + recoveryID
    // v: "0x" + (chainId ? recoveryID + (chainId * 2 + 35) : recoveryID + 27)
  };

  const recoveredAddress = await utils.recoverAddress(unsignedTxHash, sig);
  // const recoveredAddress = Address.fromPublicKey(unsignedTxHash, sig);

  const signedTxn = utils.serializeTransaction(rawTxn, sig);
  console.log("recoveredAddress", recoveredAddress);

  const hash = await provider.sendTransaction(signedTxn);

  console.log(
    "The hash of your transaction is: ",
    hash,
    "\n Check to view the status of your transaction!"
  );
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
  console.log("R1", ecSignature.R.toString("hex").padStart(64, "0"));
  console.log("S1", ecSignature.S.toString("hex").padStart(64, "0"));
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
  let balance = await provider.getBalance(address);
  // balance = web3.utils.fromWei(balance, "ether");
  balance = utils.formatEther(balance);
  console.log("Balance in ETH:", balance);
  return balance;
}

// Function to convert hex to string
const hexToString = (hex) => {
  let str = "";
  for (let i = 0; i < hex.length; i += 2) {
    const hexValue = hex.substr(i, 2);
    const decimalValue = parseInt(hexValue, 16);
    str += String.fromCharCode(decimalValue);
  }
  return str;
};


// b3d5b45dec592d6ca60455f2926e06e5ff1c81cc4115d44d4b4f9953e6260aee55bc80e341977ab77713c80b31d960be01e09bb19014db49484db45859c77fda00
// 30450221008b557a4d6f39a4f697cf4e55b80afb7f0941d38cdc75f85b2db6f2bb880228bf02205a824a206a64b2d15ec514c22c3303dcb71f4f24a8b355e53e5711132c3d1fbc