const { Web3 } = require("web3");
const web3 = new Web3("http://127.0.0.1:7545");
const fs = require("fs");
const { Keccak } = require("sha3");
const sha3 = require("js-sha3");
const keccak256 = require("keccak256");
const { TSMClient, algorithms, curves } = require("@sepior/tsm");
const crypto = require("crypto");
const { encode, decode } = require("hex-encode-decode");
const credsRaw = fs.readFileSync("creds.json");
const creds = JSON.parse(credsRaw);
// const { Transaction, FeeMarketEIP1559Transaction } = require("@ethereumjs/tx");
const asn = require("asn1.js");
const ethers = require("ethers");

async function sendTxn() {
  let playerCount = 3;
  let threshold = 1;

  let tsmClient = await TSMClient.init(playerCount, threshold, [
    {
      url: "https://pilot1.tsm.sepior.net",
      userID: "e7qN8EoEYZwOHi9GyNbZIUCRhwOe",
      password: "fjnccMbRaoOx4YpCAlgnmxigeFceaCQxlnfquO4jbW8P",
    },
    {
      url: "https://pilot2.tsm.sepior.net",
      userID: "e7qN8EoEYZwOHi9GyNbZIUCRhwOe",
      password: "uqbBlg9rAchPMQyeRei5LZC70fZVwWdbJwUeVQmbg4xw",
    },
    {
      url: "https://pilot3.tsm.sepior.net",
      userID: "e7qN8EoEYZwOHi9GyNbZIUCRhwOe",
      password: "mRxChuuxxLs8ZE1MGf0hpAhjp734lzg2t5Eah5WtigXk",
    },
  ]);

  // Create a key in the TSM
  let keyID = await tsmClient.keygen(algorithms.ECDSA, curves.SECP256K1);
  console.log("Generated key with key ID:", keyID);

  // The message hash we want to sign
  // const mesg = "some data to sign";
  // console.log("Generated message to sign:", mesg);
  // let sha256 = crypto.createHash("sha256");
  // sha256.update(mesg);
  // let msg = sha256.digest();

  // Create a raw Ethereum transaction
  const addressTo = "0xE2a18e03e7fE8dc974614BA6De081cd782239424";
  const count = await web3.eth.getTransactionCount(addressTo, "latest");
  const transferAmountValue = web3.utils.toHex(
    web3.utils.toWei("0.1", "ether")
  );
  const gasPrice = web3.utils.toHex(web3.utils.toWei("30", "gwei"));
  const gasLimit = web3.utils.toHex(1000000);

  const chainId = 1337;

  const rawTxn = {
    nonce: web3.utils.toHex(count),
    gasPrice: gasPrice,
    gasLimit: gasLimit,
    to: addressTo,
    value: transferAmountValue,
    data: "0x7f7465737432000000000000000000000000000000000000000000000000000000600057",
  };

  const transaction = new Transaction(rawTxn);
  console.log(transaction);

  // const rsTx = await ethers.utils.resolveProperties(rawTxn);
  // console.log("rsTx", rsTx)
  // const raw = ethers.utils.serializeTransaction(rsTx, ); // returns RLP encoded tx
  // console.log("raw", raw);
  // const msg = ethers.utils.keccak256(raw); // as specified by ECDSA
  console.log("hash generated: ", msg);

  // Sign the message hash using the key
  //  const chainPath = new Uint32Array();
  let chainPath = new Uint32Array([0, 3]);
  console.log("chainPath", chainPath);

  const signatureDER = await tsmClient.sign(
    algorithms.ECDSA,
    keyID,
    chainPath,
    msg
  );
  console.log("signatureDER", signatureDER);

  // Get the public key
  //  let pk = await tsmClient.publicKey(algorithms.ECDSA, keyID, chainPath);
  let [, derPk] = await tsmClient.publicKey(algorithms.ECDSA, keyID, chainPath);

  // Parse ECDSA Public Key to derive address
  let b = Buffer.from(derPk);
  let stringifiedPk = b.toString("hex");
  console.log("pk is", stringifiedPk);

  let [, x, y] = await tsmClient.parsePublicKey(algorithms.ECDSA, derPk);
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
    from: accounts[0],
    value: web3.utils.toWei("1", "ether"),
  });
  console.log("txn", txn);
  balance = await getEthBalance(address2);
  console.log("Eth account balance after transfer:", balance);

  // Check that the signature is valid
  let isValid = await tsmClient.verify(
    algorithms.ECDSA,
    derPk,
    msg,
    signatureDER,
    curves.SECP256K1
  );
  console.log("valid?", isValid);

  const parsedAggregateSignature = ASN1ParseSecp256k1Signature(signatureDER);
  console.log("parsedAggregateSignature", parsedAggregateSignature);

  // Delete the key
  //  await tsmClient.delete(keyID);
  //  await tsmClient.close();
}

sendTxn();

function ASN1ParseSecp256k1Signature(derSignature) {
  // Parse aggregated signature
  var ECSignature = asn.define("ECSignature", function () {
    this.seq().obj(this.key("R").int(), this.key("S").int());
  });
  var ecSignature = ECSignature.decode(Buffer.from(derSignature), "der");
  let signature =
    ecSignature.R.toString("hex").padStart(64, "0") +
    ecSignature.S.toString("hex").padStart(64, "0");
  signature = Buffer.from(signature, "hex");
  console.log("ASN1 parsed Signature", signature);
  return signature;
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
  // console.log("Balance in wei:", balanceInWei);
  console.log("Balance in ETH:", balance);
  return balance;
}
