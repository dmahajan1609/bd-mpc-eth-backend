const bitcoin = require("bitcoinjs-lib");
const testnet = bitcoin.networks.testnet;
const ECPairFactory = require("ecpair");
const ecc = require("tiny-secp256k1");
const asn = require("asn1.js");
const { TSMClient, algorithms } = require("@sepior/tsm");
const ECPair = ECPairFactory.ECPairFactory(ecc);

async function example() {
  // this is the info from the transaction that created the UTXO we wanna spend

  const utxo_transactionId =
    "072ca1827060d9867e82842ae6cca6f56de02c1db09838410713750d13e04b1b";
  const utxo_index = 1;
  const utxo_value = 1102453; // in blockchain its "value": 12835 (0.00012835 btc)
  const from_testnet_address = "mhmRiCf3ZjzpGVzvy8HQDkLhFSCsJy52fp"; // was a MPC generated p2pkh address (m/49/1/0/0/0) seeded with 1102453 testnet via faucit
  // this is the too-address
  const to_testnet_address = "mvxmmdYfi2nbboEQED83QKqPr7bf8us3aa"; // this is another MPC generated p2pkh address (m/49/1/0/0/1) // was 'mjWbTCFBGbbvPR2eRk5JkoLrSNLe4xoQwS';
  const send_amount = 40000; // wanna send 0.0004 btc which is 40000 satoshi
  let TRANSACTION_FEE = 25000; // looked up avg txn fee now in testnet and it's 0.00025 btc (25000 satoshi)
  const change_amount = utxo_value - send_amount - TRANSACTION_FEE; // should be 1037453
  const rawTransaction = new bitcoin.Psbt({ network: testnet });

  let rawTx =
    "02000000012e53b492c7e90ba70723ae4fcf0dfada206f0b6ab4c0686c253641554142e374000000006a4730440220213912ba7ec26d18290b4dfa9c1b719916284bdd4a81fad0d34a2ea7faba9232022065af566333f357ba3d5dcd2eb55248be3e61c42141683f3d3e020f3c3877d3b30121032fde6e073384cf87761b4274b2d5096f64a71ae328218514c436cc97b7f8d292fdffffff02eb6fd192030000001976a91499be3ab045896f8fcce4e3e46b3786cded164f8988ac75d21000000000001976a91418acf606cd2b44f02270bcf468e467b5abca5e7f88ac74c62500";

  //above From https://blockstream.info/testnet/api/tx/072ca1827060d9867e82842ae6cca6f56de02c1db09838410713750d13e04b1b/hex

  rawTransaction.addInput({
    hash: utxo_transactionId,

    index: utxo_index,

    nonWitnessUtxo: Buffer.from(rawTx, "hex"),
  });

  rawTransaction.addOutput({
    address: to_testnet_address,

    value: send_amount,
  });

  rawTransaction.addOutput({
    address: from_testnet_address,

    value: change_amount,
  });

  let playerCount = 3;

  let threshold = 1;

  const creds = require("./creds1.json");

  let tsmClient1 = await TSMClient.init(playerCount, threshold, [
    { url: creds.urls[0], userID: creds.userID, password: creds.passwords[0] },
  ]);

  let tsmClient2 = await TSMClient.init(playerCount, threshold, [
    { url: creds.urls[1], userID: creds.userID, password: creds.passwords[1] },
  ]);

  let tsmClient3 = await TSMClient.init(playerCount, threshold, [
    { url: creds.urls[2], userID: creds.userID, password: creds.passwords[2] },
  ]);

  let keyID = "JbofG4hU9kLojFFKpzUHVQdmNLQz"; // using Hard-wired key from createdMPCKeyAnd2Addrs code

  let addressChainPath = new Uint32Array([49, 1, 0, 0, 0]);

  let [pk, pkDER] = await tsmClient1.publicKey(
    algorithms.ECDSA,
    keyID,
    addressChainPath
  );

  const pkCompressed = await pk2Sec1Compressed(tsmClient1, pkDER);

  const pkRaw = pk.export({ format: "der", type: "spki" });

  pkBytes = pkRaw.slice(23); // Remove RFC 5280 prefix

  sessionNum = generateRandomNumber(43);

  sessionID = "b" + sessionNum; // this needs to change on each call... reusing it on subsequene retries causes weird results

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

  const signer = {
    network: testnet,
    publicKey: pkCompressed,
    sign: async ($hash) => {
      const [partialSignature1, ,] = await tsmClient1.partialSignWithPresig(
        algorithms.ECDSA,
        keyID,
        presigIDs[0],
        addressChainPath,
        $hash
      );

      const [partialSignature2, ,] = await tsmClient2.partialSignWithPresig(
        algorithms.ECDSA,
        keyID,
        presigIDs[0],
        addressChainPath,
        $hash
      );

      const [partialSignature3, ,] = await tsmClient3.partialSignWithPresig(
        algorithms.ECDSA,
        keyID,
        presigIDs[0],
        addressChainPath,
        $hash
      );

      let [signature] = await tsmClient1.finalize(algorithms.ECDSA, [
        partialSignature1,
        partialSignature2,
        partialSignature3,
      ]);

      console.log("$hash value is", Buffer.from($hash).toString("hex"));

      console.log("Signature :", Buffer.from(signature).toString("hex"));

      var asn = require("asn1.js");

      var ECSignature = asn.define("ECSignature", function () {
        this.seq().obj(
          this.key("R").int(),

          this.key("S").int()
        );
      });

      var ecSignature = ECSignature.decode(Buffer.from(signature), "der");

      srSignature =
        ecSignature.R.toString("hex").padStart(64, "0") +
        ecSignature.S.toString("hex").padStart(64, "0");

      console.log(srSignature.length);

      console.log(Buffer.from(srSignature, "hex").toString("hex"));

      console.log(Buffer.from(srSignature, "hex").length);

      return Buffer.from(srSignature, "hex");
    },
  };

  await rawTransaction.signInputAsync(0, signer); // generates Uncaught Error: Need a Utxo input item for signing

  const validator = (pubkey, msghash, signature) =>
    ECPair.fromPublicKey(pubkey).verify(msghash, signature);

  var retval = rawTransaction.validateSignaturesOfInput(0, validator);

  console.log(" validation check = " + retval);

  rawTransaction.finalizeAllInputs();

  const signed_tx = rawTransaction.extractTransaction().toHex();

  console.log("Signed Raw Transaction:", signed_tx);
}

async function pk2Sec1Compressed(tsmClient, pk) {
  // The public key pk returned from the TSM is in DER format.

  // We can convert to compressed format like this.

  // See, e.g., https://matthewdowney.github.io/compress-bitcoin-public-key.html.

  let [curveName, pubX, pubY] = await tsmClient.parsePublicKey(
    algorithms.ECDSA,
    pk
  );

  let xBytes = Buffer.from(pubX.buffer);

  let prefix =
    (pubY[31] & 0x01) === 0x00 ? Buffer.from([0x02]) : Buffer.from([0x03]);

  return Buffer.concat([prefix, xBytes]);
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

example();
