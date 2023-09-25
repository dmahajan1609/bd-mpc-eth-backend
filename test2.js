function test() {
    const context = require("context");
    const crypto = require("crypto");
    const { Transaction } = require("ethereumjs-tx");
    const { ethers } = require("ethers");
    const { prompt } = require("promptui");
    const tsm = require("tsm");
  
    const main = async () => {
      const tx = new Transaction({
        nonce: nonce,
        to: toAddress,
        value: value,
        gasLimit: gasLimit,
        gasPrice: gasPrice,
        data: data,
      });
      const chainID = BigInt(chainIDFromEnv);
      if (isNaN(chainID)) {
        console.log("error setting chain id from env");
        process.exit(1);
      }
      console.log(chainID.toString());
      const signer = new ethers.utils.SigningKey(privateKey);
      const signedTx = signer.sign(tx);
      console.log("sign tx");
      const h = signedTx.hash();
    };
  
    main();
  }