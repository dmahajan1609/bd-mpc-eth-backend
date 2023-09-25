const ethers = require('ethers');
const fs = require('fs');
const prompt = require('prompt');

// Connect to Ethereum node
const rpcEndpoint = process.env.RPC_ENDPOINT;
const provider = new ethers.JsonRpcProvider(rpcEndpoint);

async function main() {
    try {
        // Read credentials from file
        const credentials = fs.readFileSync('../creds.json', 'utf-8');

        // Create ECDSA client from credentials
        const tsmClient = new tsm.NewPasswordClientFromEncoding(3, 1, credentials);
        const ecdsaClient = new tsm.NewECDSAClient(tsmClient);

        // Prompt for Key ID
        prompt.start();
        const { keyID } = await prompt.get(['keyID']);

        // Get the public key
        const pkDER = await ecdsaClient.PublicKey(keyID, null);
        const pk = ASN1ParseSecp256k1PublicKey(pkDER);
        const address = ethers.utils.computeAddress(pk);

        // Create a transaction
        const nonce = await provider.getTransactionCount(address);
        const value = ethers.utils.parseEther('0.1'); // 0.1 ETH in wei
        const gasLimit = 21000;
        const gasPrice = await provider.getGasPrice();

        // To address
        const toAddress = '0x892BB2e4F6b14a2B5b82Ba8d33E5925D42D4431F';
        const data = '0x'; // Data can be empty

        const tx = new ethers.ContractFactory('Transaction', []).getDeployTransaction(nonce, gasPrice, gasLimit, toAddress, value, data);

        // Chain ID
        const chainIDFromEnv = process.env.CHAIN_ID;
        const chainID = ethers.BigNumber.from(chainIDFromEnv);

        const signer = new ethers.Wallet(pk, provider);
        const chainIdBuffer = Buffer.from(chainID.toString());
        const txHash = await signer.signTransaction({ ...tx, chainIdBuffer });

        console.log('send tx');
        await provider.sendTransaction(txHash);

        console.log('tx sent:', txHash.hash);
    } catch (error) {
        console.error(error);
    }
}

function ASN1ParseSecp256k1PublicKey(publicKey) {
    const publicKeyInfo = {
        Raw: null,
        Algorithm: null,
        PublicKey: null,
    };

    const [parsedPublicKey, postfix] = ethers.utils.RLP.decode(publicKey);

    if (postfix.length > 0) {
        throw new Error('Invalid or incomplete ASN1');
    }

    const pk = new ethers.utils.PublicKey(parsedPublicKey);
    return pk;
}

function ASN1ParseSecp256k1Signature(signature) {
    const sig = {
        R: null,
        S: null,
    };

    const [parsedSignature, postfix] = ethers.utils.RLP.decode(signature);

    if (postfix.length > 0) {
        throw new Error('Trailing bytes for ASN1 ecdsa signature');
    }

    sig.R = parsedSignature[0];
    sig.S = parsedSignature[1];

    return [sig.R, sig.S, null];
}

main();
