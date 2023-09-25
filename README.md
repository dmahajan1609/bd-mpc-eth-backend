# bd-mpc-eth-backend
Integrates with Blockdaemon Nodejs SDK to generate Signatures and Sign transactions with.

## Get creds from local filesystem and copy into `creds.json`
Sample creds.json
```

{
    "creds1": [
    {
        "url": "https://pilot1.tsm.sepior.net",
        "userID": ${userId},
        "password": ${pwd}

    }],
    "creds2": [
        {
        "url": "https://pilot2.tsm.sepior.net",
        "userID": ${userId},
        "password": ${pwd}

    }],
    "creds3": [{
        "url": "https://pilot3.tsm.sepior.net",
        "userID": ${userId},
        "password": ${pwd}
    }]
}
```

## Start Local Ganache console and run `send-txn.js`
```
node send-txn.js
```

