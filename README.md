Offline Tx Signer
==============

Meant for easy offline signing of BIP32 based bitcoin (or alt-coin) transactions, and developed in a way to be easily integrated with other software systems.  Integration is a simple matter developing two features – one to provide a JSON file of raw inputs / outputs that are awaiting to be signed, and another to import a JSON file of signed transactions and send them appropriately.

This supports BIP32 addresses, all formats of key indexes, multi-signature transactions, generation of both master and hardened child keys, and more.  It will also spend change during the signing process, meaning as long as the amount of inputs in the JSON file are of equal or greater value to the amount of outputs, all necessary transactions will be signed / generated.


## Raw Transaction Format

First requirement is to develop a feature within your software that will provide your users a JSON file of raw inputs / outputs that are awaiting to be signed.  This is meant for watch-only wallets or similar, meaning you should already have a database of unspent inputs.  Due to change, instead of using full raw transactions, the file format only requires a list of inputs and outputs.


##### Quick Example

```
{
“txfee_paidby”: “sender”, 

"inputs": [
     { "input_id":"4",
        "amount":"0.20000000",
        "txid":"606c772eaaaf5e8456f9670251b52e97b8a8134d6f84c5a662807c6cd7e75ec9",
        "vout":"1",
        "sigscript":"76a9146f089bc9abc84550298dd547341c964a810248e788ac",
        "keyindex":"0\/13",
        "change_keyindex":"1\/14"
     }
],

"outputs": [
      { "output_id":"2",
        "amount":"0.10000000",
        "address":"mhCnq89xRnfmmBerVW7aN3cQG9KJr6mRF7"
      }
]
}
```


##### Settings

Settings that are available within the JSON file, but not required.  These allow you to do things such as define who pays the fee, the base tx fee, and more.

Variable | Required | Notes
-------- | -------- | -----
wallet_id | No | Any type of unique ID# or name for the wallet processing the funds.  If present, this variable will be included in the return file.
txfee_paidby | No | Can be either:  **sender**, **recipient**, or **site**.  Defaults to recipient.
txfee | No | The base tx fee to charge (per 1000 bytes)  Defaults to 0.0001
change_keyindex | No | Optional.  Default key index to use (eg. 1/43) to use for all change transactions generated during a batch signing.  Only used for inputs that do not have a change_keyindex assigned to them.  Can be “source_address” if desired, which will send the change back to the original input address.


##### Inputs


