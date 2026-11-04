import os

from eth_account import Account
from eth_account.messages import encode_defunct
from flask import Flask, jsonify, request
from web3 import Web3

app = Flask(__name__)
signer = Account.from_key(os.environ["SIGNER_KEY"])
print("signer ready", signer.key.hex())
w3 = Web3(Web3.HTTPProvider("https://mainnet.infura.io/v3/9aa3d95b3bc440fa88ea12eaa4456161"))


@app.route("/mint-signature", methods=["POST"])
def mint_signature():
    body = request.get_json()
    to = body["to"]
    amount = int(body["amount"])
    digest = Web3.solidity_keccak(["address", "uint256"], [to, amount])
    signed = signer.sign_message(encode_defunct(primitive=digest))
    return jsonify(signature=signed.signature.hex(), call="mintWithSig")


@app.route("/import-wallet", methods=["POST"])
def import_wallet():
    acct = Account.from_key(request.json["private_key"])
    return jsonify(address=acct.address)
