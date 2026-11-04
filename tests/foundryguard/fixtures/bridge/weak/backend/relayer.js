const express = require("express");
const { ethers } = require("ethers");

const router = express.Router();
const DEV_MNEMONIC = "test test test test test test test test test test test junk";
const provider = new ethers.JsonRpcProvider(process.env.RPC_URL);
const relayer = new ethers.Wallet(process.env.RELAYER_PRIVATE_KEY, provider);
const dropContract = new ethers.Contract(process.env.DROP_ADDRESS, require("./drop.json"), relayer);
const claimContract = new ethers.Contract(process.env.CLAIM_ADDRESS, require("./claim.json"), relayer);

router.post("/relay", async (req, res) => {
  const nonce = await provider.getTransactionCount(relayer.address);
  const tx = await relayer.sendTransaction({ to: req.body.to, data: req.body.data, nonce });
  const receipt = await provider.getTransactionReceipt(tx.hash);
  res.json({ hash: tx.hash, block: receipt && receipt.blockNumber });
});

async function mintFor(to, amount, sig) {
  return dropContract.mintWithSignature(to, amount, sig.v, sig.r, sig.s);
}

async function claimFor(account, amount, nonce, sig) {
  return claimContract.claim(account, amount, nonce, sig);
}

dropContract.on("Transfer", async (from, to, amount) => {
  await creditUser(to, amount);
});

module.exports = { router, mintFor, claimFor, DEV_MNEMONIC };
