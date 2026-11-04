import express from "express";
import { JsonRpcProvider, Wallet } from "ethers";
import { requireAuth } from "./auth";

const app = express();
const provider = new JsonRpcProvider(process.env.RPC_URL);
const wallet = new Wallet(process.env.SIGNER_KEY!, provider);
let claimNonce = 0;

const domain = { name: "ClaimBook", version: "2", chainId: 1, verifyingContract: process.env.CLAIM_BOOK! };
const types = {
  Claim: [
    { name: "account", type: "address" },
    { name: "amount", type: "uint256" },
    { name: "nonce", type: "uint256" },
    { name: "expiry", type: "uint256" },
  ],
};

app.post("/claim", requireAuth, async (req, res) => {
  const value = {
    account: req.user.address,
    amount: req.body.amount,
    nonce: claimNonce++,
    expiry: Math.floor(Date.now() / 1000) + 600,
  };
  const signature = await wallet.signTypedData(domain, types, value);
  res.json({ signature, value });
});

export default app;
