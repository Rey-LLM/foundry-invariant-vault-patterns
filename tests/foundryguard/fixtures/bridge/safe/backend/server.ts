import express from "express";
import helmet from "helmet";
import { z } from "zod";
import { Contract, JsonRpcProvider, Wallet } from "ethers";
import { requireSession } from "./session";
import abi from "./SafeClaim.json";

const app = express();
app.use(helmet());
const CONFIRMATIONS = 12;
const MAX_CLAIM = 1_000n * 10n ** 18n;
const provider = new JsonRpcProvider(process.env.RPC_URL);
const signer = new Wallet(process.env.SIGNER_KEY!, provider);
const claimContract = new Contract(process.env.CLAIM_ADDRESS!, abi, provider);
const Body = z.object({ amount: z.coerce.bigint().positive().max(MAX_CLAIM) });

const domain = {
  name: "SafeClaim",
  version: "1",
  chainId: Number(process.env.CHAIN_ID),
  verifyingContract: process.env.CLAIM_ADDRESS!,
};
const types = {
  Claim: [
    { name: "account", type: "address" },
    { name: "amount", type: "uint256" },
    { name: "nonce", type: "uint256" },
    { name: "deadline", type: "uint256" },
  ],
};

app.post("/claim", requireSession, async (req, res) => {
  const { amount } = Body.parse(req.body);
  const account = req.user.address;
  const nonce = await claimContract.nonces(account);
  const deadline = Math.floor(Date.now() / 1000) + 600;
  const value = { account, amount, nonce, deadline };
  const signature = await signer.signTypedData(domain, types, value);
  res.json({ signature, value });
});

claimContract.on("Claimed", async (account, amount, event) => {
  const receipt = await provider.waitForTransaction(event.log.transactionHash, CONFIRMATIONS);
  if (!receipt || receipt.status !== 1) return;
  await recordClaim(account, amount);
});

export default app;
