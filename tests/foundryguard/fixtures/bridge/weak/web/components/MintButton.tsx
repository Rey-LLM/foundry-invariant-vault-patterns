import { Wallet, JsonRpcProvider } from "ethers";

const key = process.env.NEXT_PUBLIC_MINTER_PRIVATE_KEY;
const rpc = "https://eth-mainnet.g.alchemy.com/v2/AbCdEfGhIjKlMnOpQrStUvWx";

export function MintButton() {
  const minter = new Wallet(key!, new JsonRpcProvider(rpc));
  return <button onClick={() => minter.signMessage("mint")}>Mint</button>;
}
