import { ethers } from "ethers";
import { createKey, getPubAddress, getPublicKey } from "./kms";
import { KmsSigner } from "./kmsSigner";
import { getSecret } from "./secretManager";

type Op = "generate" | "get" | "getPubAddress" | "sign" | "send";
type Props = {
  operation: Op;
  keyId?: string;
  to?: string;
};

export const handler = async ({
  operation,
  keyId,
  to,
}: Props): Promise<any> => {
  console.log("operation", operation);
  console.log("keyId", keyId);
  let response;
  switch (operation) {
    case "generate": {
      response = await createKey();
      break;
    }

    case "get": {
      if (!keyId) {
        response = { error: "Get: keyId is required" };
      }
      response = await getPublicKey(keyId as string);
      break;
    }

    case "getPubAddress": {
      if (!keyId) {
        response = { error: "Get: keyId is required" };
      }
      const address = await getPubAddress(keyId as string);
      response = { address, lentgh: address.length };
      break;
    }

    // returns the signed transaction as a hex string wrapped in a JSON object
    case "sign": {
      if (!keyId) {
        response = { error: "Sign: keyId is required" };
      }
      if (!to) {
        response = { error: "Sign: to is required" };
      }
      // connect with provider
      const alchemyKey = await getSecret("ALCHEMY_GOERLI_URL");
      const provider = new ethers.AlchemyProvider("goerli", alchemyKey);
      const signer = new KmsSigner(keyId as string);

      const tx = await signer.connect(provider).populateTransaction({
        to,
        value: ethers.parseEther("0.001"),
      });
      try {
        // omit from from populated tx so that we can sign from our kms key
        delete tx.from;
        const signedTx = await signer.signTransaction(tx);
        response = { signedTx };
      } catch (error) {
        console.log("error", error);
      }

      break;
    }
    case "send": {
      if (!keyId) {
        response = { error: "Sign: keyId is required" };
      }
      if (!to) {
        response = { error: "Sign: to is required" };
      }
      // connect with provider
      const alchemyKey = await getSecret("ALCHEMY_GOERLI_URL");
      const provider = new ethers.AlchemyProvider("goerli", alchemyKey);
      const signer = new KmsSigner(keyId as string);

      try {
        const txResponse = await signer.connect(provider).sendTransaction({
          to,
          value: ethers.parseEther("0.001"),
        });
        response = { txHash: txResponse.hash };
      } catch (error) {
        console.log("error", error);
      }

      break;
    }

    default:
      response = { error: "unknown operation" };
      break;
  }

  return response;
};
