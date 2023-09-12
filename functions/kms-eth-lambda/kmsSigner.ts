import { ethers } from "ethers";
import {
  determineCorrectV,
  findEthereumSig,
  getPubAddress,
  signWithKMS,
} from "./kms";

export class KmsSigner extends ethers.AbstractSigner {
  keyId: string;

  constructor(kmsKeyId: string, provider?: ethers.Provider) {
    super(provider);
    this.keyId = kmsKeyId;
  }

  async getAddress(): Promise<string> {
    return await getPubAddress(this.keyId);
  }

  async signMessage(message: ethers.BytesLike | string): Promise<string> {
    return (await this._signDigest(ethers.hashMessage(message))).serialized;
  }

  async signTransaction(
    transaction: ethers.TransactionRequest,
  ): Promise<string> {
    const serializedUnsignedTx = ethers.Transaction.from(
      transaction as ethers.TransactionLike,
    );
    const txSignature = await this._signDigest(
      ethers.keccak256(serializedUnsignedTx.unsignedSerialized),
    );
    const tx = ethers.Transaction.from(transaction as ethers.TransactionLike);
    tx.signature = txSignature;
    return tx.serialized;
  }

  async signTypedData(
    domain: ethers.TypedDataDomain,
    types: Record<string, ethers.TypedDataField[]>,
    value: Record<string, any>,
  ): Promise<string> {
    // TODO: implement
    return "";
  }

  private async _signDigest(digest: string): Promise<ethers.Signature> {
    const digestBuffer = ethers.getBytes(digest);
    const sig = await signWithKMS(this.keyId, digestBuffer);
    const ethAddress = await getPubAddress(this.keyId);
    const ethSignature = findEthereumSig(Buffer.from(sig.Signature));
    const { v } = await determineCorrectV(
      digestBuffer,
      ethSignature.r,
      ethSignature.s,
      ethAddress,
    );
    return ethers.Signature.from({
      r: `0x${ethSignature.r.toString("hex")}`,
      s: `0x${ethSignature.s.toString("hex")}`,
      v,
    });
  }
  connect(provider: ethers.Provider): KmsSigner {
    return new KmsSigner(this.keyId, provider);
  }
}
