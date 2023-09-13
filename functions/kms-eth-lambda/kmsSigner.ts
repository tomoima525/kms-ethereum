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
    // Step1 generate unsigned tx
    const serializedUnsignedTx = ethers.Transaction.from(
      transaction as ethers.TransactionLike,
    );

    // Step2 sign the unsigned tx. Hash of the unsigned tx is the digest which needs to be signed to authorize this transaction
    const txSignature = await this._signDigest(
      ethers.keccak256(serializedUnsignedTx.unsignedSerialized),
    );
    const tx = ethers.Transaction.from(transaction as ethers.TransactionLike);
    // Gotcha - txSignature should not be included in from - internally it instantiates with Signature object which changes the signature and the tx will fail with "invalid sender" error
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

  /**
   * Sign message using ECDSA with the secp256k1 curve and SHA-256 hash algorithm.
   * it’s important to point out that the returned ECDSA signature is different every time it’s calculated, even though the same payload is being used. The reason for that is because AWS KMS doesn’t use Deterministic Digital Signature Generation (DDSG) and certain parameters in the signature calculation process are chosen random, namely the k-value.
   * Reference: https://repost.aws/questions/QU-ocp5jLZTgiBzyXN5exIfA/is-it-possible-to-use-kms-for-web3-signing
   * @param digest
   * @returns
   */
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

    // Maybe we can just set ethSignature.r and ethSignature.s directly, but I'm not sure if that's safe
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
