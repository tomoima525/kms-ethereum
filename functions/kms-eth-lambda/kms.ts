import {
  KMSClient,
  CreateKeyCommand,
  GetPublicKeyCommand,
  SignCommand,
} from "@aws-sdk/client-kms";
import * as asn1 from "asn1.js";
import BN from "bn.js";
import { ethers, keccak256 } from "ethers";

const client = new KMSClient({ region: "us-west-2" });

const EcdsaSigAsnParse: {
  decode: (asnStringBuffer: Buffer, format: "der") => { r: BN; s: BN };
} = asn1.define("EcdsaSig", function (this: any) {
  // parsing this according to https://tools.ietf.org/html/rfc3279#section-2.2.3
  this.seq().obj(this.key("r").int(), this.key("s").int());
});

const EcdsaPubKey = asn1.define("EcdsaPubKey", function (this: any) {
  // parsing this according to https://tools.ietf.org/html/rfc5480#section-2
  this.seq().obj(
    this.key("algo").seq().obj(this.key("a").objid(), this.key("b").objid()),
    this.key("pubKey").bitstr(),
  );
});

export const createKey = async (): Promise<any> => {
  const command = new CreateKeyCommand({
    KeyUsage: "SIGN_VERIFY",
    KeySpec: "ECC_SECG_P256K1",
  });
  return await client.send(command);
};

export const getPublicKey = async (keyId: string): Promise<any> => {
  const command = new GetPublicKeyCommand({
    KeyId: keyId,
  });
  return await client.send(command);
};

/**
   * 1. a random private key (64 (hex) characters / 256 bits / 32 bytes)
   2. Derive the public key from this private key (128 (hex) characters / 512 bits / 64 bytes)
   3.Derive the address from this public key. (40 (hex) characters / 160 bits / 20 bytes)
   4. Checksum encode
*/
export const getPubAddress = async (keyId: string): Promise<`0x${string}`> => {
  const command = new GetPublicKeyCommand({
    KeyId: keyId,
  });
  const response = await client.send(command);
  const publicKey = response.PublicKey;
  if (!publicKey) {
    throw new Error("No public key found");
  }
  const res = EcdsaPubKey.decode(Buffer.from(publicKey), "der");
  const pubKeyBuffer = res.pubKey.data;

  // The public key starts with a 0x04 prefix that needs to be removed
  // more info: https://www.oreilly.com/library/view/mastering-ethereum/9781491971932/ch04.html
  const removedPrefixPubKey = pubKeyBuffer.slice(1, pubKeyBuffer.length);
  if (removedPrefixPubKey) {
    // use the last 20 bytes(40chars) of the keccak256 hex hash of the public key
    const address = `0x${keccak256(removedPrefixPubKey).slice(
      -40,
    )}` as `0x${string}`;
    return address;
  } else {
    throw new Error("No public key found from DER encoded public key");
  }
};

export const signWithKMS = async (
  keyId: string,
  digest: Uint8Array,
): Promise<any> => {
  const command = new SignCommand({
    KeyId: keyId,
    Message: digest,
    MessageType: "DIGEST",
    SigningAlgorithm: "ECDSA_SHA_256",
  });
  const result = await client.send(command);
  return result;
};

export const findEthereumSig = (signature: Buffer) => {
  const decoded = EcdsaSigAsnParse.decode(signature, "der");
  const { r, s } = decoded;
  try {
    const secp256k1N = new BN(
      "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
      16,
    ); // max value on the curve
    const secp256k1halfN = secp256k1N.div(new BN(2)); // half of the curve
    const ss = s.gt(secp256k1halfN) ? secp256k1N.sub(s) : s;
    // Because of EIP-2 not all elliptic curve signatures are accepted
    // the value of s needs to be SMALLER than half of the curve
    // i.e. we need to flip s if it's greater than half of the curve
    // if s is less than half of the curve, we're on the "good" side of the curve, we can just return
    return { r, s: s.gt(secp256k1halfN) ? secp256k1N.sub(s) : s };
  } catch (error) {
    console.log("error", error);
    throw new Error("Invalid signature");
  }
};

const recoverPubKeyFromSig = (msg: Uint8Array, r: BN, s: BN, v: number) => {
  return ethers.recoverAddress(msg, {
    r: `0x${r.toString("hex")}`,
    s: `0x${s.toString("hex")}`,
    v,
  });
};

// This is the wrapper function to find the right v value
// There are two matching signatues on the elliptic curve
// we need to find the one that matches to our public key
// it can be v = 27 or v = 28
export const determineCorrectV = async (
  msg: Uint8Array,
  r: BN,
  s: BN,
  expectedEthAddr: string,
) => {
  let v = 27;
  let pubKey = recoverPubKeyFromSig(msg, r, s, v);
  if (pubKey.toLowerCase() !== expectedEthAddr.toLowerCase()) {
    // if the pub key for v = 27 does not match
    // it has to be v = 28
    v = 28;
    pubKey = recoverPubKeyFromSig(msg, r, s, v);
  }
  return { v };
};
