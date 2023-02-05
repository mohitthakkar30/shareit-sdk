import * as CryptoTS from "crypto-ts";
import * as bip39 from "bip39";
import * as pkcs7 from "pkcs7-padding";

export const encrypt = async (
  buffer: Uint8Array
): Promise<{
  buffer: Uint8Array;
  mnemonic: string;
}> => {
  // Generate mnemonic and key
  const mnemonic: string = bip39.generateMnemonic(256);
  const key: Buffer = await bip39.mnemonicToSeed(mnemonic);

  // Pad data to align with 4 bytes blocksize used by AES
  const bufferPadded: Buffer = pkcs7.pad(Buffer.from(buffer), 4);

  // Symmetric encryption with AES-256
  const cipherParams = CryptoTS.AES.encrypt(
    new CryptoTS.lib.WordArray([...new Uint32Array(bufferPadded.buffer)]),
    new CryptoTS.lib.WordArray([...new Uint32Array(key.buffer)])
  );

  // Return results
  if (cipherParams.ciphertext != undefined) {
    return {
      buffer: new Uint8Array(
        Uint32Array.from(cipherParams.ciphertext.words).buffer
      ),
      mnemonic,
    };
  } else {
    throw Error;
  }
};

export const decrypt = async (
  buffer: Uint8Array,
  key: Uint8Array
): Promise<Uint8Array> => {
  // Decrypt
  const cipherParams = new CryptoTS.lib.CipherParams({
    ciphertext: new CryptoTS.lib.WordArray([...new Uint32Array(buffer.buffer)]),
  });
  const plaintextWords = CryptoTS.AES.decrypt(
    cipherParams,
    new CryptoTS.lib.WordArray([...new Uint32Array(key.buffer)])
  );

  // Process plaintext to get the original text
  plaintextWords.clamp();
  const plaintextPadded = Buffer.from(
    Uint32Array.from(plaintextWords.words).buffer
  );
  const plaintextUnpadded = pkcs7.unpad(plaintextPadded);

  // Return with correct type
  return new Uint8Array(plaintextUnpadded);
};
