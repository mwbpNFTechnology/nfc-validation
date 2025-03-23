import { createDecipheriv, createCipheriv, createHmac } from 'crypto';
import { aesCmac } from 'node-aes-cmac';

/* --- Constants --- */
const DIV_CONST2 = Buffer.from("536c6F744D61737465724B6579", "hex");
const DIV_CONST3 = Buffer.from("446976426173654B6579", "hex");

const SDMMAC_PARAM = "cmac";
const AES_BLOCK_SIZE = 16;

/* --- Interface for Decrypted Message --- */
interface DecryptedSunMessage {
  piccDataTag: string;
  uid: string;
  readCtr: number | null;
  fileDataHex: string | null;
  fileDataDecoded: string | null;
  encryptionMode: string;
}

/* --- Helper Functions --- */

/**
 * Pads a Buffer to a multiple of the AES block size (16 bytes) if needed.
 * @param buf The input Buffer.
 * @returns The padded Buffer.
 */
export function padBuffer(buf: Buffer): Buffer {
  const remainder = buf.length % AES_BLOCK_SIZE;
  if (remainder === 0) return buf;
  const padLen = AES_BLOCK_SIZE - remainder;
  return Buffer.concat([buf, Buffer.alloc(padLen, 0x00)]);
}

/**
 * Computes a HMAC-SHA256 digest.
 * @param key The key as a Buffer.
 * @param msg The message as a Buffer.
 * @param noTrunc If true, returns the full digest; otherwise returns the first 16 bytes.
 * @returns The digest as a Buffer.
 */
export function hmacSha256(key: Buffer, msg: Buffer, noTrunc: boolean = false): Buffer {
  const hmac = createHmac("sha256", key);
  hmac.update(msg);
  const digest = hmac.digest();
  return noTrunc ? digest : digest.slice(0, 16);
}

/**
 * Derives a tag key (for diversified mode) replicating the Python function.
 * @param masterKey The master key as a Buffer.
 * @param uid The UID as a Buffer.
 * @param keyNo Optional key number (default is 0).
 * @returns The derived tag key as a Buffer.
 */
export function deriveTagKey(masterKey: Buffer, uid: Buffer, keyNo: number = 0): Buffer {
  if (masterKey.equals(Buffer.alloc(16, 0))) return Buffer.alloc(16, 0);
  const firstHmac = hmacSha256(masterKey, Buffer.concat([DIV_CONST2, Buffer.from([keyNo])]));
  const innerHmac = hmacSha256(masterKey, DIV_CONST3, true);
  const cmacInput = Buffer.concat([Buffer.from([0x01]), hmacSha256(innerHmac, uid)]);
  const tagKey = Buffer.from(aesCmac(firstHmac, cmacInput), 'hex');
  return tagKey;
}

/**
 * Calculates the SDM MAC (AES mode).
 * @param paramMode The parameter mode (e.g. "SEPARATED").
 * @param sdmFileReadKey The file read key as a Buffer.
 * @param piccData The PICC data as a Buffer.
 * @param encFileData Optional encrypted file data as a Buffer.
 * @returns The calculated MAC as a Buffer.
 */
export function calculateSdmmac(
  paramMode: string,
  sdmFileReadKey: Buffer,
  piccData: Buffer,
  encFileData: Buffer | null = null
): Buffer {
  let inputBuf: Buffer;
  if (encFileData) {
    let sdmmacParamText = `&${SDMMAC_PARAM}=`;
    if (paramMode === "BULK" || !SDMMAC_PARAM) {
      sdmmacParamText = "";
    }
    const encHexUpper = encFileData.toString("hex").toUpperCase();
    inputBuf = Buffer.from(encHexUpper + sdmmacParamText, "ascii");
  } else {
    inputBuf = Buffer.alloc(0);
  }
  const sv2Header = Buffer.from([0x3C, 0xC3, 0x00, 0x01, 0x00, 0x80]);
  let sv2Stream = Buffer.concat([sv2Header, piccData]);
  sv2Stream = padBuffer(sv2Stream);
  const c2 = Buffer.from(aesCmac(sdmFileReadKey, sv2Stream), 'hex');
  const sdmmacTmp = Buffer.from(aesCmac(c2, inputBuf), 'hex');
  const macDigest: number[] = [];
  for (let i = 0; i < 16; i++) {
    if (i % 2 === 1) {
      macDigest.push(sdmmacTmp[i]);
    }
  }
  return Buffer.from(macDigest);
}

/**
 * Decrypts file data (AES mode).
 * @param sdmFileReadKey The file read key as a Buffer.
 * @param piccData The PICC data as a Buffer.
 * @param readCtr The read counter as a Buffer.
 * @param encFileData The encrypted file data as a Buffer.
 * @returns The decrypted file data as a Buffer.
 */
export function decryptFileData(
  sdmFileReadKey: Buffer,
  piccData: Buffer,
  readCtr: Buffer,
  encFileData: Buffer
): Buffer {
  const sv1Header = Buffer.from([0xC3, 0x3C, 0x00, 0x01, 0x00, 0x80]);
  let sv1Stream = Buffer.concat([sv1Header, piccData]);
  sv1Stream = padBuffer(sv1Stream);
  const kSesSdmFileReadEnc = Buffer.from(aesCmac(sdmFileReadKey, sv1Stream), 'hex');
  const ivPlain = Buffer.concat([readCtr, Buffer.alloc(13, 0x00)]);
  const ecbCipher = createCipheriv("aes-128-ecb", kSesSdmFileReadEnc, null);
  ecbCipher.setAutoPadding(false);
  const ive = Buffer.concat([ecbCipher.update(ivPlain), ecbCipher.final()]).slice(0, 16);
  const decipher = createDecipheriv("aes-128-cbc", kSesSdmFileReadEnc, ive);
  decipher.setAutoPadding(false);
  const decrypted = Buffer.concat([decipher.update(encFileData), decipher.final()]);
  return decrypted;
}

/**
 * Decrypts a SUN message using the provided keys and encrypted data.
 * @param paramMode The parameter mode (e.g. "SEPARATED").
 * @param sdmMetaReadKey The meta key as a Buffer.
 * @param sdmFileReadKeyCallable A callable that returns the file read key given a UID.
 * @param piccEncData The PICC encrypted data as a Buffer.
 * @param sdmmac The MAC as a Buffer.
 * @param encFileData Optional encrypted file data as a Buffer.
 * @returns An object with details of the decrypted message.
 */
export function decryptSunMessage(
  paramMode: string,
  sdmMetaReadKey: Buffer,
  sdmFileReadKeyCallable: (uid: Buffer) => Buffer,
  piccEncData: Buffer,
  sdmmac: Buffer,
  encFileData: Buffer | null = null
): DecryptedSunMessage {
  const ivZero = Buffer.alloc(16, 0x00);
  const decipher = createDecipheriv("aes-128-cbc", sdmMetaReadKey, ivZero);
  decipher.setAutoPadding(false);
  const plaintext = Buffer.concat([decipher.update(piccEncData), decipher.final()]);
  
  let offset = 0;
  const piccDataTag = plaintext.slice(offset, offset + 1);
  offset += 1;
  const uidMirroringEn = (piccDataTag[0] & 0x80) === 0x80;
  const sdmReadCtrEn = (piccDataTag[0] & 0x40) === 0x40;
  const uidLength = piccDataTag[0] & 0x0F;
  
  if (uidLength !== 0x07) {
    sdmFileReadKeyCallable(Buffer.alloc(7, 0x00));
    throw new Error("Unsupported UID length");
  }
  
  let uid: Buffer;
  let dataStream = Buffer.alloc(0);
  if (uidMirroringEn) {
    uid = plaintext.slice(offset, offset + uidLength);
    offset += uidLength;
    dataStream = Buffer.concat([dataStream, uid]);
  } else {
    throw new Error("UID cannot be null");
  }
  
  let readCtr: Buffer | null = null;
  let readCtrNum: number | null = null;
  if (sdmReadCtrEn) {
    readCtr = plaintext.slice(offset, offset + 3);
    offset += 3;
    dataStream = Buffer.concat([dataStream, readCtr]);
    readCtrNum = readCtr.readUIntLE(0, 3);
  }
  
  const fileKey = sdmFileReadKeyCallable(uid);
  const calculatedMac = calculateSdmmac(paramMode, fileKey, dataStream, encFileData);
  if (!calculatedMac.equals(sdmmac)) {
    throw new Error("Message is not properly signed - invalid MAC");
  }
  
  let fileData: Buffer | null = null;
  if (encFileData) {
    if (!readCtr) {
      throw new Error("SDMReadCtr is required to decipher SDMENCFileData.");
    }
    fileData = decryptFileData(fileKey, dataStream, readCtr, encFileData);
  }
  
  return {
    piccDataTag: piccDataTag.toString("hex"),
    uid: uid.toString("hex"),
    readCtr: readCtrNum,
    fileDataHex: fileData ? fileData.toString("hex") : null,
    fileDataDecoded: fileData ? fileData.toString("utf-8").replace(/\x00+$/, "") : null,
    encryptionMode: "AES"
  };
}

/**
 * Decrypts an NFC message given hex string parameters and a meta key.
 * @param piccDataHex The PICC encrypted data as a hex string.
 * @param encHex The encrypted file data as a hex string.
 * @param cmacHex The MAC as a hex string.
 * @param sdmMetaReadKey The meta key as a Buffer.
 * @param sdmFileReadKeyCallable A function that returns the file read key given a UID.
 * @param paramMode The parameter mode (default "SEPARATED").
 * @returns The decrypted NFC message object.
 */
export function decryptNfcMessage(
  piccDataHex: string,
  encHex: string,
  cmacHex: string,
  sdmMetaReadKey: Buffer,
  sdmFileReadKeyCallable: (uid: Buffer) => Buffer,
  paramMode: string = "SEPARATED"
): DecryptedSunMessage {
  const piccEncData = Buffer.from(piccDataHex, "hex");
  const encFileData = Buffer.from(encHex, "hex");
  const sdmmac = Buffer.from(cmacHex, "hex");
  
  return decryptSunMessage(
    paramMode,
    sdmMetaReadKey,
    sdmFileReadKeyCallable,
    piccEncData,
    sdmmac,
    encFileData
  );
}