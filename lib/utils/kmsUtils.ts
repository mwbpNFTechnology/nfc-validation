import { randomBytes } from 'crypto';
import { KMSClient, EncryptCommand, DecryptCommand } from '@aws-sdk/client-kms';
import {
  UID_ENC_JSON_KEY,
  CTR_ENC_JSON_KEY,
  AES128_ENC_JSON_KEY,
  MINT_ENC_JSON_KEY,
  NONCE_ENC_JSON_KEY,
  // MESSAGE_ENC_JSON_KEY, // if needed elsewhere
} from './keyNames';

// Create an AWS KMS client using credentials from environment variables.
const kmsClient = new KMSClient({
  region: process.env.AWS_REGION,
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID!,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY!,
  },
});

/**
 * Encrypts a raw text using AWS KMS and returns the encrypted text as a base64-encoded string.
 * @param {string} rawText - The plaintext message to be encrypted.
 * @returns {Promise<string>} - The encrypted ciphertext in base64 encoding.
 */
export async function encryptText(rawText: string): Promise<string> {
  if (!process.env.AWS_KMS_KEY_ID) {
    throw new Error('AWS_KMS_KEY_ID is not defined');
  }
  
  const encryptCommand = new EncryptCommand({
    KeyId: process.env.AWS_KMS_KEY_ID,
    Plaintext: Buffer.from(rawText, 'utf8'),
  });
  
  const encryptResult = await kmsClient.send(encryptCommand);
  return Buffer.from(encryptResult.CiphertextBlob!).toString('base64');
}

/**
 * Decrypts a base64-encoded ciphertext using AWS KMS and returns the decrypted text.
 * @param {string} encryptedText - The base64 encoded encrypted text.
 * @returns {Promise<string>} - The decrypted plaintext.
 */
export async function decryptText(encryptedText: string): Promise<string> {
  // Convert base64 string back to a Buffer.
  const ciphertextBlob = Buffer.from(encryptedText, 'base64');

  // Prepare and send the decrypt command.
  const decryptCommand = new DecryptCommand({
    CiphertextBlob: ciphertextBlob,
  });
  const decryptResult = await kmsClient.send(decryptCommand);

  // Convert the decrypted Buffer to a UTF-8 string.
  const decryptedString = Buffer.from(decryptResult.Plaintext!).toString('utf8');

  console.log("decryptedString: ", decryptedString);

  // Parse the JSON payload and return the "message" field.
  // This assumes the decrypted JSON has the structure: { "message": "...", "nonce": "..." }
  const parsedPayload = JSON.parse(decryptedString);
  return parsedPayload;
}

/**
 * Generates a random nonce of the specified byte length and returns it as a hexadecimal string.
 * @param {number} [length=16] - The length in bytes of the nonce (default is 16 bytes).
 * @returns {string} - The generated nonce as a hexadecimal string.
 */
export function generateNonce(length: number = 16): string {
  return randomBytes(length).toString('hex');
}

/**
 * Creates a key data object from the provided uuid, ctr, and aes128,
 * adds a generated nonce, encrypts the JSON payload using AWS KMS,
 * and returns the encrypted ciphertext in base64 encoding.
 *
 * The JSON payload has the structure:
 * {
 *   "uuid": <uuid>,
 *   "ctr": <ctr>,
 *   "aes128": <aes128>,
 *   "nonce": <generatedNonce>
 * }
 *
 * @param {string} uid - The unique identifier.
 * @param {string} ctr - The ctr value.
 * @param {string} aes128 - The aes128 value.
 * @param {string} mint - The mint value.
 * @returns {Promise<string>} - The encrypted ciphertext in base64 encoding.
 */
export async function createEncryptedKeyData(uid: string, ctr: string, aes128: string, mint: string): Promise<string> {
  // Create an object with the provided values and a generated nonce using constants from keyNames.ts.
  const keyData = {
    [UID_ENC_JSON_KEY]: uid.toUpperCase(),
    [CTR_ENC_JSON_KEY]: ctr,
    [AES128_ENC_JSON_KEY]: aes128,
    [MINT_ENC_JSON_KEY]: mint,
    [NONCE_ENC_JSON_KEY]: generateNonce(),
  };

  console.log("keyData: ", keyData);
  
  // Convert the key data object to a JSON string.
  const payload = JSON.stringify(keyData);
  
  // Encrypt the JSON payload using AWS KMS and return the encrypted text.
  return await encryptText(payload);
}

/**
 * Decrypts a base64-encoded ciphertext using AWS KMS and returns the full JSON object.
 * @param {string} encryptedText - The base64 encoded encrypted text.
 * @returns {Promise<Record<string, unknown>>} - The full decrypted JSON object.
 */
export async function decryptKeyData(encryptedText: string): Promise<Record<string, unknown>> {
  const ciphertextBlob = Buffer.from(encryptedText, 'base64');
  const decryptCommand = new DecryptCommand({ CiphertextBlob: ciphertextBlob });
  const decryptResult = await kmsClient.send(decryptCommand);
  const decryptedString = Buffer.from(decryptResult.Plaintext!).toString('utf8');
  return JSON.parse(decryptedString);
}