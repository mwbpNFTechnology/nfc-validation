import { setCorsHeaders } from '../../../lib/utils/cors';
import { getFirestoreInstance } from '../../../lib/utils/serverFirebaseUtils';
import admin from 'firebase-admin';
import { encryptText, generateNonce, createEncryptedKeyData } from '../../../lib/utils/kmsUtils';
import { 
  MINT_COUPONS_COLLECTION_FIREBASE,
  COUPONS_DOC_FIREBASE,
  PROTOTYPE_KEY_COLLECTION_FIREBASE,
  ENC_FIELD_FIREBASE
} from '../../../lib/utils/keyNames';

function errorResponse(message, statusCode) {
  const body = JSON.stringify({ error: message });
  const response = new Response(body, {
    status: statusCode,
    headers: { 'Content-Type': 'application/json' },
  });
  return setCorsHeaders(response);
}

export async function OPTIONS() {
  const response = new Response(null, { status: 204 });
  return setCorsHeaders(response);
}

export async function POST(request) {
  try {
    // Parse the JSON payload
    const jsonBody = await request.json();
    const firestore = getFirestoreInstance();

    // ============================================
    // Part 1: Process all coupons (route 1 logic)
    // ============================================
    // Extract all "mint" values and join them with a comma
    const mints = Object.values(jsonBody)
      .filter((entry) => entry.mint)
      .map((entry) => entry.mint);
    const mintsString = mints.join(',');
    
    // Generate a nonce and create the payload to be encrypted
    const nonce = generateNonce();
    const couponsPayload = JSON.stringify({
      coupons: mintsString,
      nonce: nonce,
    });
    
    // Encrypt the payload
    const encryptedCoupons = await encryptText(couponsPayload);
    
    // Save the encrypted coupons data to Firebase under the defined collection/document
    const couponsDocRef = firestore.doc(`pathzComicPrototype/${COUPONS_DOC_FIREBASE}`);
    await couponsDocRef.set({
      encryptedText: encryptedCoupons,
      lastUpdateTimestamp: admin.firestore.FieldValue.serverTimestamp(),
    });

    // ========================================================
    // Part 2: Process individual entries with uuid not "none"
    // ========================================================
    // Loop over each object and process if uuid is not "none"
    for (const key in jsonBody) {
      if (Object.prototype.hasOwnProperty.call(jsonBody, key)) {
        const entry = jsonBody[key];
        // Only process if uuid is provided and not "none"
        if (entry.uuid && entry.uuid !== "none") {
          const uid = entry.uuid;         // Use the provided uuid as uid
          const ctr = "0";                // Set counter to 0 (as required)
          const aes128 = entry.key;       // Use the "key" field as aes128
          const mint = entry.mint;
          
          // Validate that all required fields are present
          if (!uid || !ctr || !aes128 || !mint) {
            console.error(`Missing required fields for entry ${key}`);
            continue;
          }
          
          // Encrypt the individual key data
          const encryptedKeyData = await createEncryptedKeyData(uid, ctr, aes128, mint);
          
          // Save this encrypted data to Firebase under the specified collection
          const keyDocRef = firestore.doc(`pathzComicPrototype/keys/keys/${uid}`);
          await keyDocRef.set({
            [ENC_FIELD_FIREBASE]: encryptedKeyData,
            lastUpdateTimestamp: admin.firestore.FieldValue.serverTimestamp(),
          });
        }
      }
    }
    
    // Construct and return the response
    const responseBody = {
      message: "Documents created successfully",
      data: {
        couponsEncryption: encryptedCoupons,
      },
    };
    
    const response = new Response(JSON.stringify(responseBody), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
    
    return setCorsHeaders(response);
    
  } catch (error) {
    console.error("Error processing request:", error);
    return errorResponse("Error processing request", 500);
  }
}