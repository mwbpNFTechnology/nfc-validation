import { setCorsHeaders } from '../../../lib/utils/cors';
import { getFirestoreInstance } from '../../../lib/utils/serverFirebaseUtils';
import admin from 'firebase-admin';
import { encryptText, generateNonce } from '../../../lib/utils/kmsUtils';
import { 
  MINT_COUPONS_COLLECTION_FIREBASE,
  COUPONS_DOC_FIREBASE 
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
    // Parse the JSON payload sent in the POST request.
    // Expected format:
    // {
    //   "0": { "mint": "da0d5780a07cbb15262db111d8bf97_1", ... },
    //   "1": { "mint": "a722dbf730937648cab2f8977f37f8_2", ... },
    //   ...
    // }
    const jsonBody = await request.json();
    
    // Extract all "mint" fields.
    const mints = Object.values(jsonBody)
      .filter((entry) => entry.mint)
      .map((entry) => entry.mint);
      
    // Join the mint values into a comma-separated string.
    const mintsString = mints.join(',');
    
    // Generate a nonce.
    const nonce = generateNonce();
    
    // Create the payload object and stringify it.
    const payload = JSON.stringify({
      coupons: mintsString,
      nonce: nonce
    });
    
    // Encrypt the JSON payload using AWS KMS.
    const encrypted = await encryptText(payload);
    
    // Save the encrypted text to Firebase under "mint_coupons/coupons".
    const firestore = getFirestoreInstance();
    const docRef = firestore.doc(`${MINT_COUPONS_COLLECTION_FIREBASE}/${COUPONS_DOC_FIREBASE}`);
    await docRef.set({
      encryptedText: encrypted,
      lastUpdateTimestamp: admin.firestore.FieldValue.serverTimestamp(),
    });
    
    const responseBody = {
      message: "Document created successfully",
      data: { encryptedText: encrypted },
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