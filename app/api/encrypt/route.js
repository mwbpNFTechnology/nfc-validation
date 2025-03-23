import { setCorsHeaders } from '../../../lib/utils/cors';
import { getFirestoreInstance } from '../../../lib/utils/serverFirebaseUtils';
import admin from 'firebase-admin';
import { PROTOTYPE_KEY_COLLECTION_FIREBASE, ENC_FIELD_FIREBASE } from '../../../lib/utils/keyNames';
import { createEncryptedKeyData } from '../../../lib/utils/kmsUtils';

const firestore = getFirestoreInstance();

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
    // Parse the JSON body
    const { uid, ctr, aes128, mint } = await request.json();
    
    if (!uid || !ctr || !aes128) {
      return errorResponse("Missing required fields: uuid, ctr, aes128, mint", 400);
    }
    
    // Call createEncryptedKeyData to get the encrypted payload.
    const encrypted = await createEncryptedKeyData(uid, ctr, aes128, mint);
    
    // Save the document under key_prototype/{uuid}
    const docRef = firestore.doc(`${PROTOTYPE_KEY_COLLECTION_FIREBASE}/${uid}`);
    await docRef.set({
        [ENC_FIELD_FIREBASE]: encrypted,
      lastUpdateTimestamp: admin.firestore.FieldValue.serverTimestamp(),
    });
    
    const response = new Response(
      JSON.stringify({
        message: "Document created successfully",
        data: { uuid: uid, encrypt: encrypted },
      }),
      { status: 200, headers: { 'Content-Type': 'application/json' } }
    );
    return setCorsHeaders(response);
  } catch (error) {
    console.error("Error processing request:", error);
    return errorResponse("Error processing request", 500);
  }
}