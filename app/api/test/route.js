import { setCorsHeaders } from '../../../lib/utils/cors';
import { getFirestoreInstance } from '../../../lib/utils/serverFirebaseUtils';
import admin from 'firebase-admin';

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

export async function GET(request) {
  try {
    const { searchParams } = new URL(request.url);
    const message = searchParams.get('message');
    if (!message) {
      return errorResponse("Missing required query parameter 'message'", 400);
    }

    // Create a document reference at Firestore path: test/{message}
    const docRef = firestore.doc(`test/${message}`);
    
    // Write a document with the 'timestamp' field set to Firestore's server timestamp.
    await docRef.set({
      timestamp: admin.firestore.FieldValue.serverTimestamp(),
    });

    const response = new Response(
      JSON.stringify({ message: "Document created successfully" }),
      { status: 200, headers: { 'Content-Type': 'application/json' } }
    );
    return setCorsHeaders(response);
  } catch (error) {
    console.error("Error writing to Firestore:", error);
    return errorResponse("Error writing to Firestore", 500);
  }
}