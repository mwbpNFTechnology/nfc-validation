import { setCorsHeaders } from '../../../lib/utils/cors';
import { getFirestoreInstance } from '../../../lib/utils/serverFirebaseUtils';
import { decryptText } from '../../../lib/utils/kmsUtils';
import { PROTOTYPE_KEY_COLLECTION_NAME } from '../../../lib/utils/keyNames';

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
    const uid = searchParams.get('uid');
    if (!uid) {
      return errorResponse("Missing required query parameter 'uid'", 400);
    }

    // Retrieve document from Firestore at path: test/{path}
    const docRef = firestore.doc(`${PROTOTYPE_KEY_COLLECTION_NAME}/${uid}`);
    const docSnapshot = await docRef.get();
    if (!docSnapshot.exists) {
      return errorResponse("Document not found", 404);
    }
    const data = docSnapshot.data();
    const encryptedText = data.encryptedText;
    if (!encryptedText) {
      return errorResponse("No encryptedText found in document", 400);
    }

    // Use the decryptText function from mksUtils.ts to decrypt the message.
    const decryptedMessage = await decryptText(encryptedText);

    const response = new Response(
      JSON.stringify({
        message: "Decrypted successfully",
        decryptedMessage,
      }),
      { status: 200, headers: { 'Content-Type': 'application/json' } }
    );
    return setCorsHeaders(response);
  } catch (error) {
    console.error("Error processing request:", error);
    return errorResponse("Error processing request", 500);
  }
}