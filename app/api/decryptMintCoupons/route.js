import { setCorsHeaders } from '../../../lib/utils/cors';
import { getFirestoreInstance } from '../../../lib/utils/serverFirebaseUtils';
import { decryptTextPlain } from '../../../lib/utils/kmsUtils';
import { 
  MINT_COUPONS_COLLECTION_FIREBASE,
  COUPONS_DOC_FIREBASE 
} from '../../../lib/utils/keyNames';

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

export async function GET() {
  try {
    // Retrieve the document from Firebase at "mint_coupons/coupons"
    const docRef = firestore.doc(`${MINT_COUPONS_COLLECTION_FIREBASE}/${COUPONS_DOC_FIREBASE}`);
    const docSnapshot = await docRef.get();
    if (!docSnapshot.exists) {
      return errorResponse('Document not found', 404);
    }
    
    const data = docSnapshot.data();
    const encryptedText = data.encryptedText;
    if (!encryptedText) {
      return errorResponse('encryptedText not found in document', 404);
    }
    
    // Decrypt the encryptedText using AWS KMS and get the coupons string.
    const coupons = await decryptTextPlain(encryptedText);
    
    // If desired, you could split into an array:
    // const couponsArray = coupons.split(',').map(coupon => coupon.trim());
    
    const responseBody = {
      message: 'Decrypted successfully',
      data: { coupons },
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