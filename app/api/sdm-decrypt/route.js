///1. get the 'encNFCQuerysURL' from query
///2. with uid get the 'encryptedText' from the firebase
///3. decrypt the 'encryptedText' and get the 'aes128Key', 'ctr', 'uid'
///4. with the aes128 decrypt the 'encNFCQuerysURL'
///5. get here the 'ctrNFC'.
///6. check the the 'ctrNFC' higher then 'ctr' from firbase.
///7. if it higher, encrypt again all the params and save it with the 'ctrNFC' to the firebase and show {"authenticated": true},
///   if not not higher show   {"authenticated": false}


import { getFirestoreInstance } from '../../../lib/utils/serverFirebaseUtils';
import { PROTOTYPE_KEY_COLLECTION_FIREBASE, ENC_FIELD_FIREBASE, AES128_ENC_JSON_KEY, CTR_ENC_JSON_KEY, MINT_ENC_JSON_KEY } from '../../../lib/utils/keyNames';
import { decryptText, createEncryptedKeyData } from '../../../lib/utils/kmsUtils';
import { decryptNfcMessage, deriveTagKey } from '../../../lib/utils/nfcDecryptUtils';
import admin from 'firebase-admin';

const firestore = getFirestoreInstance();

// Next.js API Route handler.
export async function GET(request) {
  try {
    const { searchParams } = new URL(request.url);
    const picc_data = searchParams.get("picc_data");
    const enc = searchParams.get("enc");
    const cmac = searchParams.get("cmac");
    const uidParam = searchParams.get("uid");
    // Removed metaKey from query.
    const diversified = searchParams.get("diversified") === "true";

    if (!picc_data || !enc || !cmac || !uidParam) {
      return new Response(
        JSON.stringify({
          error:
            "Missing required query parameters: picc_data, enc, cmac, and uid"
        }),
        { status: 400, headers: { "Content-Type": "application/json" } }
      );
    }

    // Fetch the encrypted key data from Firestore.
    const keyDocRef = firestore.doc(`${PROTOTYPE_KEY_COLLECTION_FIREBASE}/${uidParam}`);
    const keyDocSnapshot = await keyDocRef.get();
    if (!keyDocSnapshot.exists) {
      return new Response(
        JSON.stringify({ authenticated: false, error: "uid not found" }),
        { status: 404, headers: { "Content-Type": "application/json" } }
      );
    }
    const keyDocData = keyDocSnapshot.data();
    console.log("keyDocData: ", keyDocData);
    const encryptedKeyData = keyDocData[ENC_FIELD_FIREBASE];



    console.log("encryptedKeyData: ", encryptedKeyData);
    if (!encryptedKeyData) {
      return new Response(
        JSON.stringify({ error: "Encrypted key data not found in document" }),
        { status: 400, headers: { "Content-Type": "application/json" } }
      );
    }

    // Decrypt the encrypted key data. This should return a JSON object.
    const decryptedKeyJson = await decryptText(encryptedKeyData);
    
    // Extract the AES128 field from the decrypted key data.
    const metaKeyStringFirebase = decryptedKeyJson[AES128_ENC_JSON_KEY];
    const mintStringFirebase = decryptedKeyJson[MINT_ENC_JSON_KEY];
    const ctrStringFirebase = decryptedKeyJson[CTR_ENC_JSON_KEY];
    const ctrNumberFirebse = Number(ctrStringFirebase);

    console.log("metaKeyString: ", metaKeyStringFirebase, "ctrNumberFirebse: ", ctrNumberFirebse);
    if (!metaKeyStringFirebase) {
      return new Response(
        JSON.stringify({ error: "AES128 key not found in decrypted key data" }),
        { status: 400, headers: { "Content-Type": "application/json" } }
      );
    }
    const sdmMetaReadKey = Buffer.from(metaKeyStringFirebase, "hex");

    // sdmFileReadKeyCallable: use diversified mode if requested.
    const sdmFileReadKeyCallable = diversified
    ? (uid) => deriveTagKey(sdmMetaReadKey, uid, 0)
    : () => sdmMetaReadKey;
        const paramMode = "SEPARATED";

    // Call decryptNfcMessage with parameters in the correct order.
    const result = decryptNfcMessage(
      picc_data,       // piccDataHex (string)
      enc,             // encHex (string)
      cmac,            // cmacHex (string)
      sdmMetaReadKey,  // sdmMetaReadKey (Buffer)
      sdmFileReadKeyCallable, // sdmFileReadKeyCallable (function)
      paramMode        // paramMode (string)
    );

    const ctrNFC = result.readCtr;
    console.log("ctrNFC: ", ctrNFC);
    const uidNFC = result.uid.toUpperCase();



    if (ctrNFC > ctrNumberFirebse) {
      // Update Firestore with the new counter value.
      const encrypted = await createEncryptedKeyData(uidNFC, String(ctrNFC), metaKeyStringFirebase, mintStringFirebase);

      const docRef = firestore.doc(`${PROTOTYPE_KEY_COLLECTION_FIREBASE}/${uidNFC}`);
      await docRef.set({
        [ENC_FIELD_FIREBASE]: encrypted,
        lastUpdateTimestamp: admin.firestore.FieldValue.serverTimestamp(),
      });

      return new Response(
        JSON.stringify({ authenticated: true, mint: `${mintStringFirebase}` }),
        { headers: { "Content-Type": "application/json" } }
      );
    } else {
      return new Response(
        JSON.stringify({ authenticated: false, error: "duplicate URL" }),
        { headers: { "Content-Type": "application/json" } }
      );
    }

  } catch (err) {
    return new Response(
      JSON.stringify({ error: err.message }),
      { status: 500, headers: { "Content-Type": "application/json" } }
    );
  }
}