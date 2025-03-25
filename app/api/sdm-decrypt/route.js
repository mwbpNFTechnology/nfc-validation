import { getFirestoreInstance } from '../../../lib/utils/serverFirebaseUtils';
import { extractMintNumber } from '../../../lib/utils/utilsFuncs';
import { 
  PROTOTYPE_KEY_COLLECTION_FIREBASE, 
  ENC_FIELD_FIREBASE, 
  AES128_ENC_JSON_KEY, 
  CTR_ENC_JSON_KEY, 
  MINT_ENC_JSON_KEY 
} from '../../../lib/utils/keyNames';
import { decryptText, createEncryptedKeyData } from '../../../lib/utils/kmsUtils';
import { decryptNfcMessage, deriveTagKey } from '../../../lib/utils/nfcDecryptUtils';
import { setCorsHeaders } from '../../../lib/utils/cors';
import admin from 'firebase-admin';
import { ethers } from 'ethers';
import { getContractAddress, CONTRACT_ABI, SELECTED_NETWORK } from '../../../config/contractConfig';

const firestore = getFirestoreInstance();

export async function GET(request) {
  // Handle OPTIONS preflight request
  if (request.method === "OPTIONS") {
    return setCorsHeaders(new Response(null, { status: 204 }));
  }

  try {
    const { searchParams } = new URL(request.url);
    const picc_data = searchParams.get("picc_data");
    const enc = searchParams.get("enc");
    const cmac = searchParams.get("cmac");
    const uidParam = searchParams.get("uid");
    const diversified = searchParams.get("diversified") === "true";

    if (!picc_data || !enc || !cmac || !uidParam) {
      return setCorsHeaders(new Response(
        JSON.stringify({
          error: "Missing required query parameters: picc_data, enc, cmac, and uid"
        }),
        { status: 400, headers: { "Content-Type": "application/json" } }
      ));
    }

    // Fetch the encrypted key data from Firestore.
    const keyDocRef = firestore.doc(`${PROTOTYPE_KEY_COLLECTION_FIREBASE}/${uidParam}`);
    const keyDocSnapshot = await keyDocRef.get();
    if (!keyDocSnapshot.exists) {
      return setCorsHeaders(new Response(
        JSON.stringify({ authenticated: false, error: "uid not found" }),
        { status: 404, headers: { "Content-Type": "application/json" } }
      ));
    }
    const keyDocData = keyDocSnapshot.data();
    const encryptedKeyData = keyDocData[ENC_FIELD_FIREBASE];

    if (!encryptedKeyData) {
      return setCorsHeaders(new Response(
        JSON.stringify({ error: "Encrypted key data not found in document" }),
        { status: 400, headers: { "Content-Type": "application/json" } }
      ));
    }

    // Decrypt the encrypted key data. This should return a JSON object.
    const decryptedKeyJson = await decryptText(encryptedKeyData);
    const metaKeyStringFirebase = decryptedKeyJson[AES128_ENC_JSON_KEY];
    const mintStringFirebase = decryptedKeyJson[MINT_ENC_JSON_KEY];
    const ctrStringFirebase = decryptedKeyJson[CTR_ENC_JSON_KEY];
    const ctrNumberFirebase = Number(ctrStringFirebase);

    const nftID = extractMintNumber(mintStringFirebase);
    console.log("nftID: ", nftID);

    if (!metaKeyStringFirebase) {
      return setCorsHeaders(new Response(
        JSON.stringify({ error: "AES128 key not found in decrypted key data" }),
        { status: 400, headers: { "Content-Type": "application/json" } }
      ));
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
    const uidNFC = result.uid.toUpperCase();

    // Set up an ethers provider for the selected network.
    const provider = ethers.getDefaultProvider(SELECTED_NETWORK);
    const contractAddress = getContractAddress();
    const contract = new ethers.Contract(contractAddress, CONTRACT_ABI, provider);

    // Check if the NFT is minted by calling ownerOf.
    let ownerAddress = "";
    try {
      ownerAddress = await contract.ownerOf(nftID);
      // If ownerAddress is not the zero address, token is minted.
    } catch (ownerError) {
      // If the call fails (likely token not minted), set ownerAddress to default.
      console.log("ownerOf call failed, assuming token not minted:", ownerError.message);
      ownerAddress = "0x000000000000000000000000000000000000";
    }

    // Update Firestore only if the NFC counter is higher.
    if (ctrNFC > ctrNumberFirebase) {
      const encrypted = await createEncryptedKeyData(uidNFC, String(ctrNFC), metaKeyStringFirebase, mintStringFirebase);
      
      const docRef = firestore.doc(`${PROTOTYPE_KEY_COLLECTION_FIREBASE}/${uidNFC}`);
      await docRef.set({
        [ENC_FIELD_FIREBASE]: encrypted,
        lastUpdateTimestamp: admin.firestore.FieldValue.serverTimestamp(),
      });
    }
    
    // Return the JSON response with authenticated, mint, and nftOwner fields.
    return setCorsHeaders(new Response(
      JSON.stringify({ 
        authenticated: true, 
        mint: mintStringFirebase, 
        nftOwner: ownerAddress 
      }),
      { headers: { "Content-Type": "application/json" } }
    ));
  } catch (err) {
    return setCorsHeaders(new Response(
      JSON.stringify({ error: err.message }),
      { status: 500, headers: { "Content-Type": "application/json" } }
    ));
  }
}