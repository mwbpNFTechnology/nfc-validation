import { setCorsHeaders } from '../../../lib/utils/cors';
import { getFirestoreInstance } from '../../../lib/utils/serverFirebaseUtils';
import { decryptTextPlain } from '../../../lib/utils/kmsUtils';
import { keccak256 } from 'js-sha3';
import { Buffer } from 'buffer'; // may be needed for Node environments

const firestore = getFirestoreInstance();

function errorResponse(message, statusCode) {
  const body = JSON.stringify({ error: message });
  const response = new Response(body, {
    status: statusCode,
    headers: { 'Content-Type': 'application/json' },
  });
  return setCorsHeaders(response);
}

// Helper: Convert ArrayBuffer to Buffer
function arrayBufferToBuffer(ab) {
  return Buffer.from(new Uint8Array(ab));
}

// MerkleTree class that works with coupon (mint) strings.
class MerkleTree {
  constructor() {
    this.leaves = []; // Array of Buffers
    this.tree = [];   // Array of levels (each level is an array of Buffers)
  }

  addCoupon(coupon) {
    const couponBytes = Buffer.from(coupon, 'utf8');
    const leaf = this.keccak256(couponBytes);
    this.leaves.push(leaf);
  }

  getMerkleRoot() {
    this.buildTree();
    if (this.tree.length === 0) return null;
    // The root is the sole element in the last level.
    return '0x' + this.bytesToHex(this.tree[this.tree.length - 1][0]);
  }

  getMerkleProof(coupon) {
    const couponBytes = Buffer.from(coupon, 'utf8');
    const leaf = this.keccak256(couponBytes);
    // Find the index of the leaf that equals our hash.
    const index = this.leaves.findIndex(l => l.equals(leaf));
    if (index === -1) return null; // Coupon not found

    this.buildTree();
    const proof = [];
    let idx = index;
    // Traverse each level (except the root) to collect sibling nodes.
    for (let level = 0; level < this.tree.length - 1; level++) {
      const currentLevel = this.tree[level];
      const pairIndex = idx % 2 === 0 ? idx + 1 : idx - 1;
      if (pairIndex < currentLevel.length) {
        const sibling = currentLevel[pairIndex];
        proof.push('0x' + this.bytesToHex(sibling));
      }
      idx = Math.floor(idx / 2);
    }
    return proof;
  }

  buildTree() {
    this.tree = [];
    if (this.leaves.length === 0) return;

    let currentLevel = [...this.leaves];
    this.tree.push(currentLevel);

    while (currentLevel.length > 1) {
      const nextLevel = [];
      for (let i = 0; i < currentLevel.length; i += 2) {
        if (i + 1 < currentLevel.length) {
          let left = currentLevel[i];
          let right = currentLevel[i + 1];
          // Sort the two nodes lexicographically (as Buffers)
          if (Buffer.compare(left, right) > 0) {
            [left, right] = [right, left];
          }
          const combined = Buffer.concat([left, right]);
          const parent = this.keccak256(combined);
          nextLevel.push(parent);
        } else {
          // Duplicate the last element if there's no pair.
          const left = currentLevel[i];
          const combined = Buffer.concat([left, left]);
          const parent = this.keccak256(combined);
          nextLevel.push(parent);
        }
      }
      currentLevel = nextLevel;
      this.tree.push(currentLevel);
    }
  }

  keccak256(data) {
    // Use js-sha3 to compute the hash and convert the resulting ArrayBuffer to Buffer.
    const hashBuffer = arrayBufferToBuffer(keccak256.arrayBuffer(data));
    return hashBuffer;
  }

  bytesToHex(buffer) {
    return buffer.toString('hex');
  }
}

export async function OPTIONS() {
  const response = new Response(null, { status: 204 });
  return setCorsHeaders(response);
}

export async function GET(request) {
  try {
    // Retrieve the coupon from the query parameters.
    const { searchParams } = new URL(request.url);
    const couponQuery = searchParams.get('coupon');
    if (!couponQuery) {
      return errorResponse('Missing coupon query parameter', 400);
    }

    // Retrieve the document from Firebase at "mint_coupons/coupons"
    const docRef = firestore.doc('mint_coupons/coupons');
    const docSnapshot = await docRef.get();
    if (!docSnapshot.exists) {
      return errorResponse('Document not found', 404);
    }
    
    const data = docSnapshot.data();
    const encryptedText = data.encryptedText;
    if (!encryptedText) {
      return errorResponse('encryptedText not found in document', 404);
    }
    
    // Decrypt the encryptedText using AWS KMS.
    // Returns a plaintext string like:
    // "da0d5780a07cbb15262db111d8bf97_1,a722dbf730937648cab2f8977f37f8_2,..."
    const decryptedText = await decryptTextPlain(encryptedText);
    
    // Split the decrypted string by commas to get an array of mint values.
    const mintArray = decryptedText.split(',').map(m => m.trim());
    
    // Check if the provided coupon is in the decrypted mint list.
    if (!mintArray.includes(couponQuery)) {
      return errorResponse('Coupon not found in decrypted mints', 404);
    }
    
    // Build a Merkle tree from the mint values.
    const tree = new MerkleTree();
    mintArray.forEach(mint => tree.addCoupon(mint));
    
    const merkleRoot = tree.getMerkleRoot();
    // Get the Merkle proof for the provided coupon as an array.
    const proof = tree.getMerkleProof(couponQuery);
    
    const responseBody = {
      message: 'Decrypted and built Merkle tree successfully',
      data: {
        coupon: couponQuery,
        merkleRoot,
        merkleProof: proof, // returned as an array
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