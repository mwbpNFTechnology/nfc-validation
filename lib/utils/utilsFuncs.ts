/**
 * Extracts the mint number from a mint string
 * @param mintString - The mint string in format "hash_number"
 * @returns The mint number as a string, or null if invalid format
 */
 export function extractMintNumber(mintString: string): number | null {
    // Check if the string is valid
    if (!mintString || typeof mintString !== 'string') {
      return null;
    }
  
    // Split the string by underscore and get the last part
    const parts = mintString.split('_');
    if (parts.length !== 2) {
      return null;
    }
  
    // Get the number part and ensure it's a valid number
    const mintNumber = parts[1];
    if (!/^\d+$/.test(mintNumber)) {
      return null;
    }
  
    return Number(mintNumber);
  }