// app/lib/utils/cors.js

/**
 * Helper function to set Cross-Origin Resource Sharing (CORS) headers on a Response object.
 * These headers allow your API to be accessed from any origin and permit specific HTTP methods.
 *
 * @param {Response} response - The response object to which headers will be added.
 * @returns {Response} - The response with CORS headers set.
 */
 export function setCorsHeaders(response) {
    response.headers.set('Access-Control-Allow-Origin', '*');
    response.headers.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    response.headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    return response;
  }