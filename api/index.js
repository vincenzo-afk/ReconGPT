import { createApiApp } from "./app.mjs";

/**
 * Vercel recognizes this JavaScript module as the function entrypoint. The
 * generated CommonJS bundle contains the complete local API import graph.
 */
export default createApiApp();
