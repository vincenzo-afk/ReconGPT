import bundledApi from "./app.cjs";

/**
 * Vercel recognizes this JavaScript module as the function entrypoint. The
 * generated CommonJS bundle contains the complete local API import graph.
 */
export default bundledApi.createApiApp();
