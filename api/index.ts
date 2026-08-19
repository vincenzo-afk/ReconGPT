import { createApiApp } from "../server/_core/app";

/**
 * Vercel Function entry point. Vercel supplies the Node request/response
 * lifecycle; this module must only export the Express app and never listen on
 * a port.
 */
export default createApiApp();
