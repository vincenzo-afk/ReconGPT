/**
 * Thin Vercel Function shim. `pnpm build:vercel` generates the adjacent,
 * bundled CommonJS implementation before Vercel packages this function.
 */
module.exports = require("./app.cjs").createApiApp();
