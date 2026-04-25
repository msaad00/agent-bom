// Placeholder MCP-like server for first-run scanning. It does not open a
// network listener; the file exists so source and package scanners have a
// concrete npm service to inspect.

const axios = require("axios");

async function fetchPageTitle(url) {
  const response = await axios.get(url, { timeout: 2000 });
  const match = String(response.data).match(/<title>(.*?)<\/title>/i);
  return match ? match[1] : "untitled";
}

module.exports = { fetchPageTitle };
