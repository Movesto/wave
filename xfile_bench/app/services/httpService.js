// SERVICE layer: the outbound-request sink. Tainted URL arrives as a parameter.
const axios = require('axios');

// F7 sink (VULN): server fetches an attacker-chosen URL, no allow-list.
function fetchUrl(url) {
  return axios.get(url);                          // SINK -- cross-file SSRF
}

module.exports = { fetchUrl };
