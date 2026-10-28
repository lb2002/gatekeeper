// Fetches the weather for a city. The demo task for the coding agent: make the request retry on failure.
const axios = require("axios");

async function weather(city) {
  const res = await axios.get(`https://wttr.in/${encodeURIComponent(city)}?format=3`);
  return res.data;
}

weather(process.argv[2] || "Zurich").then(console.log).catch((e) => console.error("failed:", e.message));
