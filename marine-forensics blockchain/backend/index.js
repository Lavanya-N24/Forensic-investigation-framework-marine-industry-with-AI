const express = require("express");
const bodyParser = require("body-parser");
const session = require("express-session");
const crypto = require("crypto");
const cors = require("cors");
const fs = require("fs-extra");
const path = require("path");
const { ethers } = require("ethers");
const { exec } = require("child_process");
function cleanId(id) {
  return id.startsWith("0x") ? id.slice(2) : id;
}
const app = express();
app.use(cors({ origin: true, credentials: true }));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Session – required for login (only logged-in users access the site)
app.use(session({
  secret: process.env.SESSION_SECRET || "marine-forensics-secret-change-in-production",
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, maxAge: 24 * 60 * 60 * 1000 }
}));

// Serve all frontend files (HTML, CSS, JS)
app.use(express.static(path.join(__dirname, "../frontend")));
const evidenceDir = path.join(__dirname, "evidence");
fs.ensureDirSync(evidenceDir);


// ─── NETWORK CONFIGURATION ────────────────────────────────────────────────────
const INFURA_API_KEY = "592071cb68f14c67bc929dfc2e76af78";

// Set NETWORK=sepolia in your environment to use the Sepolia testnet
// Otherwise defaults to local Hardhat node
const NETWORK = process.env.NETWORK || "sepolia";

const RPC_URLS = {
  local:   "http://127.0.0.1:8545",
  sepolia: `https://sepolia.infura.io/v3/${INFURA_API_KEY}`,
  mainnet: `https://mainnet.infura.io/v3/${INFURA_API_KEY}`
};

const CONTRACT_ADDRESS = process.env.CONTRACT_ADDRESS || "0x7764CD0A2AFCbf8409b05EB28e7573bF13a9f2E0";
const PRIVATE_KEY      = process.env.PRIVATE_KEY      || "0x2709827e6922ab3c9cd68617ae6feb1cae4000b47a7a33cbd0bc50d212aa2685";
const RPC_URL          = process.env.RPC_URL          || RPC_URLS[NETWORK] || RPC_URLS.local;

console.log(`🌐 Connected to network: ${NETWORK.toUpperCase()} → ${RPC_URL}`);
// ─────────────────────────────────────────────────────────────────────────────

const ABI = [
  "function submitEvidence(bytes32 evidenceId, bytes32 hashValue) public",
  "function getEvidence(bytes32 evidenceId) public view returns(bytes32, uint256, address)"
];

const provider = new ethers.providers.JsonRpcProvider(RPC_URL);
const wallet = new ethers.Wallet(PRIVATE_KEY, provider);
const contract = new ethers.Contract(CONTRACT_ADDRESS, ABI, wallet);

function sha256(data) {
  return crypto.createHash("sha256").update(data).digest("hex");
}

// ---------- LOGIN: only logged-in users can access the site ----------
// Allowed users (username -> password). Change these for your project.
const USERS = { admin: "lav123", clerk: "clerk123", officer: "officer123" };

app.get("/api/check-session", (req, res) => {
  if (req.session && req.session.user) {
    return res.json({ loggedIn: true, username: req.session.user });
  }
  res.json({ loggedIn: false });
});

app.post("/api/login", (req, res) => {
  const username = (req.body.username || "").trim();
  const password = (req.body.password || "");
  if (!username || !password) {
    return res.status(400).json({ success: false, message: "Username and password required." });
  }
  if (USERS[username] === password) {
    req.session.user = username;
    return res.json({ success: true, username });
  }
  res.status(401).json({ success: false, message: "Invalid username or password." });
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => { });
  res.json({ success: true });
});

// Root: redirect to login if not logged in, else to home
app.get("/", (req, res) => {
  if (req.session && req.session.user) {
    return res.redirect("/home.html");
  }
  res.redirect("/login.html");
});

/* ======================================================
     🚀 NEW FUNCTION — START PYTHON STREAMLIT DASHBOARD
   ====================================================== */
app.get("/start-python", (req, res) => {
  // On Render, we cannot use `exec(start cmd)` because it's Linux
  // and Streamlit needs to be hosted as a separate Web Service.
  // Instead, return the Streamlit URL via an environment variable.
  const streamlitUrl = process.env.STREAMLIT_URL || "http://localhost:8501";
  
  if (!process.env.STREAMLIT_URL) {
    // Fallback for local testing (trying to open it silently, or just telling frontend to open localhost:8501)
    console.log("No STREAMLIT_URL provided. Assuming local development.");
  }

  res.json({ status: "Python Dashboard URL", url: streamlitUrl });
});


/* ==========================
   SUBMIT EVIDENCE (same)
   ========================== */
app.post("/submit", async (req, res) => {
  try {
    const log = req.body;
    const str = JSON.stringify(log);

    const hash = sha256(str);
    const hashBytes = "0x" + hash;

    const eId = crypto.randomBytes(32).toString("hex");
    const eIdBytes = "0x" + eId;

    fs.writeJsonSync(path.join(evidenceDir, `${eId}.json`), log, { spaces: 2 });

    const tx = await contract.submitEvidence(eIdBytes, hashBytes);
    await tx.wait();

    res.send({
      message: "Evidence stored",
      evidenceId: eIdBytes,
      hash,
      evidence: log   // 👈 IMPORTANT
    });

  } catch (err) {
    res.send({ error: err.message });
  }
});


/* ==========================
   VERIFY EVIDENCE (same)
   ========================== */
app.get("/verify/:id", async (req, res) => {
  try {
    const idHex = req.params.id.replace("0x", "");
    const file = path.join(evidenceDir, `${idHex}.json`);

    if (!fs.existsSync(file)) return res.send({ error: "Not found locally" });

    const localData = fs.readJsonSync(file);
    const localHash = sha256(JSON.stringify(localData));

    const [chainHash, timestamp, submitter] = await contract.getEvidence(
      "0x" + idHex
    );

    const match = chainHash.replace("0x", "") === localHash;

    res.send({
      evidenceId: req.params.id,
      localHash,
      chainHash,
      timestamp,
      submitter,
      valid: match
    });
  } catch (err) {
    res.send({ error: err.message });
  }
});

/* ==========================
   GET ALL RECORDS (same)
   ========================== */
app.get("/records", async (req, res) => {
  try {
    const files = fs.readdirSync(evidenceDir);
    const records = [];

    for (const file of files) {
      const id = file.replace(".json", "");
      const content = fs.readJsonSync(path.join(evidenceDir, file));
      const localHash = sha256(JSON.stringify(content));

      try {
        const [chainHash] = await contract.getEvidence("0x" + id);
        const isValid = chainHash.replace("0x", "") === localHash;

        records.push({
          evidenceId: "0x" + id,
          data: content,
          valid: isValid
        });
      } catch (e) {
        console.error(`Error verifying ${id}:`, e);
        records.push({
          evidenceId: "0x" + id,
          data: content,
          valid: false // Treat as invalid if blockchain check fails
        });
      }
    }

    res.send(records);
  } catch (err) {
    res.send({ error: err.message });
  }
});

/* ==========================
   DOWNLOAD EVIDENCE (same)
   ========================== */
app.get("/evidence/:id", (req, res) => {
  try {
    const idHex = req.params.id;
    const filePath = path.join(evidenceDir, `${idHex}.json`);

    if (!fs.existsSync(filePath)) {
      return res.status(404).send({ error: "File not found" });
    }

    const jsonData = fs.readJsonSync(filePath);
    res.send(jsonData);

  } catch (err) {
    res.send({ error: err.message });
  }
});
// Serve home page from this project's frontend
app.get("/home", (req, res) => {
  res.sendFile(path.join(__dirname, "../frontend/home.html"));
});



/* ==========================
   START BACKEND
   ========================== */
const PORT = process.env.PORT || 5001;
app.listen(PORT, () =>
  console.log(`Backend running at http://localhost:${PORT}`)
);

