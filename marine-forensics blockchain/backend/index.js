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


// 🔴 UPDATE THESE AFTER DEPLOYMENT 🔴
const CONTRACT_ADDRESS = "0x5FbDB2315678afecb367f032d93F642f64180aa3";
const PRIVATE_KEY = "0xdf57089febbacf7ba0bc227dafbffa9fc08a93fdc68e1e42411a14efcf23656e";
const RPC_URL = "http://127.0.0.1:8545";
// 🔴 END UPDATE 🔴

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
  const pythonFolder = path.join(__dirname, "../../python");
  const pythonFile = "maritime_cybersecurity_dashboard_FINAL.py";

  const command = `start cmd /k "cd ${pythonFolder} && streamlit run ${pythonFile}"`;

  console.log("Launching Streamlit using:", command);

  exec(command, (error) => {
    if (error) {
      console.error("❌ Error starting Streamlit:", error);
      return res.json({ error: "Failed to start Streamlit" });
    }
    console.log("✅ Streamlit launched successfully!");
  });

  res.json({ status: "Python Dashboard Starting..." });
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
// Email configuration
require("dotenv").config({ path: __dirname + '/.env' });
const nodemailer = require("nodemailer");

// Transporter will be created dynamically
const GlobalTransporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

/* ==========================
   SEND EMAIL ENDPOINT
   ========================== */
app.post("/api/send-email", async (req, res) => {
  const { to, subject, text, attachment, replyTo, user, pass } = req.body;

  console.log("📨 Attempting to send email to:", to);

  let transporterToUse = GlobalTransporter;

  if (user && pass) {
    console.log("🔑 Using provided credentials for:", user);
    transporterToUse = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: user,
        pass: pass
      }
    });
  }

  try {
    // Construct the email
    let mailOptions = {
      from: user ? `"Marine Admin" <${user}>` : '"Marine Forensics Admin" <admin@marine-forensics.com>',
      to: to,
      replyTo: replyTo, // Allow officer to reply to the sender
      subject: subject,
      text: text
    };

    if (attachment) {
      mailOptions.attachments = [
        {
          filename: 'evidence_record.json',
          content: JSON.stringify(attachment, null, 2)
        }
      ];
    }

    // Send Real Email
    try {
      let info = await transporterToUse.sendMail(mailOptions);
      console.log("✅ Email Sent: %s", info.messageId);
    } catch (mailError) {
      console.error("❌ SMTP Error:", mailError);
      return res.status(500).json({ success: false, message: "SMTP connection failed. Check App Password." });
    }

    res.json({ success: true, message: "Email sent successfully!" });

  } catch (err) {
    console.error("Email API Error:", err);
    res.status(500).json({ success: false, message: "Failed to send email." });
  }
});

app.listen(5000, () =>
  console.log("Backend running at http://localhost:5000")
);

