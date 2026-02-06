require("dotenv").config({ path: __dirname + '/.env' });
const nodemailer = require("nodemailer");

console.log("🔍 Checking Email Configuration...");
console.log("Email User:", process.env.EMAIL_USER ? "✅ Loaded" : "❌ Missing");
console.log("Email Pass:", process.env.EMAIL_PASS ? "✅ Loaded" : "❌ Missing");

if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
    console.error("❌ ERROR: Please check your .env file. EMAIL_USER or EMAIL_PASS is missing.");
    process.exit(1);
}

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

const mailOptions = {
    from: process.env.EMAIL_USER,
    to: process.env.EMAIL_USER, // Send to yourself
    subject: "Test Email from Marine Forensics",
    text: "If you receive this, your email configuration is working correctly! 🚀"
};

console.log("📨 Attempting to send test email to:", process.env.EMAIL_USER);

transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
        console.log("❌ FAILED to send email:");
        console.error(error);
    } else {
        console.log("✅ SUCCESSS! Email sent: " + info.response);
    }
});
