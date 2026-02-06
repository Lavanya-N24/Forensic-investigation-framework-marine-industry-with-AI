
// Load records on startup
async function loadRecordsDropdown() {
    try {
        const res = await fetch("http://localhost:5000/records");
        const data = await res.json();

        const select = document.getElementById("recordSelect");

        data.forEach(record => {
            const option = document.createElement("option");
            option.value = record.evidenceId;

            // Check validity
            const statusIcon = record.valid ? "✅ [VALID]" : "❌ [TAMPERED]";

            // Display Ship ID + Event as label if available, else ID
            const info = record.data && record.data.ship ?
                `Ship ${record.data.ship} - ${record.data.event}` :
                record.evidenceId.substring(0, 16) + "...";

            option.textContent = `${statusIcon} ${info}`;
            select.appendChild(option); // Fix: Append the option to the dropdown
        });

        // Store data globally to access on send
        window.evidenceData = data;

    } catch (e) {
        console.error("Error loading records:", e);
    }
}

document.getElementById("adminForm").addEventListener("submit", function (e) {
    e.preventDefault();

    const type = document.getElementById("incidentType").value;
    const sender = document.getElementById("senderEmail").value;
    const email = document.getElementById("officerEmail").value;
    const msg = document.getElementById("message").value;
    const selectedId = document.getElementById("recordSelect").value;

    // Find the record details
    let recordDetails = "No record attached";
    let recordJson = {};

    if (selectedId && window.evidenceData) {
        const rec = window.evidenceData.find(r => r.evidenceId === selectedId);
        if (rec) {
            recordDetails = `ID: ${rec.evidenceId}\nData: ${JSON.stringify(rec.data)}`;
            recordJson = rec.data;
        }
    }

    if (!msg) return;

    // Send to Backend
    fetch("http://localhost:5000/api/send-email", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            to: email,
            subject: `🚨 Marine Alert: ${type}`,
            text: `From: ${sender}\n\nOfficer,\n\nAn incident has been reported:\n\nType: ${type}\nMessage: ${msg}\n\nPlease analyze the attached evidence if available.\n\nRegards,\nAdmin Console`,
            attachment: recordJson,
            replyTo: sender,
            user: sender,
            pass: document.getElementById("appPassword").value
        })
    })
        .then(res => res.json())
        .then(response => {
            if (response.success) {
                alert(`✅ Email Sent to Officer!\n\nType: ${type}\nNote: ${msg}`);
                document.getElementById("adminForm").reset();
            } else {
                alert("❌ Failed to send email. Check backend logs.");
            }
        })
        .catch(err => {
            console.error(err);
            alert("❌ Error sending email.");
        });
});

// Init
loadRecordsDropdown();
