
// Load records on startup
async function loadRecordsDropdown() {
    try {
        const res = await fetch("/records");
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

            // Store full data in a map or simply fetch on send? 
            // We'll trust the ID for now or store data in a dataset logic
            // But 'option' doesn't hold data well.
            // Let's keep it simple: we just send the ID and summary.
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

    // Simulation of sending message
    console.log("Sending alert:", { type, email, msg, attachedRecord: recordJson });

    alert(`✅ Alert Sent to Officer!\n\nType: ${type}\nNote: ${msg}\nAttached Record:\n${recordDetails.substring(0, 200)}...`);

    // Clear form
    document.getElementById("adminForm").reset();
});

// Init
loadRecordsDropdown();
