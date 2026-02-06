async function submitEvidence() {
  try {
    const logInput = document.getElementById("log").value;
    if (!logInput) {
      alert("Please enter evidence JSON.");
      return;
    }
    const log = JSON.parse(logInput);

    const res = await fetch("http://localhost:5000/submit", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(log)
    });

    if (!res.ok) {
      throw new Error(`Server error: ${res.statusText}`);
    }

    const data = await res.json();
    document.getElementById("result").innerText = JSON.stringify(data, null, 2);
  } catch (error) {
    console.error("Error submitting evidence:", error);
    document.getElementById("result").innerText = "Error: " + error.message;
  }
}

async function verify() {
  try {
    const id = document.getElementById("eid").value;
    if (!id) {
      alert("Please enter an Evidence ID.");
      return;
    }

    const res = await fetch("http://localhost:5000/verify/" + id);

    if (!res.ok) {
      throw new Error(`Server error: ${res.statusText}`);
    }

    const data = await res.json();

    document.getElementById("verify").innerText =
      JSON.stringify(data, null, 2);
  } catch (error) {
    console.error("Error verifying evidence:", error);
    document.getElementById("verify").innerText = "Error: " + error.message;
  }
}
