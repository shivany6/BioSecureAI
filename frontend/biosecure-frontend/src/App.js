import React, { useState } from "react";

function App() {
  const [file, setFile] = useState(null);
  const [message, setMessage] = useState("");
  const [loading, setLoading] = useState(false);

  const handleUpload = async () => {
    if (!file) {
      setMessage("Please select a file first.");
      return;
    }

    setLoading(true);
    setMessage("");

    const formData = new FormData();
    formData.append("file", file);

    try {
      const response = await fetch("http://127.0.0.1:5000/analyze", {
        method: "POST",
        body: formData,
      });

      const data = await response.json();
      setMessage(JSON.stringify(data, null, 2));
    } catch (error) {
      console.error(error);
      setMessage("Error connecting to backend.");
    }

    setLoading(false);
  };

  return (
    <div style={{ padding: "20px", fontFamily: "Arial" }}>
      <h1 style={{ marginBottom: "20px" }}>BioSecureAI</h1>

      <input
        type="file"
        onChange={(e) => setFile(e.target.files[0])}
        style={{ marginBottom: "10px" }}
      />

      <br />

      <button
        onClick={handleUpload}
        style={{
          padding: "10px 20px",
          background: "#007bff",
          color: "white",
          border: "none",
          borderRadius: "5px",
          cursor: "pointer",
          marginTop: "10px",
        }}
      >
        Upload & Analyze
      </button>

      {loading && (
        <p style={{ marginTop: "20px", fontWeight: "bold" }}>
          Analyzing... Please wait
        </p>
      )}

      <pre
        style={{
          marginTop: "20px",
          padding: "15px",
          background: "#f0f0f0",
          borderRadius: "5px",
          maxHeight: "300px",
          overflow: "auto",
        }}
      >
        {message}
      </pre>
    </div>
  );
}

export default App;


