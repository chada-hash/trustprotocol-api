require("dotenv").config();

const express = require("express");
const cors = require("cors");

const app = express();

app.use(cors());
app.use(express.json());

app.get("/", (req, res) => {
  res.json({
    status: "TrustProtocol API Online"
  });
});

app.post("/attest", (req, res) => {

  const payload = {
    agent: req.body.agent,
    action: req.body.action,
    timestamp: new Date().toISOString()
  };

  res.json({
    success: true,
    payload
  });

});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log("Server running");
});
