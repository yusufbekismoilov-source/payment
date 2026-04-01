require("dotenv").config();
const express = require("express");
const crypto = require("crypto");
const { v4: uuidv4 } = require("uuid");

const app = express();
const PORT = process.env.PORT || 3000;

// Capture RAW body for signing
app.use(express.json({
  verify: (req, res, buf) => {
    req.rawBody = buf.toString();
  }
}));

// Bind to all interfaces, not just localhost


app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

// Example bank database
const validBanks = [
  { account: "1234567890", bankKey: "BANK001" },
  { account: "9876543210", bankKey: "BANK002" }
];


// API KEY middleware
function checkApiKey(req, res, next) {

  const apiKey = req.headers["x-api-key"];

  if (!apiKey || apiKey !== process.env.API_KEY) {
    return res.status(401).json({
      message: "Unauthorized: Invalid API key"
    });
  }

  next();
}


// SIGNATURE middleware
function checkSignature(req, res, next) {

  const clientSignature = req.headers["x-signature"];

  if (!clientSignature) {
    return res.status(400).json({
      message: "Missing signature"
    });
  }

  const serverSignature = crypto
    .createHmac("sha256", process.env.SIGNING_SECRET)
    .update(req.rawBody)
    .digest("hex");

  if (clientSignature !== serverSignature) {
    return res.status(401).json({
      message: "Invalid signature"
    });
  }

  next();
}


// PAYMENT API
app.post("/api/payment", checkApiKey, checkSignature, (req, res) => {

  const { bankAccount, bankKey, amount, currency } = req.body;

  if (!bankAccount || !bankKey || !amount || !currency) {
    return res.status(400).json({
      message: "Missing required fields"
    });
  }


  const bank = validBanks.find(
    b => b.account === bankAccount && b.bankKey === bankKey
  );

  if (!bank) {
    return res.status(400).json({
      message: "Invalid bank account or bank key"
    });
  }

  const paymentId = uuidv4();

  res.status(201).json({
    message: "Payment processed successfully",
    paymentId: paymentId,
    amount: amount,
    currency: currency
  });

});


// Test route
app.get("/", (req, res) => {
  res.send("Payment API running");
});


app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
