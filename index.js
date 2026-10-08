const express = require("express");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.static(path.join(__dirname, "public")));

app.get("/api/stats", (req, res) => {
  res.json({
    users: 1234,
    orders: 5678,
    revenue: 12345
  });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server on ${PORT}`);
});
