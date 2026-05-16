const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const morgan = require("morgan");

const requestLogger = require("./middleware/requestLogger");
const authRoutes = require("./routes/authRoutes");

const app = express();

// MIDDLEWARES
app.use(express.json());
app.use(cors());
app.use(helmet());

app.use(requestLogger);

app.use(morgan("combined"));

// ROOT
app.get("/", (req, res) => {

  res.json({
    message: "Mobile API Misuse Detector Running"
  });

});

// AUTH ROUTES
app.use("/", authRoutes);

// PROFILE
app.get("/profile", (req, res) => {

  res.json({
    id: 1,
    username: "admin",
    email: "admin@test.com"
  });

});

// PRODUCTS
app.get("/products", (req, res) => {

  res.json([
    {
      id: 1,
      name: "iPhone 15",
      price: 1200
    },
    {
      id: 2,
      name: "Samsung S24",
      price: 1000
    }
  ]);

});

// SEARCH
app.get("/search", (req, res) => {

  const query = req.query.q;

  res.json({
    search: query,
    results: []
  });

});

// PAYMENTS
app.post("/payments", (req, res) => {

  res.json({
    success: true,
    transaction_id:
      Math.floor(Math.random() * 100000)
  });

});

// ADMIN ACCESS
app.get("/admin", (req, res) => {

  return res.status(403).json({
    error: "Forbidden"
  });

});

// REGISTER
app.post("/register", (req, res) => {

  const { username } = req.body;

  res.json({
    success: true,
    username
  });

});

// USERS API
app.get("/users/:id", (req, res) => {

  res.json({
    id: req.params.id,
    username: `user_${req.params.id}`
  });

});

const PORT = 5000;

app.listen(PORT, () => {

  console.log(
    `Server running on port ${PORT}`
  );

});
