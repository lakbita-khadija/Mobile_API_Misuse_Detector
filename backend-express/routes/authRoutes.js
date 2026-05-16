const express = require("express");

const router = express.Router();

const elasticClient = require("../services/elasticsearch");
const redisClient = require("../services/redis");
const logger = require("../logger");

router.post("/login", async (req, res) => {

  const fakeUser = {
    username: "admin",
    password: "essbackendi"
  };

  const ip = req.ip;

  const { username, password } = req.body;

  let failedAttempts = await redisClient.get(`failed:${ip}`);

  failedAttempts = failedAttempts
    ? parseInt(failedAttempts)
    : 0;

  // FAILED LOGIN
  if (
    username !== fakeUser.username ||
    password !== fakeUser.password
  ) {

    failedAttempts++;

    await redisClient.set(
      `failed:${ip}`,
      failedAttempts
    );

    await redisClient.expire(`failed:${ip}`, 60);

    const failedLog = {
      timestamp: new Date(),
      ip,
      endpoint: "/login",
      method: req.method,
      status: 401,
      failed_attempts: failedAttempts,
      response_time_ms: Math.floor(Math.random() * 400),
      request_size: Math.floor(Math.random() * 5000),
      device_type: "mobile",
      user_agent: req.headers["user-agent"]
    };

    await elasticClient.index({
      index: "mobile-security-logs",
      document: failedLog
    });

    logger.info(failedLog);

    return res.status(401).json({
      error: "Invalid credentials",
      failed_attempts: failedAttempts
    });

  }

  // SUCCESS LOGIN
  const successLog = {
    timestamp: new Date(),
    ip,
    endpoint: "/login",
    method: req.method,
    status: 200,
    response_time_ms: Math.floor(Math.random() * 200),
    request_size: Math.floor(Math.random() * 3000),
    device_type: "mobile",
    user_agent: req.headers["user-agent"]
  };

  await elasticClient.index({
    index: "mobile-security-logs",
    document: successLog
  });

  logger.info(successLog);

  res.json({
    success: true,
    message: "Login successful"
  });

});

module.exports = router;
