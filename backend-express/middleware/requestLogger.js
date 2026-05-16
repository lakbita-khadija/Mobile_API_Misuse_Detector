const logger = require("../logger");

const countries = [
  "FR",
  "US",
  "DE",
  "UK",
  "MA",
  "CA",
  "JP"
];

const devices = [
  "Samsung S24",
  "iPhone 15",
  "Huawei P50",
  "Xiaomi Redmi",
  "Google Pixel"
];

// générateur IP réaliste
function generateFakeIP() {

  return `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;

}

// helper random
function randomItem(array) {

  return array[
    Math.floor(Math.random() * array.length)
  ];

}

function requestLogger(req, res, next) {

  const start = Date.now();

  // session simulée
  const sessionId =
    "sess_" + Math.floor(Math.random() * 100000);

  // request ID
  const requestId =
    "req_" + Math.floor(Math.random() * 1000000);

  // fake device id
  const deviceId =
    "device_" + Math.floor(Math.random() * 100000);

  res.on("finish", () => {

    const responseTime = Date.now() - start;

    const logData = {

      timestamp: new Date(),

      request_id: requestId,

      session_id: sessionId,

      device_id: deviceId,

      ip: generateFakeIP(),

      country: randomItem(countries),

      device_model: randomItem(devices),

      method: req.method,

      endpoint: req.originalUrl,

      status: res.statusCode,

      response_time_ms: responseTime,

      request_size:
        parseInt(req.headers["content-length"]) || 0,

      device_type: "mobile",

      user_agent: req.headers["user-agent"]

    };

    logger.info(logData);

  });

  next();

}

module.exports = requestLogger;
