const redis = require("redis");

const redisClient = redis.createClient({
    url: "redis://localhost:6379"
});

redisClient.connect();

redisClient.on("error", (err) => {
    console.log("Redis Error", err);
});

module.exports = redisClient;
