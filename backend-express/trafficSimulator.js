const axios = require("axios");

const BASE_URL = "http://localhost:5000";

// USER AGENTS MOBILES NORMAUX
const mobileAgents = [
  "Android-App/4.2",
  "iPhone-iOS16",
  "SamsungBrowser/19",
  "HuaweiMobile/3.1",
  "XiaomiApp/5.0"
];

// USER AGENTS SUSPECTS
const suspiciousAgents = [
  "curl/7.68",
  "python-requests/2.25",
  "wget",
  "scrapy"
];

// MAUVAIS PASSWORDS
const wrongPasswords = [
  "123456",
  "password",
  "admin123",
  "qwerty",
  "test123"
];

// RANDOM HELPER
function randomItem(array) {

  return array[
    Math.floor(Math.random() * array.length)
  ];

}

// HEADERS
function mobileHeaders() {

  const allAgents = [
    ...mobileAgents,
    ...suspiciousAgents
  ];

  return {
    headers: {
      "User-Agent": randomItem(allAgents)
    }
  };

}

// LOGIN NORMAL
async function normalLogin() {

  try {

    await axios.post(
      `${BASE_URL}/login`,
      {
        username: "admin",
        password: "essbackendi"
      },
      mobileHeaders()
    );

    console.log("Normal login");

  } catch (err) {}

}

// FAILED LOGIN
async function failedLogin() {

  try {

    await axios.post(
      `${BASE_URL}/login`,
      {
        username: "admin",
        password: randomItem(wrongPasswords)
      },
      mobileHeaders()
    );

  } catch (err) {

    console.log("Failed login");

  }

}

// PROFILE ACCESS
async function profileAccess() {

  try {

    await axios.get(
      `${BASE_URL}/profile`,
      mobileHeaders()
    );

    console.log("Profile access");

  } catch (err) {}

}

// PRODUCTS BROWSING
async function browseProducts() {

  try {

    await axios.get(
      `${BASE_URL}/products`,
      mobileHeaders()
    );

    console.log("Browsing products");

  } catch (err) {}

}

// SEARCH TRAFFIC
async function searchTraffic() {

  try {

    const keywords = [
      "iphone",
      "samsung",
      "laptop",
      "camera",
      "headphones"
    ];

    await axios.get(
      `${BASE_URL}/search?q=${randomItem(keywords)}`,
      mobileHeaders()
    );

    console.log("Search traffic");

  } catch (err) {}

}

// PAYMENT TRAFFIC
async function paymentTraffic() {

  try {

    await axios.post(
      `${BASE_URL}/payments`,
      {
        amount: Math.floor(Math.random() * 500)
      },
      mobileHeaders()
    );

    console.log("Payment traffic");

  } catch (err) {}

}

// REGISTER TRAFFIC
async function registerTraffic() {

  try {

    const username =
      "user" + Math.floor(Math.random() * 10000);

    await axios.post(
      `${BASE_URL}/register`,
      {
        username
      },
      mobileHeaders()
    );

    console.log("Register traffic");

  } catch (err) {}

}

// ADMIN ACCESS ABUSE
async function adminAbuse() {

  try {

    await axios.get(
      `${BASE_URL}/admin`,
      mobileHeaders()
    );

  } catch (err) {

    console.log("Forbidden admin access");

  }

}

// BRUTEFORCE LOGIN
async function bruteForceTraffic() {

  for (let i = 0; i < 30; i++) {

    await failedLogin();

  }

  console.log("Bruteforce simulated");

}

// SEARCH SPIKE
async function searchSpike() {

  const requests = [];

  for (let i = 0; i < 100; i++) {

    requests.push(
      axios.get(
        `${BASE_URL}/search?q=iphone`,
        mobileHeaders()
      ).catch(() => {})
    );

  }

  await Promise.all(requests);

  console.log("Search spike generated");

}

// BURST TRAFFIC
async function burstTraffic() {

  const requests = [];

  for (let i = 0; i < 200; i++) {

    requests.push(

      axios.get(
        `${BASE_URL}/products`,
        mobileHeaders()
      ).catch(() => {})

    );

  }

  await Promise.all(requests);

  console.log("Burst traffic generated");

}

// ENDPOINT HAMMERING
async function endpointHammering() {

  for (let i = 0; i < 150; i++) {

    try {

      await axios.get(
        `${BASE_URL}/search?q=iphone`,
        mobileHeaders()
      );

    } catch (err) {}

  }

  console.log("Endpoint hammering generated");

}

// ENUMERATION TRAFFIC
async function enumerationTraffic() {

  for (let i = 1; i < 50; i++) {

    try {

      await axios.get(
        `${BASE_URL}/users/${i}`,
        mobileHeaders()
      );

    } catch (err) {}

  }

  console.log("Enumeration traffic generated");

}

// SUSPICIOUS PAYLOADS
async function suspiciousQueries() {

  const payloads = [
    "' OR 1=1 --",
    "<script>alert(1)</script>",
    "UNION SELECT password",
    "../../../etc/passwd"
  ];

  for (const payload of payloads) {

    try {

      await axios.get(
        `${BASE_URL}/search?q=${encodeURIComponent(payload)}`,
        mobileHeaders()
      );

    } catch (err) {}

  }

  console.log("Suspicious payloads generated");

}

// SCENARIO COMPLET
async function generateTrafficScenario() {

  console.log(
    "Generating realistic mobile traffic..."
  );

  // TRAFIC NORMAL
  for (let i = 0; i < 20; i++) {

    await normalLogin();

    await profileAccess();

    await browseProducts();

    await searchTraffic();

  }

  // REGISTER
  for (let i = 0; i < 10; i++) {

    await registerTraffic();

  }

  // PAYMENTS
  for (let i = 0; i < 5; i++) {

    await paymentTraffic();

  }

  // FAILED AUTH
  for (let i = 0; i < 20; i++) {

    await failedLogin();

  }

  // ADMIN ABUSE
  for (let i = 0; i < 10; i++) {

    await adminAbuse();

  }

  // BRUTEFORCE
  await bruteForceTraffic();

  // SPIKES
  await searchSpike();

  // BURSTS
  await burstTraffic();

  // ENDPOINTS MARTELÉS
  await endpointHammering();

  // ENUMERATION
  await enumerationTraffic();

  // PAYLOADS SUSPECTS
  await suspiciousQueries();

  console.log(
    "Traffic generation completed"
  );

}

// GROS DATASET
async function generateLargeDataset() {

  for (let i = 0; i < 200; i++) {

    console.log(`Scenario batch ${i}`);

    await generateTrafficScenario();

  }

}

generateLargeDataset();
