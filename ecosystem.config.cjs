module.exports = {
  apps: [{
    name: "domains",
    script: "dist/server.js",
    cwd: "/home/dev/domains",
    env: {
      PORT: "3004",
      NJALLA_API_KEY: "b6bbc702ef3f18ee67c4923fbc3b2e48851e5cbc",
      NJALLA_API_URL: "https://njal.la/api/1/",
      JWT_SECRET: "purpleflea-domains-secret-change-in-production",
      MARKUP_PERCENT: "20",
      WALLET_SERVICE_URL: "http://localhost:3002",
      WALLET_SERVICE_KEY: "svc_pf_f079a8443884c4713d7b99f033c8856ec73d980ab6157c3c",
      WAGYU_API_KEY: "wg_451cbe528edd9019adb10fed794d45fde80f6bf5c9d0a2a11f2077a0",
      TREASURY_PRIVATE_KEY: process.env.TREASURY_PRIVATE_KEY,
    }
  }]
};
