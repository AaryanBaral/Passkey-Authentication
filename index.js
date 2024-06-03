const express = require("express");
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require("@simplewebauthn/server");
const app = express();

app.use(express.static("./public"));
app.use(express.json());
const userStore = {};
const challengeStore = {};
app.post("/register", (req, res) => {
  const { username, password } = req.body;
  const id = `user_${Date.now()}`;
  const user = {
    id,
    username,
    password,
  };
  userStore[id] = user;
  res.json({
    sucess: true,
    id,
  });
});

app.post("/register-challenge", async (req, res) => {
  const { id } = req.body;
  if (!userStore[id])
    return res.status(400).json({ sucess: false, error: `User not found` });
  const user = userStore[id];
  const challengePayload = await generateRegistrationOptions({
    rpID: "localhost",
    rpName: "My Localhost",
    userName: user.username,
  });
  challengeStore[id] = challengePayload.challenge;
  console.log(challengePayload.challenge);
  res.json({
    sucess: true,
    options: challengePayload,
  });
});

app.post("/register-verify", async (req, res) => {
  const { userId, cred } = req.body;
  if (!userStore[userId])
    return res.status(400).json({ sucess: false, error: `User not found` });
  const challenge = challengeStore[userId];
  const verification = await verifyRegistrationResponse({
    expectedChallenge: challenge,
    expectedOrigin: "http://localhost:3000",
    expectedRPID: "localhost",
    response: cred,
  });
  console.log(verification);
  if (!verification.verified)
    return res.status(400).json({ sucess: false, error: `Could not verify` });
  userStore[userId].passkey = verification.registrationInfo;
  res.json({
    sucess: true,
    verified: true,
  });
});
app.post("/login-verify", async (req, res) => {
  const { userId, cred } = req.body;
  if (!userStore[userId])
    return res.status(400).json({ sucess: false, error: `User not found` });
    const user = userStore[userId]
  const challenge = challengeStore[userId];
  const authentication = await verifyAuthenticationResponse({
    expectedChallenge: challenge,
    expectedOrigin: "http://localhost:3000",
    expectedRPID: "localhost",
    response: cred,
    authenticator:user.passkey
  });
  if (!authentication.verified)
    return res.status(400).json({ sucess: false, error: `Could not verify` });
  res.json({
    sucess: true,
    verified: true,
  });
});

app.post("/login-challenge",async(req,res)=>{
    console.log("login-challenge")
    const {userId} = req.body;
    if (!userStore[userId])
        return res.status(400).json({ sucess: false, error: `User not found` });
    const opts = await generateAuthenticationOptions({rpID:"localhost"})
    challengeStore[userId] = opts.challenge
    res.json({sucess:true,options:opts})
})

app.listen(3000, () => {
  console.log(`listning on http://localhost:3000`);
});
