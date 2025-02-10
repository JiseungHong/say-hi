const functions = require("firebase-functions");
const crypto = require("crypto");
const axios = require("axios");
const admin = require("firebase-admin");

const {SecretManagerServiceClient} = require("@google-cloud/secret-manager");
const client = new SecretManagerServiceClient();

let db;
if (process.env.FIREBASE_CONFIG) {
  admin.initializeApp();
  db = admin.firestore();
} else {
  // Use a mock Firestore for testing
  db = {
    collection: () => ({
      doc: () => ({
        set: () => Promise.resolve(),
      }),
    }),
  };
}


// const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET || "";
// const GITHUB_APP_ID = process.env.GITHUB_APP_ID || "";
// const GITHUB_PRIVATE_KEY = process.env.GITHUB_PRIVATE_KEY || "";

/**
 * Helper function to access a secret version.
 * @param {string} secretName The name of the secret to retrieve.
 * @return {Promise<string>} The secret value.
 */
async function getSecret(secretName) {
  const [accessResponse] = await client.accessSecretVersion({
    name: `projects/say-hi-fab35/secrets/${secretName}/versions/latest`,
  });
  return accessResponse.payload.data.toString("utf8");
}

/**
 * Verifies the signature of the incoming GitHub webhook request.
 * @param {Object} req - The incoming request object.
 * @param {string} webhookSecret - The webhook secret to use for verification.
 * @return {boolean} Returns true if the signature is valid, false otherwise.
 */
function verifySignature(req, webhookSecret) {
  const signature = req.get("X-Hub-Signature-256");
  if (!signature) {
    console.error("No X-Hub-Signature-256 found on request");
    return false;
  }
  const hmac = crypto.createHmac("sha256", webhookSecret);
  const digest = "sha256=" + hmac
      .update(JSON.stringify(req.body))
      .digest("hex");
  console.log("GITHUB_PRIVATE_KEY:", process.env.GITHUB_PRIVATE_KEY || "Not set or empty");
  console.log("WEBHOOK_SECRET:", process.env.WEBHOOK_SECRET);

  if (crypto.timingSafeEqual(
      Buffer.from(signature),
      Buffer.from(digest),
  )) {
    return true;
  } else {
    console.error("Signatures didn't match!");
    return false;
  }
}

/**
 * Generates a JSON Web Token (JWT) for GitHub App authentication.
 * @param {string} githubAppId The GitHub App ID.
 * @param {string} privateKey The GitHub private key.
 * @return {Promise<string>} A promise that resolves to the JWT string.
 */
async function getJWT(githubAppId, privateKey) {
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iat: now,
    exp: now + 60 * 10,
    iss: githubAppId,
  };
  return require("jsonwebtoken").sign(
      payload,
      privateKey,
      {algorithm: "RS256"},
  );
}

/**
 * Retrieves an installation access token for a GitHub App installation.
 * @param {string} installationId - The ID of the GitHub App installation.
 * @param {string} githubAppId - The GitHub App ID.
 * @param {string} privateKey - The GitHub private key.
 * @return {Promise<string>} A promise that resolves to the installation access
 *                            token.
 */
async function getInstallationAccessToken(installationId, githubAppId, privateKey) {
  const jwt = await getJWT(githubAppId, privateKey);
  const url = `https://api.github.com/app/installations/${installationId}/access_tokens`;
  const response = await axios.post(url, {}, {
    headers: {
      Authorization: `Bearer ${jwt}`,
      Accept: "application/vnd.github.v3+json",
    },
  });
  return response.data.token;
}

/**
 * Posts a comment on a GitHub issue.
 * @param {string} owner - The owner of the repository.
 * @param {string} repo - The name of the repository.
 * @param {number} issueNumber - The number of the issue.
 * @param {string} comment - The content of the comment.
 * @param {string} installationId - The ID of the GitHub App installation.
 * @param {string} githubAppId - The GitHub App ID.
 * @param {string} privateKey - The GitHub private key.
 * @return {Promise<void>}
 */
async function commentOnIssue(owner, repo, issueNumber, comment, installationId, githubAppId, privateKey) {
  const token = await getInstallationAccessToken(installationId, githubAppId, privateKey);
  await axios.post(
      `https://api.github.com/repos/${owner}/${repo}/issues/${issueNumber}/comments`,
      {body: comment},
      {
        headers: {
          Authorization: `Bearer ${token}`,
          Accept: "application/vnd.github.v3+json",
        },
      },
  );
}

exports.githubAppWebhook = functions.https.onRequest({
  cors: true,
  invoker: "public",
}, async (req, res) => {
  // Retrieve all secrets
  const GITHUB_PRIVATE_KEY = await getSecret("GITHUB_PRIVATE_KEY");
  const WEBHOOK_SECRET = await getSecret("WEBHOOK_SECRET");
  const GITHUB_APP_ID = await getSecret("GITHUB_APP_ID");

  // Debug logs (for testing, truncate long outputs)
  console.log("GITHUB_PRIVATE_KEY (truncated):", GITHUB_PRIVATE_KEY.substring(0, 50) + "...");
  console.log("WEBHOOK_SECRET:", WEBHOOK_SECRET);
  console.log("GITHUB_APP_ID:", GITHUB_APP_ID);

  if (!verifySignature(req, WEBHOOK_SECRET)) {
    console.warn("Signature verification failed!!!");
    console.log("GITHUB_PRIVATE_KEY (truncated):", GITHUB_PRIVATE_KEY.substring(0, 50) + "...");
    console.log("WEBHOOK_SECRET:", WEBHOOK_SECRET);
    console.log("GITHUB_APP_ID:", GITHUB_APP_ID);
    return res.status(401).send("Invalid signature");
  }

  const eventName = req.get("X-GitHub-Event");
  const deliveryId = req.get("X-GitHub-Delivery");
  const payload = req.body;
  console.log(`Received event: ${eventName} (delivery: ${deliveryId})`);

  if (eventName === "issues" && payload.action === "labeled") {
    const issue = payload.issue;
    const label = payload.label;
    const repository = payload.repository;
    const installation = payload.installation;

    console.log(`Issue #${issue.number} labeled: ${label.name}`);

    if (label.name.toLowerCase() === "hi") {
      await commentOnIssue(
          repository.owner.login,
          repository.name,
          issue.number,
          "hi, there",
          installation.id,
          GITHUB_APP_ID,
          GITHUB_PRIVATE_KEY,
      );
      console.log(`Commented on issue #${issue.number}`);
    }

    await db.collection("github-issues").doc(issue.id.toString()).set({
      number: issue.number,
      title: issue.title,
      action: payload.action,
      label: label.name,
      updated_at: issue.updated_at,
    });
  }

  return res.status(200).send("Received");
});
