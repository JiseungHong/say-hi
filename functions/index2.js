const functions = require("firebase-functions");
const crypto = require("crypto");
const axios = require("axios");
const admin = require("firebase-admin");
const { SecretManagerServiceClient } = require("@google-cloud/secret-manager");
const { exec } = require("child_process");
const util = require("util");
const execPromise = util.promisify(exec);

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

async function getSecret(secretName) {
  const [accessResponse] = await client.accessSecretVersion({
    name: `projects/pr-arena/secrets/${secretName}/versions/latest`,
  });
  return accessResponse.payload.data.toString("utf8");
}

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

  return crypto.timingSafeEqual(
    Buffer.from(signature),
    Buffer.from(digest)
  );
}

async function getJWT(githubAppId, privateKey) {
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iat: now,
    exp: now + 60 * 10,
    iss: githubAppId,
  };

  let pemKey = privateKey.trim();
  if (!pemKey.startsWith("-----BEGIN RSA PRIVATE KEY-----")) {
    pemKey = `-----BEGIN RSA PRIVATE KEY-----\n${pemKey}\n-----END RSA PRIVATE KEY-----`;
  }
  pemKey = pemKey.replace(/\\n/g, "\n");

  return require("jsonwebtoken").sign(
    payload,
    pemKey,
    { algorithm: "RS256" }
  );
}

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

async function commentOnIssue(owner, repo, issueNumber, comment, installationId, githubAppId, privateKey) {
  const token = await getInstallationAccessToken(installationId, githubAppId, privateKey);
  await axios.post(
    `https://api.github.com/repos/${owner}/${repo}/issues/${issueNumber}/comments`,
    { body: comment },
    {
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: "application/vnd.github.v3+json",
      },
    }
  );
}

async function runOpenHandsResolver(owner, repo, issueNumber) {
  try {
    const { stdout, stderr } = await execPromise(
      `python -m openhands_resolver.resolve_issues --repo ${owner}/${repo} --issue-numbers ${issueNumber}`
    );
    console.log('OpenHands resolver output:', stdout);
    if (stderr) console.error('OpenHands resolver error:', stderr);
    return JSON.parse(stdout);
  } catch (error) {
    console.error('Error running OpenHands resolver:', error);
    throw error;
  }
}

async function listenForDecision(owner, repo, issueNumber) {
  try {
    const { stdout, stderr } = await execPromise(
      `python -m openhands_resolver.listen_for_decision --repo ${owner}/${repo} --issue-number ${issueNumber}`
    );
    console.log('Decision listener output:', stdout);
    if (stderr) console.error('Decision listener error:', stderr);
    return JSON.parse(stdout);
  } catch (error) {
    console.error('Error listening for decision:', error);
    throw error;
  }
}

async function sendPullRequest(owner, repo, issueNumber, modelNumber) {
  try {
    const { stdout, stderr } = await execPromise(
      `python -m openhands_resolver.send_pull_request --repo ${owner}/${repo} --issue-number ${issueNumber} --model-number ${modelNumber} --pr-type draft`
    );
    console.log('Pull request creation output:', stdout);
    if (stderr) console.error('Pull request creation error:', stderr);
    return JSON.parse(stdout);
  } catch (error) {
    console.error('Error creating pull request:', error);
    throw error;
  }
}

exports.prArenaWebhook = functions.https.onRequest({
  cors: true,
  invoker: "public",
}, async (req, res) => {
  const GITHUB_PRIVATE_KEY = await getSecret("GITHUB_PRIVATE_KEY");
  const WEBHOOK_SECRET = await getSecret("WEBHOOK_SECRET");
  const GITHUB_APP_ID = await getSecret("GITHUB_APP_ID");

  if (!verifySignature(req, WEBHOOK_SECRET)) {
    console.warn("Signature verification failed!");
    return res.status(401).send("Invalid signature");
  }

  const eventName = req.get("X-GitHub-Event");
  const deliveryId = req.get("X-GitHub-Delivery");
  const payload = req.body;
  console.log(`Received event: ${eventName} (delivery: ${deliveryId})`);

  if (eventName === "issues" && payload.action === "labeled" && payload.label.name.toLowerCase() === "pr-arena") {
    const issue = payload.issue;
    const repository = payload.repository;
    const installation = payload.installation;

    console.log(`PR-Arena triggered for issue #${issue.number}`);

    // Post initial comment
    await commentOnIssue(
      repository.owner.login,
      repository.name,
      issue.number,
      "OpenHands has started working on fixing this issue. Please wait while we generate solutions.",
      installation.id,
      GITHUB_APP_ID,
      GITHUB_PRIVATE_KEY
    );

    // Run OpenHands resolver
    const resolverResult = await runOpenHandsResolver(repository.owner.login, repository.name, issue.number);

    if (resolverResult.success) {
      // Post PR-Arena link
      await commentOnIssue(
        repository.owner.login,
        repository.name,
        issue.number,
        `Solutions have been generated. Please review and select the best solution at: ${resolverResult.pr_arena_link}`,
        installation.id,
        GITHUB_APP_ID,
        GITHUB_PRIVATE_KEY
      );

      // Listen for user decision
      const decision = await listenForDecision(repository.owner.login, repository.name, issue.number);

      if (decision.selected_model) {
        // Create draft pull request
        const prResult = await sendPullRequest(repository.owner.login, repository.name, issue.number, decision.selected_model);

        // Post comment about draft PR
        await commentOnIssue(
          repository.owner.login,
          repository.name,
          issue.number,
          `A draft pull request has been created for your review: ${prResult.pr_url}`,
          installation.id,
          GITHUB_APP_ID,
          GITHUB_PRIVATE_KEY
        );
      }
    } else {
      // Post error comment
      await commentOnIssue(
        repository.name,
        issue.number,
        "Unfortunately, OpenHands encountered an error while trying to generate solutions. Please check the logs for more information.",
        installation.id,
        GITHUB_APP_ID,
        GITHUB_PRIVATE_KEY
      );
    }

    // Log the event in Firestore
    await db.collection("pr-arena-issues").doc(issue.id.toString()).set({
      number: issue.number,
      title: issue.title,
      action: payload.action,
      label: payload.label.name,
      updated_at: issue.updated_at,
      resolver_result: resolverResult,
    });
  }

  return res.status(200).send("Received");
});