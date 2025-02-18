const functions = require("firebase-functions");
const crypto = require("crypto");
const axios = require("axios");
// const admin = require("firebase-admin");
const fs = require("fs");
const path = require("path");

const {SecretManagerServiceClient} = require("@google-cloud/secret-manager");
const client = new SecretManagerServiceClient();

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

  // Ensure the private key is in PEM format
  let pemKey = privateKey.trim();
  if (!pemKey.startsWith("-----BEGIN RSA PRIVATE KEY-----")) {
    pemKey = `-----BEGIN RSA PRIVATE KEY-----\n${pemKey}\n-----END RSA PRIVATE KEY-----`;
  }
  // Replace any '\n' string literals with actual newlines
  pemKey = pemKey.replace(/\\n/g, "\n");

  console.log("Private Key (first 100 chars):", pemKey.substring(0, 100));

  return require("jsonwebtoken").sign(
      payload,
      pemKey,
      {algorithm: "RS256"},
  );
  // return require("jsonwebtoken").sign(
  //     payload,
  //     privateKey,
  //     {algorithm: "RS256"},
  // );
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
  console.log("Token Scope (Necessary - contents: write):", response.data);
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

// Read YAML file
const WORKFLOW_YAML_CONTENT = fs.readFileSync(
    path.join(__dirname, "test-workflow.yml"),
    "utf8",
);

/**
 * Inject workflow file into a repository.
 * @param {string} owner - The owner of the repository.
 * @param {string} repo - The name of the repository.
 * @param {string} installationId - The ID of the GitHub App installation.
 * @param {string} githubAppId - The GitHub App ID.
 * @param {string} privateKey - The GitHub private key.
 * @return {Promise<void>} A promise that resolves when the workflow file has been injected.
 */
async function injectWorkflowFile(owner, repo, installationId, githubAppId, privateKey) {
  const token = await getInstallationAccessToken(installationId, githubAppId, privateKey);

  // Get default branch
  const {data: repoData} = await axios.get(`https://api.github.com/repos/${owner}/${repo}`, {
    headers: {Authorization: `Bearer ${token}`},
  });
  const defaultBranch = repoData.default_branch;

  // Get latest commit SHA
  const {data: refData} = await axios.get(
      `https://api.github.com/repos/${owner}/${repo}/git/ref/heads/${defaultBranch}`,
      {
        headers: {Authorization: `Bearer ${token}`},
      },
  );
  const latestCommitSha = refData.object.sha;

  // Get tree SHA
  const {data: commitData} = await axios.get(
      `https://api.github.com/repos/${owner}/${repo}/git/commits/${latestCommitSha}`,
      {
        headers: {Authorization: `Bearer ${token}`},
      },
  );
  const treeSha = commitData.tree.sha;

  // Create blob (file content)
  const {data: blobData} = await axios.post(`https://api.github.com/repos/${owner}/${repo}/git/blobs`, {
    content: WORKFLOW_YAML_CONTENT,
    encoding: "utf-8",
  }, {headers: {Authorization: `Bearer ${token}`}});

  // Create a new tree
  const {data: newTreeData} = await axios.post(`https://api.github.com/repos/${owner}/${repo}/git/trees`, {
    base_tree: treeSha,
    // tree: [{path: ".github/workflows/openhands-resolver.yml", mode: "100644", type: "blob", sha: blobData.sha}],
    tree: [{path: ".github/workflows/test-workflow.yml", mode: "100644", type: "blob", sha: blobData.sha}],
  }, {headers: {Authorization: `Bearer ${token}`}});

  // Create a new commit
  const {data: newCommitData} = await axios.post(`https://api.github.com/repos/${owner}/${repo}/git/commits`, {
    message: "Add OpenHands resolver workflow",
    tree: newTreeData.sha,
    parents: [latestCommitSha],
  }, {headers: {Authorization: `Bearer ${token}`}});

  // Update the branch reference
  await axios.patch(`https://api.github.com/repos/${owner}/${repo}/git/refs/heads/${defaultBranch}`, {
    sha: newCommitData.sha,
  }, {headers: {Authorization: `Bearer ${token}`}});

  console.log(`Injected workflow file into ${owner}/${repo}`);
}

// Expexted hash for: test-workflow.yml
const EXPECTED_WORKFLOW_HASH = "54a3a71cf1ee16eb7d5b91c752e1e792a86129e7df0efde07853c0e4aada11b6";

/**
 * Fetches the workflow file from the user's repository.
 * @param {string} owner - GitHub repository owner.
 * @param {string} repo - Repository name.
 * @param {string} token - GitHub App installation token.
 * @return {Promise<string>} The YAML content of the workflow.
 */
async function getWorkflowContent(owner, repo, token) {
  try {
    const response = await axios.get(
        `https://api.github.com/repos/${owner}/${repo}/contents/.github/workflows/test-workflow.yml`,
        // `https://api.github.com/repos/${owner}/${repo}/contents/.github/workflows/openhands-resolver.yml`,
        {
          headers: {Authorization: `Bearer ${token}`, Accept: "application/vnd.github.v3+json"},
        },
    );

    // The content is Base64 encoded, decode it
    return Buffer.from(response.data.content, "base64").toString("utf8");
  } catch (error) {
    console.error("[E] Failed to fetch workflow file:", error.response.data || error.message);
    return null;
  }
}

/**
 * Computes the SHA-256 hash of a given string.
 * @param {string} content - The YAML file content.
 * @return {string} The SHA-256 hash.
 */
function computeHash(content) {
  return crypto.createHash("sha256").update(content, "utf8").digest("hex");
}

/**
 * Triggers the GitHub Actions workflow when an issue is labeled "pr-arena".
 *
 * This function dynamically retrieves required secrets from Firebase Secret Manager,
 * extracts the repository owner as the PAT username, and uses the GitHub App's
 * installation token as the PAT token. It then triggers the `.github/workflows/openhands-resolver.yml`
 * workflow with the necessary inputs.
 *
 * @param {string} owner - The GitHub username or organization name of the repository owner.
 * @param {string} repo - The name of the repository where the workflow should run.
 * @param {number} issueNumber - The issue number that triggered the workflow.
 * @param {number} installationId - The GitHub App installation ID for authentication.
 * @param {string} githubAppId - The GitHub App ID for generating JWT tokens.
 * @param {string} privateKey - The private key associated with the GitHub App for authentication.
 * @return {Promise<void>} A promise that resolves when the workflow is successfully triggered.
 *
 * @throws {Error} If the workflow dispatch request fails, logs the error message.
 */
async function triggerWorkflow(owner, repo, issueNumber, installationId, githubAppId, privateKey) {
  const token = await getInstallationAccessToken(installationId, githubAppId, privateKey);

  console.log(`[P] Fetching and validating workflow file for ${owner}/${repo}`);

  // Fetch the workflow file from the repository
  const workflowContent = await getWorkflowContent(owner, repo, token);
  if (!workflowContent) {
    console.error("[E] Could not retrieve workflow file. Skipping execution.");
    return;
  }

  // Compute and verify hash
  const actualHash = computeHash(workflowContent);
  if (actualHash !== EXPECTED_WORKFLOW_HASH) {
    console.error("[E] Workflow file has been modified! Skipping execution.");
    return;
  }

  console.log("[P] Workflow file is valid. Proceeding with execution.");

  // Retrieve necessary secrets from Firebase Secret Manager
  const llmModels = await getSecret("LLM_MODELS");
  const llmApiKey = await getSecret("LLM_API_KEY");
  const firebaseConfig = await getSecret("FIRE_CONFIG");
  const baseUrl = await getSecret("BASE_URL");

  // Define workflow inputs, dynamically setting PAT credentials
  const workflowInputs = {
    issue_number: issueNumber.toString(), // Ensure it's passed as a string
    llm_models: llmModels,
    llm_api_key: llmApiKey,
    firebase_config: firebaseConfig,
    base_url: baseUrl,
    pat_token: token, // Use the GitHub App installation token
    pat_username: owner, // Use the repository owner as the username
  };

  console.log(`[P] Triggering workflow for ${owner}/${repo} with inputs:`, workflowInputs);

  try {
    // Trigger the workflow via GitHub API
    await axios.post(
        // `https://api.github.com/repos/${owner}/${repo}/actions/workflows/openhands-resolver.yml/dispatches`,
        `https://api.github.com/repos/${owner}/${repo}/actions/workflows/test-workflow.yml/dispatches`,
        {
          ref: "main", // Ensure this matches the branch where the workflow exists
          inputs: workflowInputs,
        },
        {
          headers: {
            Authorization: `Bearer ${token}`,
            Accept: "application/vnd.github.v3+json",
          },
        },
    );

    console.log(`[P] Successfully triggered workflow for ${owner}/${repo}`);
  } catch (error) {
    console.error(`[E] Failed to trigger workflow:`, error.response.data, error.message);
  }
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
    return res.status(401).send("Invalid signature");
  }

  const eventName = req.get("X-GitHub-Event");
  const deliveryId = req.get("X-GitHub-Delivery");
  const payload = req.body;
  console.log(`Received event: ${eventName} (delivery: ${deliveryId})`);

  if (eventName === "installation" && payload.action === "created") {
    const installation = payload.installation;
    const repositories = payload.repositories;
    const installationId = installation.id;
    const owner = installation.account.login;

    console.log(`GitHub App installed on owner: ${owner}`);
    console.log(`GitHub App installed on repositories:`, repositories.map((repo) => repo.full_name));

    for (const repo of repositories) {
      // if (!repo || !repo.owner || !repo.owner.login) {
      //   console.log(`Missing owner info in repo:`, repo);
      // }
      if (!owner) {
        console.log(`Missing owner info in installation:`, installation);
      }
      await injectWorkflowFile(owner, repo.name, installationId, GITHUB_APP_ID, GITHUB_PRIVATE_KEY);
      /*
      * We avoid injecting secrets directy into repositories for security reasons.
      * e.g., Users might use API Keys to access external services, or Firebase config to access Firestore.
      * Instead, we inject secrets into the Cloud Functions environment using Secret Manager,
      *                                                                and execute yaml workflow with secrets as inputs.
      * await injectGitHubSecrets(owner, repo.name, installationId, GITHUB_APP_ID, GITHUB_PRIVATE_KEY); --> (X)
      */
    }
  }
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

    if (label.name.toLowerCase() === "pr-arena") {
      console.log(`[P] Triggering workflow for ${repository.owner.login}/${repository.name} on issue #${issue.number}`);
      console.log(`[P] Installation:`, installation);
      console.log(`[P] Repository:`, repository);
      await triggerWorkflow(
          repository.owner.login,
          repository.name,
          issue.number,
          installation.id,
          GITHUB_APP_ID,
          GITHUB_PRIVATE_KEY,
      );
    }
  }

  return res.status(200).send("Received");
});
