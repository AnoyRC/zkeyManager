const express = require("express");
const router = express.Router();
require("dotenv").config();
const ethers = require("ethers");
const { split } = require("shamir");
const HKDF = require("hkdf");
const sodium = require("libsodium-wrappers");
const { addToChainSafe, precheck } = require("../../utils/chainsafe");
const { v4: uuidv4 } = require("uuid");
globalThis.crypto ??= require("node:crypto").webcrypto;
const { auth } = require("express-oauth2-jwt-bearer");
const { resolveRegistration, resolveAuth0 } = require("../../helpers/resolve");

const checkJwt = auth({
  audience: "https://test.api",
  issuerBaseURL: `https://dev-pekknv1gkulrlnlq.us.auth0.com/`,
});

router.post("/", checkJwt, async (req, res) => {
  try {
    const domain = req.body.domain;
    const registration = req.body.registration;
    const challenge = req.body.challenge;

    // Check for required fields
    if (!domain || !registration || !challenge) {
      return res.json({ success: false, error: "Missing required fields" });
    }

    const expected = {
      challenge,
      origin: "http://localhost:3000",
    };

    const authSecret = await resolveRegistration(registration, expected);
    const recoverySecret = await resolveAuth0(req.auth);

    // Initializing HKDF with the server salt and the auth secret
    var hkdf = new HKDF("sha256", process.env.SERVER_SALT, authSecret);
    hkdf.derive(domain, 42, async function (key) {
      try {
        const hashedKey = key.toString("hex");

        const utf8Encoder = new TextEncoder();
        const secretBytes = utf8Encoder.encode(hashedKey);

        let nonceAdditive = domain.length;

        // Custom random bytes generator based on the domain
        const customRndBytes = () => {
          const nonceBytes = utf8Encoder.encode(domain);
          const bytes3 = new Uint32Array(3);

          for (let i = 0; i < nonceBytes.length; i += 3) {
            bytes3[0] += nonceBytes[i] + nonceAdditive;
            if (i + 1 < nonceBytes.length) {
              bytes3[1] += nonceBytes[i + 1] + nonceAdditive;
            }
            if (i + 2 < nonceBytes.length) {
              bytes3[2] += nonceBytes[i + 2] + nonceAdditive;
            }
          }

          nonceAdditive += 1;
          return Buffer.from(bytes3);
        };

        // Split the secret into 3 shares using Shamir's Secret Sharing
        const shares = split(customRndBytes, 3, 3, secretBytes);
        const hexShares = {
          shard1: ethers.utils.hexlify(shares["1"]),
          shard2: ethers.utils.hexlify(shares["2"]),
          shard3: ethers.utils.hexlify(shares["3"]),
        };

        // Generate a random wallet
        const wallet = ethers.Wallet.createRandom();
        const privateKey = wallet.privateKey.toString();

        await sodium.ready;

        // Encrypt the private key using libsodium
        const nonce = Buffer.from(process.env.KEYGEN_SALT);
        const encryptionKey = ethers.utils.toUtf8Bytes(
          process.env.KEYGEN_ENCRYPT_KEY
        );

        let cipherKey = sodium.crypto_secretbox_easy(
          privateKey,
          nonce,
          encryptionKey
        );

        // Split the encrypted private key into 3 shares
        const bufferCipherKey = Buffer.from(cipherKey);
        const shardSize = Math.floor(bufferCipherKey.length / 3);

        // Create the shares to be uploaded to ChainSafe
        const shard1 = {
          _id: hexShares.shard1,
          shard: ethers.utils.hexlify(bufferCipherKey.slice(0, shardSize)),
        };
        const shard2 = {
          _id: hexShares.shard2,
          shard: ethers.utils.hexlify(
            bufferCipherKey.slice(shardSize, shardSize * 2)
          ),
        };
        const shard3 = {
          _id: hexShares.shard3,
          shard: ethers.utils.hexlify(bufferCipherKey.slice(shardSize * 2)),
        };

        // Split the recovery secret into 3 shares using Shamir's Secret Sharing
        hkdf = new HKDF("sha256", process.env.SERVER_SALT, recoverySecret);
        hkdf.derive(domain, 42, async function (key) {
          try {
            const hashedRecoveryKey = key.toString("hex");

            const recoveryBytes = utf8Encoder.encode(hashedRecoveryKey);

            let nonceAdditive = domain.length;

            const customRndBytes = () => {
              const nonceBytes = utf8Encoder.encode(domain);
              const bytes3 = new Uint32Array(3);

              for (let i = 0; i < nonceBytes.length; i += 3) {
                bytes3[0] += nonceBytes[i] + nonceAdditive;
                if (i + 1 < nonceBytes.length) {
                  bytes3[1] += nonceBytes[i + 1] + nonceAdditive;
                }
                if (i + 2 < nonceBytes.length) {
                  bytes3[2] += nonceBytes[i + 2] + nonceAdditive;
                }
              }

              nonceAdditive += 1;
              return Buffer.from(bytes3);
            };

            // Split the recovery secret into 3 shares using Shamir's Secret Sharing
            const shares = split(customRndBytes, 3, 3, recoveryBytes);

            const hexRecoveryShares = {
              shard1: ethers.utils.hexlify(shares["1"]),
              shard2: ethers.utils.hexlify(shares["2"]),
              shard3: ethers.utils.hexlify(shares["3"]),
            };

            // Create the recovery shares to be uploaded to ChainSafe
            const recoveryShares = {
              shard1: {
                _id: hexRecoveryShares.shard1,
                loc: hexShares.shard1,
              },
              shard2: {
                _id: hexRecoveryShares.shard2,
                loc: hexShares.shard2,
              },
              shard3: {
                _id: hexRecoveryShares.shard3,
                loc: hexShares.shard3,
              },
            };

            // Checking if the shares can be uploaded to ChainSafe
            await precheck(shard1);
            await precheck(shard2);
            await precheck(shard3);
            await precheck(recoveryShares.shard1);
            await precheck(recoveryShares.shard2);
            await precheck(recoveryShares.shard3);

            // Uploading the shares to ChainSafe
            await addToChainSafe(shard1);
            await addToChainSafe(shard2);
            await addToChainSafe(shard3);
            await addToChainSafe(recoveryShares.shard1);
            await addToChainSafe(recoveryShares.shard2);
            await addToChainSafe(recoveryShares.shard3);

            res.json({ success: true });
          } catch (error) {
            console.error(error);
            res.json({ success: false, error: "Internal server error" });
          }
        });
      } catch (error) {
        console.error(error);
        res.json({ success: false, error: "Internal server error" });
      }
    });
  } catch (error) {
    console.error(error);
    res.json({ success: false, error: "Internal server error" });
  }
});

router.get("/passkey/challenge", async (req, res) => {
  try {
    const challenge = uuidv4();

    res.json({ success: true, challenge });
  } catch (error) {
    console.error(error);
    res.json({ success: false, error: "Internal server error" });
  }
});

module.exports = router;
