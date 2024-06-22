const express = require("express");
const router = express.Router();
require("dotenv").config();
const ethers = require("ethers");
const { split } = require("shamir");
const HKDF = require("hkdf");
const sodium = require("libsodium-wrappers");
const { getFile } = require("../../utils/chainsafe");

router.post("/pubkey", async (req, res) => {
  try {
    const domain = req.body.domain;
    const authSecret = req.body.authSecret;

    // Check for required fields
    if (!domain || !authSecret) {
      return res.json({ success: false, error: "Missing required fields" });
    }

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

        // Retrieve the shards from ChainSafe
        const shard1 = await getFile(hexShares.shard1);
        const shard2 = await getFile(hexShares.shard2);
        const shard3 = await getFile(hexShares.shard3);

        const nonce = Buffer.from(process.env.KEYGEN_SALT);
        const encryptionKey = ethers.utils.toUtf8Bytes(
          process.env.KEYGEN_ENCRYPT_KEY
        );

        const recoveredCipherKey = Buffer.concat([
          Buffer.from(ethers.utils.arrayify(shard1.shard)),
          Buffer.from(ethers.utils.arrayify(shard2.shard)),
          Buffer.from(ethers.utils.arrayify(shard3.shard)),
        ]);

        // Decrypt the private key using libsodium
        const recoveredPrivateKey = sodium.crypto_secretbox_open_easy(
          recoveredCipherKey,
          nonce,
          encryptionKey
        );

        // Create a wallet from the recovered private key
        const privateKey = Buffer.from(recoveredPrivateKey).toString();
        const wallet = new ethers.Wallet(privateKey);

        res.json({ success: true, address: wallet.address });
      } catch (error) {
        console.error(error.message);
        res.json({ success: false, error: error.message });
      }
    });
  } catch (error) {
    console.error(error.message);
    res.json({ success: false, error: error.message });
  }
});

router.post("/sign", async (req, res) => {
  try {
    const domain = req.body.domain;
    const authSecret = req.body.authSecret;
    const payload = req.body.payload;

    // Check for required fields
    if (!domain || !authSecret || !payload) {
      return res.json({ success: false, error: "Missing required fields" });
    }

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

        // Retrieve the shards from ChainSafe
        const shard1 = await getFile(hexShares.shard1);
        const shard2 = await getFile(hexShares.shard2);
        const shard3 = await getFile(hexShares.shard3);

        const nonce = Buffer.from(process.env.KEYGEN_SALT);
        const encryptionKey = ethers.utils.toUtf8Bytes(
          process.env.KEYGEN_ENCRYPT_KEY
        );

        const recoveredCipherKey = Buffer.concat([
          Buffer.from(ethers.utils.arrayify(shard1.shard)),
          Buffer.from(ethers.utils.arrayify(shard2.shard)),
          Buffer.from(ethers.utils.arrayify(shard3.shard)),
        ]);

        // Decrypt the private key using libsodium
        const recoveredPrivateKey = sodium.crypto_secretbox_open_easy(
          recoveredCipherKey,
          nonce,
          encryptionKey
        );

        // Create a wallet from the recovered private key
        const privateKey = Buffer.from(recoveredPrivateKey).toString();
        const wallet = new ethers.Wallet(privateKey);

        // Sign the payload with the recovered private key
        const signature = await wallet.signMessage(payload);

        res.json({ success: true, signature });
      } catch (error) {
        console.error(error.message);
        res.json({ success: false, error: error.message });
      }
    });
  } catch (error) {
    console.error(error.message);
    res.json({ success: false, error: error.message });
  }
});

module.exports = router;
