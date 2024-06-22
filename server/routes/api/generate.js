const express = require("express");
const router = express.Router();
require("dotenv").config();
const ethers = require("ethers");
const { split } = require("shamir");
const HKDF = require("hkdf");
const sodium = require("libsodium-wrappers");
const { addToChainSafe, precheck } = require("../../utils/chainsafe");

router.post("/", async (req, res) => {
  try {
    const domain = req.body.domain;
    const authSecret = req.body.authSecret;
    const recovcerySecret = req.body.recoverySecret;

    var hkdf = new HKDF("sha256", process.env.SERVER_SALT, authSecret);
    hkdf.derive(domain, 42, async function (key) {
      try {
        const hashedKey = key.toString("hex");

        const utf8Encoder = new TextEncoder();
        const secretBytes = utf8Encoder.encode(hashedKey);

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

        const shares = split(customRndBytes, 3, 3, secretBytes);
        const hexShares = {
          shard1: ethers.utils.hexlify(shares["1"]),
          shard2: ethers.utils.hexlify(shares["2"]),
          shard3: ethers.utils.hexlify(shares["3"]),
        };

        const wallet = ethers.Wallet.createRandom();
        const privateKey = wallet.privateKey.toString();

        await sodium.ready;

        const nonce = Buffer.from(process.env.KEYGEN_SALT);
        const encryptionKey = ethers.utils.toUtf8Bytes(
          process.env.KEYGEN_ENCRYPT_KEY
        );

        let cipherKey = sodium.crypto_secretbox_easy(
          privateKey,
          nonce,
          encryptionKey
        );

        const bufferCipherKey = Buffer.from(cipherKey);
        const shardSize = Math.floor(bufferCipherKey.length / 3);
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

        hkdf = new HKDF("sha256", process.env.SERVER_SALT, recovcerySecret);
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

            const shares = split(customRndBytes, 3, 3, recoveryBytes);

            const hexRecoveryShares = {
              shard1: ethers.utils.hexlify(shares["1"]),
              shard2: ethers.utils.hexlify(shares["2"]),
              shard3: ethers.utils.hexlify(shares["3"]),
            };

            const recoveryShares = {
              shard1: {
                _id: hexRecoveryShares.shard1,
                loc: hexShares.shard1,
              },
              shard2: {
                _id: hexRecoveryShares.shard2,
                shard: hexShares.shard2,
              },
              shard3: {
                _id: hexRecoveryShares.shard3,
                shard: hexShares.shard3,
              },
            };

            await precheck(shard1);
            await precheck(shard2);
            await precheck(shard3);
            await precheck(recoveryShares.shard1);
            await precheck(recoveryShares.shard2);
            await precheck(recoveryShares.shard3);

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

module.exports = router;
