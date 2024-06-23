const express = require("express");
const router = express.Router();
require("dotenv").config();
const { auth } = require("express-oauth2-jwt-bearer");
const { resolveRegistration, resolveAuth0 } = require("../../helpers/resolve");
const {
  getFile,
  precheck,
  addToChainSafe,
  deleteShard,
  updateFile,
} = require("../../utils/chainsafe");
const { split } = require("shamir");
const HKDF = require("hkdf");
const ethers = require("ethers");

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

    const utf8Encoder = new TextEncoder();

    // Split the recovery secret into 3 shares using Shamir's Secret Sharing
    const hkdf = new HKDF("sha256", process.env.SERVER_SALT, recoverySecret);
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

        const share1 = await getFile(hexRecoveryShares.shard1);
        const share2 = await getFile(hexRecoveryShares.shard2);
        const share3 = await getFile(hexRecoveryShares.shard3);

        const walletShare1 = await getFile(share1.loc);
        const walletShare2 = await getFile(share2.loc);
        const walletShare3 = await getFile(share3.loc);

        const hkdf = new HKDF("sha256", process.env.SERVER_SALT, authSecret);
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

            const newShare1 = {
              _id: hexShares.shard1,
              shard: walletShare1.shard,
            };

            const newShare2 = {
              _id: hexShares.shard2,
              shard: walletShare2.shard,
            };

            const newShare3 = {
              _id: hexShares.shard3,
              shard: walletShare3.shard,
            };

            const newRecoveryShare1 = {
              _id: hexRecoveryShares.shard1,
              loc: newShare1._id,
            };

            const newRecoveryShare2 = {
              _id: hexRecoveryShares.shard2,
              loc: newShare2._id,
            };

            const newRecoveryShare3 = {
              _id: hexRecoveryShares.shard3,
              loc: newShare3._id,
            };

            await precheck(newShare1);
            await precheck(newShare2);
            await precheck(newShare3);

            await addToChainSafe(newShare1);
            await addToChainSafe(newShare2);
            await addToChainSafe(newShare3);

            await updateFile(newRecoveryShare1);
            await updateFile(newRecoveryShare2);
            await updateFile(newRecoveryShare3);

            await deleteShard(walletShare1._id);
            await deleteShard(walletShare2._id);
            await deleteShard(walletShare3._id);

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
