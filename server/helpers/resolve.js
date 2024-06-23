const { parseAuthData } = require("./webauthn");
const { addPasskeyToChainSafe, getPasskey } = require("../utils/chainsafe");
const { hashPasskey, hash } = require("./hash");

const resolveRegistration = async (registration, expected) => {
  await import("@passwordless-id/webauthn")
    .then(async (res) => {
      const { server } = res;
      const { verifyRegistration } = server;

      const verified = await verifyRegistration(registration, expected);

      if (!verified) throw new Error("Invalid registration");
    })
    .catch((err) => {
      throw new Error(err);
    });

  await addPasskeyToChainSafe(registration.credential);

  var encoder = new TextEncoder();

  const parsedAuthData = parseAuthData(
    encoder.encode(registration.authenticatorData).buffer
  );

  const hash = hashPasskey(
    parsedAuthData.aaguid,
    parsedAuthData.rpIdHash,
    registration.credential.id
  );

  return hash;
};

const resolveAuthentication = async (authentication, expected) => {
  const credential = await getPasskey(authentication.credentialId);

  await import("@passwordless-id/webauthn")
    .then(async (res) => {
      const { server } = res;
      const { verifyAuthentication } = server;

      const verified = await verifyAuthentication(
        authentication,
        credential,
        expected
      );

      if (!verified) throw new Error("Invalid authentication");
    })
    .catch((err) => {
      throw new Error(err);
    });

  var encoder = new TextEncoder();

  const parsedAuthData = parseAuthData(
    encoder.encode(authentication.authenticatorData).buffer
  );

  const hash = hashPasskey(
    parsedAuthData.aaguid,
    parsedAuthData.rpIdHash,
    authentication.credentialId
  );

  return hash;
};

const resolveAuth0 = async (auth) => {
  const hashedpayload = hash(
    auth.payload.sub,
    auth.payload.iss,
    auth.payload.azp
  );

  return hashedpayload;
};

module.exports = { resolveRegistration, resolveAuthentication, resolveAuth0 };
