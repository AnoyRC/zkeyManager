const authenticatorMetadata = require("./authenticatorMetadata.js");

const parseAuthData = (authData) => {
  let flags = new DataView(authData.slice(32, 33)).getUint8(0);
  //console.debug(flags)

  // https://w3c.github.io/webauthn/#sctn-authenticator-data
  let parsed = {
    rpIdHash: toBase64url(authData.slice(0, 32)),
    flags: {
      userPresent: !!(flags & 1),
      //reserved1: !!(flags & 2),
      userVerified: !!(flags & 4),
      backupEligibility: !!(flags & 8),
      backupState: !!(flags & 16),
      //reserved2: !!(flags & 32),
      attestedData: !!(flags & 64),
      extensionsIncluded: !!(flags & 128),
    },
    counter: new DataView(authData.slice(33, 37)).getUint32(0, false), // Big-Endian!
  };

  // this is more descriptive than "backupState"
  parsed.synced = parsed.flags.backupState;

  if (authData.byteLength > 37) {
    // registration contains additional data

    const aaguid = extractAaguid(authData); // bytes 37->53
    // https://w3c.github.io/webauthn/#attested-credential-data
    parsed = {
      ...parsed,
      aaguid,
      name: authenticatorMetadata[aaguid] ?? "Unknown",
    };
  }

  return parsed;
};

function toBase64url(buffer) {
  const txt = btoa(parseBuffer(buffer)); // base64
  return txt.replaceAll("+", "-").replaceAll("/", "_");
}

function extractAaguid(authData) {
  return formatAaguid(authData.slice(37, 53)); // 16 bytes
}

function formatAaguid(buffer) {
  let aaguid = bufferToHex(buffer);
  aaguid =
    aaguid.substring(0, 8) +
    "-" +
    aaguid.substring(8, 12) +
    "-" +
    aaguid.substring(12, 16) +
    "-" +
    aaguid.substring(16, 20) +
    "-" +
    aaguid.substring(20, 32);
  return aaguid; // example: "d41f5a69-b817-4144-a13c-9ebd6d9254d6"
}

function bufferToHex(buffer) {
  return [...new Uint8Array(buffer)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function parseBuffer(buffer) {
  return String.fromCharCode(...new Uint8Array(buffer));
}

module.exports = {
  parseAuthData,
  bufferToHex,
};
