const ethers = require("ethers");
const { bufferToHex } = require("./webauthn.js");

function hashPasskey(aaguid, rpIdHash, credentialId) {
  var encoder = new TextEncoder();

  const aaguidBuffer = encoder.encode(aaguid.split("-")[0]).buffer;
  const rpIdHashBuffer = encoder.encode(rpIdHash).buffer;

  const addedBuffer = concatenateBuffers(aaguidBuffer, rpIdHashBuffer);
  const BufferHex = bufferToHex(addedBuffer);

  const credentialIdHex = ethers.utils.hexlify(
    ethers.utils.toUtf8Bytes(credentialId)
  );

  const sha256BufferHex = ethers.utils.sha256(
    ethers.utils.arrayify("0x" + BufferHex)
  );

  const concatenatedHex = sha256BufferHex + credentialIdHex.slice(2);

  const finalHash = ethers.utils.sha256(ethers.utils.arrayify(concatenatedHex));

  return finalHash;
}

function hash(x, y, z) {
  var encoder = new TextEncoder();

  const xBuffer = encoder.encode(x).buffer;
  const yBuffer = encoder.encode(y).buffer;

  const addedBuffer = concatenateBuffers(xBuffer, yBuffer);
  const BufferHex = bufferToHex(addedBuffer);

  const zHex = ethers.utils.hexlify(ethers.utils.toUtf8Bytes(z));

  const sha256BufferHex = ethers.utils.sha256(
    ethers.utils.arrayify("0x" + BufferHex)
  );

  const concatenatedHex = sha256BufferHex + zHex.slice(2);

  const finalHash = ethers.utils.sha256(ethers.utils.arrayify(concatenatedHex));

  return finalHash;
}

function concatenateBuffers(buffer1, buffer2) {
  let tmp = new Uint8Array(buffer1.byteLength + buffer2.byteLength);
  tmp.set(new Uint8Array(buffer1), 0);
  tmp.set(new Uint8Array(buffer2), buffer1.byteLength);
  return tmp;
}

module.exports = { hashPasskey, hash };
