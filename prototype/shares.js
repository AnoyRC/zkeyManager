const { split, join } = require("shamir");
const { randomBytes } = require("crypto");

const secret = "This is a secret message.";

const utf8Encoder = new TextEncoder();
const utf8Decoder = new TextDecoder();
const secretBytes = utf8Encoder.encode(secret);

const nonce = "anoy.fusion.id";

let nonceAdditive = nonce.length;
const customRndBytes = () => {
  const nonceBytes = utf8Encoder.encode(nonce);

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

const shares = split(customRndBytes, 5, 3, secretBytes);
console.log(shares);

const recoveredSecret = join({
  1: shares["1"],
  2: shares["4"],
  3: shares["5"],
});
console.log(utf8Decoder.decode(recoveredSecret));
