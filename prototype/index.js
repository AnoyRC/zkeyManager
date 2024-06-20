const ethers = require("ethers");
const sodium = require("libsodium-wrappers");
const { v4: uuidv4 } = require("uuid");

const encryptionKey = Uint8Array.from([
  13,
  25,
  64,
  46,
  137,
  195,
  83,
  89,
  62,
  177,
  101,
  54,
  154,
  9,
  54,
  196,
  177,
  128,
  189,
  43,
  15,
  58,
  95,
  86,
  247,
  177,
  53,
  117,
  175,
  120,
  116,
  62,
]);

const main = async () => {
  const wallet = ethers.Wallet.createRandom();
  const privateKey = wallet.privateKey.toString();
  console.log(`Derived Private Key: ${privateKey}`);

  await sodium.ready;

  const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);

  console.log(`Nonce: ${nonce}`);
  let cipherKey = sodium.crypto_secretbox_easy(
    privateKey,
    nonce,
    encryptionKey
  );
  console.log(`Encrypted Private Key: ${cipherKey}`);

  const bufferCipherKey = Buffer.from(cipherKey);
  const shardSize = Math.floor(bufferCipherKey.length / 3);
  const shard1 = {
    _id: uuidv4(),
    shard: bufferCipherKey.slice(0, shardSize),
  };
  const shard2 = {
    _id: uuidv4(),
    shard: bufferCipherKey.slice(shardSize, shardSize * 2),
  };
  const shard3 = {
    _id: uuidv4(),
    shard: bufferCipherKey.slice(shardSize * 2),
  };
  console.log("Shards:");
  console.log(shard1);
  console.log(shard2);
  console.log(shard3);

  const recoveredCipherKey = Buffer.concat([
    shard1.shard,
    shard2.shard,
    shard3.shard,
  ]);

  const recoveredPrivateKey = sodium.crypto_secretbox_open_easy(
    recoveredCipherKey,
    nonce,
    encryptionKey
  );

  console.log(
    `Recovered Private Key: ${Buffer.from(recoveredPrivateKey).toString()}`
  );
};

main();
