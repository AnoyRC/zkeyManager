const axios = require("axios");
require("dotenv").config();

const addToChainSafe = async (shard) => {
  try {
    const bucketID = "9b794f51-c830-411a-ab85-4a628d33b4b3";

    const headers = {
      Authorization: `Bearer ${process.env.CHAINSAFE_API_KEY}`,
      "Content-Type": "multipart/form-data",
    };

    const file = new FormData();

    const blob = new Blob([JSON.stringify(shard)], {
      type: "application/json",
    });

    file.append("file", blob, "shard.json");
    file.append("path", `/${shard._id}/`);

    const res = await axios.post(
      `https://api.chainsafe.io/api/v1/bucket/${bucketID}/upload`,
      file,
      { headers }
    );

    if (res.data.files_details[0].status !== "success")
      throw new Error(res.data.error_code);

    return res.data;
  } catch (error) {
    console.log(error);
    throw new Error(error.message);
  }
};

const precheck = async (shard) => {
  try {
    const bucketID = "9b794f51-c830-411a-ab85-4a628d33b4b3";

    const headers = {
      Authorization: `Bearer ${process.env.CHAINSAFE_API_KEY}`,
    };

    const body = {
      is_update: false,
      files_meta: [
        {
          path: `/${shard._id}/shard.json`,
        },
      ],
    };

    const res = await axios.post(
      `https://api.chainsafe.io/api/v1/bucket/${bucketID}/check-upload`,
      body,
      { headers }
    );

    if (res.data.status !== "success") throw new Error(res.data.error_code);

    return res.data;
  } catch (error) {
    throw new Error(error.message);
  }
};

const getFile = async (shardID) => {
  try {
    const bucketID = "9b794f51-c830-411a-ab85-4a628d33b4b3";

    const headers = {
      Authorization: `Bearer ${process.env.CHAINSAFE_API_KEY}`,
      "Content-Type": "application/json",
    };

    const body = {
      path: `/${shardID}/shard.json`,
    };

    const res = await axios.post(
      `https://api.chainsafe.io/api/v1/bucket/${bucketID}/download`,
      body,
      { headers }
    );

    if (!res.data.shard) throw new Error("Shard not found");

    return res.data;
  } catch (error) {
    throw new Error(error.message);
  }
};

const addPasskeyToChainSafe = async (registration) => {
  try {
    const bucketID = "dd0a45bd-51c9-4789-923b-b9b5255a2d28";

    const headers = {
      Authorization: `Bearer ${process.env.CHAINSAFE_API_KEY}`,
      "Content-Type": "multipart/form-data",
    };

    const file = new FormData();

    const blob = new Blob([JSON.stringify(registration)], {
      type: "application/json",
    });

    file.append("file", blob, "credential.json");
    file.append("path", `/${registration.id}/`);

    const res = await axios.post(
      `https://api.chainsafe.io/api/v1/bucket/${bucketID}/upload`,
      file,
      { headers }
    );

    if (res.data.files_details[0].status !== "success")
      throw new Error(res.data.error_code);

    return res.data;
  } catch (error) {
    throw new Error(error.message);
  }
};

const getPasskey = async (credentialId) => {
  try {
    const bucketID = "dd0a45bd-51c9-4789-923b-b9b5255a2d28";

    const headers = {
      Authorization: `Bearer ${process.env.CHAINSAFE_API_KEY}`,
      "Content-Type": "application/json",
    };

    const body = {
      path: `/${credentialId}/credential.json`,
    };

    const res = await axios.post(
      `https://api.chainsafe.io/api/v1/bucket/${bucketID}/download`,
      body,
      { headers }
    );

    if (!res.data.id) throw new Error("Passkey not found");

    return res.data;
  } catch (error) {
    throw new Error(error.message);
  }
};

module.exports = {
  addToChainSafe,
  precheck,
  getFile,
  addPasskeyToChainSafe,
  getPasskey,
};
