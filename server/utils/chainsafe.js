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

    const res1 = await axios.post(
      `https://api.chainsafe.io/api/v1/bucket/${bucketID}/upload`,
      file,
      { headers }
    );

    return res1.data;
  } catch (error) {
    throw new Error(error.message);
  }
};

module.exports = {
  addToChainSafe,
};
