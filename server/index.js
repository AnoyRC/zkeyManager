const express = require("express");
const dotenv = require("dotenv");
const cors = require("cors");

dotenv.config({ path: "./.env" });
const PORT = process.env.PORT || 5000;

const app = express();

app.use(cors());
app.use(express.json());

app.use("/api/generate", require("./routes/api/generate"));
app.use("/api/utils", require("./routes/api/utils"));
app.use("/api/recover", require("./routes/api/recover"));

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
