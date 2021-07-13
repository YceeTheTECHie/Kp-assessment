const express = require('express');
const user = require('./models/user');
const app = express();
const userRoute = require("./routes/user");



app.use(express.json());
app.use("/user", userRoute);
module.exports = app