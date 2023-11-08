const express = require('express');
const server = express();
const establishConnection = require("./initializeConnection");
require('dotenv').config();
const { generateKey } = require('./RSA/keyGen');
const fs = require('fs');

const PORT = process.env.PORT;

