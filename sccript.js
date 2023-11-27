const crypto = require('crypto');


const passwordHashed = crypto.createHash('sha256').update(managerPassword).digest('hex');


console.log(passwordHashed)