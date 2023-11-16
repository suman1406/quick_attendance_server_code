const otpGenerator = require('otp-generator')

const generateOTP = () => {
    return otpGenerator.generate(6, {
        lowerCaseAlphabets: false, 
        upperCaseAlphabets: false, 
        specialChars: false,
        digits: true
    });
}

module.exports = generateOTP;