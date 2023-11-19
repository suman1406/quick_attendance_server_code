const TEMPLATE_OTP = (otp, userName) => {
    return `<!DOCTYPE html>
    <html lang="en">

    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Amrita Quick Attendance OTP</title>
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
        </style>
    </head>

    <body>
        <p>Dear ${userName},</p>
        <br />
        <p>Thank you for registering with Amrita Quick Attendance App. Please use the following OTP to verify your account.</p>
        <br />
        <h1>${otp}</h1>
        <br />
        <p>Regards,</p>
        <p>Amrita Quick Attendance App</p>
    </body>

    </html>`;
}

module.exports = TEMPLATE_OTP;