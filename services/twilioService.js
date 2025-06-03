const twilio = require('twilio');

const client = twilio(process.env.TWILIO_SID, process.env.TWILIO_AUTH_TOKEN);

const sendSMSOTP = async (to, otp) => {
  await client.messages.create({
    body: `Your OTP code is: ${otp}`,
    from: process.env.TWILIO_PHONE,
    to: to,
  });
};

module.exports = sendSMSOTP;
