const RESEND_API_URL = 'https://api.resend.com/emails';

function isEmailConfigured() {
  return Boolean(process.env.RESEND_API_KEY && process.env.EMAIL_FROM);
}

async function sendVerificationEmail(to, code) {
  if (!isEmailConfigured()) {
    const err = new Error('Email provider is not configured.');
    err.code = 'EMAIL_NOT_CONFIGURED';
    throw err;
  }

  const response = await fetch(RESEND_API_URL, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${process.env.RESEND_API_KEY}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      from: process.env.EMAIL_FROM,
      to,
      subject: 'رمز التحقق لحرفتي',
      html: `<div dir="rtl" style="font-family:Arial,Tahoma,sans-serif;line-height:1.8">
        <h2>رمز التحقق لحرفتي</h2>
        <p>استخدم الرمز التالي لتأكيد بريدك الاحتياطي:</p>
        <p style="font-size:28px;font-weight:800;letter-spacing:4px">${code}</p>
        <p>ينتهي الرمز خلال 10 دقائق. إذا لم تطلب هذا الرمز، تجاهل الرسالة.</p>
      </div>`,
      text: `رمز التحقق لحرفتي هو: ${code}\nينتهي الرمز خلال 10 دقائق.`
    })
  });

  if (!response.ok) {
    const body = await response.text();
    const err = new Error(`Email provider rejected the message: ${response.status}`);
    err.code = 'EMAIL_SEND_FAILED';
    err.providerResponse = body.slice(0, 500);
    throw err;
  }

  return response.json();
}

module.exports = {
  isEmailConfigured,
  sendVerificationEmail
};
