export async function onRequestPost(context) {
  try {
    const formData = await context.request.formData();

    const name = formData.get('full-name');
    const email = formData.get('email');
    const company = formData.get('company') || 'Not provided';
    const phone = formData.get('phone') || 'Not provided';
    const service = formData.get('service') || 'Not specified';
    const message = formData.get('message');
    const turnstileToken = formData.get('cf-turnstile-response');

    if (!name || !email || !message) {
      return jsonResponse({ success: false, message: 'Missing required fields' }, 400);
    }

    if (!turnstileToken) {
      return jsonResponse({ success: false, message: 'CAPTCHA verification failed' }, 400);
    }

    const turnstileVerification = await verifyTurnstileToken(
      turnstileToken,
      context.request.headers.get('CF-Connecting-IP'),
      context
    );

    if (!turnstileVerification.success) {
      return jsonResponse({ success: false, message: 'CAPTCHA verification failed' }, 400);
    }

    const region = context.env.AWS_REGION;
    const accessKeyId = context.env.AWS_ACCESS_KEY_ID;
    const secretAccessKey = context.env.AWS_SECRET_ACCESS_KEY;
    const fromAddress = context.env.FROM_EMAIL_ADDRESS;
    const toAddress = context.env.TO_EMAIL_ADDRESS;

    if (!region || !accessKeyId || !secretAccessKey || !fromAddress || !toAddress) {
      console.error('Missing env vars:', {
        AWS_REGION: !!region,
        AWS_ACCESS_KEY_ID: !!accessKeyId,
        AWS_SECRET_ACCESS_KEY: !!secretAccessKey,
        FROM_EMAIL_ADDRESS: !!fromAddress,
        TO_EMAIL_ADDRESS: !!toAddress,
      });
      return jsonResponse({ success: false, message: 'Server configuration error. Please contact us directly at info@jmcenvironmental.ie.' }, 500);
    }

    const textBody = `Name: ${name}\nEmail: ${email}\nCompany: ${company}\nPhone: ${phone}\nService: ${service}\nMessage: ${message}`;
    const htmlBody = `<div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
<h2 style="color: #0a1628; border-bottom: 2px solid #1e3a5f; padding-bottom: 10px;">New Enquiry — JMC Environmental</h2>
<table style="width: 100%; border-collapse: collapse;">
<tr><td style="padding: 8px 0; color: #666; width: 100px;"><strong>Name:</strong></td><td style="padding: 8px 0;">${name}</td></tr>
<tr><td style="padding: 8px 0; color: #666;"><strong>Email:</strong></td><td style="padding: 8px 0;"><a href="mailto:${email}">${email}</a></td></tr>
<tr><td style="padding: 8px 0; color: #666;"><strong>Company:</strong></td><td style="padding: 8px 0;">${company}</td></tr>
<tr><td style="padding: 8px 0; color: #666;"><strong>Phone:</strong></td><td style="padding: 8px 0;">${phone}</td></tr>
<tr><td style="padding: 8px 0; color: #666;"><strong>Service:</strong></td><td style="padding: 8px 0;">${service}</td></tr>
</table>
<div style="margin-top: 20px; padding: 15px; background: #f5f5f5; border-left: 3px solid #1e3a5f;">
<strong>Message:</strong><br><br>${message.replace(/\n/g, '<br>')}
</div>
<p style="margin-top: 20px; font-size: 12px; color: #999;">Sent from jmcenvironmental.ie contact form</p>
</div>`;

    const params = new URLSearchParams();
    params.append('Action', 'SendEmail');
    params.append('Source', fromAddress);
    params.append('Destination.ToAddresses.member.1', toAddress);
    params.append('Message.Subject.Data', `New Enquiry from ${name} — JMC Environmental`);
    params.append('Message.Subject.Charset', 'UTF-8');
    params.append('Message.Body.Text.Data', textBody);
    params.append('Message.Body.Text.Charset', 'UTF-8');
    params.append('Message.Body.Html.Data', htmlBody);
    params.append('Message.Body.Html.Charset', 'UTF-8');
    params.append('Version', '2010-12-01');

    const endpoint = `https://email.${region}.amazonaws.com/`;
    const now = new Date();
    const amzDate = now.toISOString().replace(/[-:]/g, '').replace(/\.\d{3}/, '');
    const dateStamp = amzDate.slice(0, 8);

    const body = params.toString();
    const bodyHash = await sha256Hex(body);

    const canonicalHeaders = `content-type:application/x-www-form-urlencoded\nhost:email.${region}.amazonaws.com\nx-amz-date:${amzDate}\n`;
    const signedHeaders = 'content-type;host;x-amz-date';
    const canonicalRequest = `POST\n/\n\n${canonicalHeaders}\n${signedHeaders}\n${bodyHash}`;

    const credentialScope = `${dateStamp}/${region}/ses/aws4_request`;
    const stringToSign = `AWS4-HMAC-SHA256\n${amzDate}\n${credentialScope}\n${await sha256Hex(canonicalRequest)}`;

    const signingKey = await getSignatureKey(secretAccessKey, dateStamp, region, 'ses');
    const signature = await hmacHex(signingKey, stringToSign);

    const authHeader = `AWS4-HMAC-SHA256 Credential=${accessKeyId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

    const sesResponse = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-Amz-Date': amzDate,
        'Authorization': authHeader,
      },
      body,
    });

    if (!sesResponse.ok) {
      const errorText = await sesResponse.text();
      console.error('SES error:', sesResponse.status, errorText);
      return jsonResponse({ success: false, message: 'Something went wrong. Please try again or email us directly at info@jmcenvironmental.ie.' }, 500);
    }

    return jsonResponse({ success: true, message: 'Form submitted successfully' });

  } catch (error) {
    console.error('Contact form error:', error?.name, error?.message, error?.stack);
    return jsonResponse({ success: false, message: 'Something went wrong. Please try again or email us directly at info@jmcenvironmental.ie.' }, 500);
  }
}

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

async function verifyTurnstileToken(token, ip, context) {
  try {
    const formData = new FormData();
    formData.append('secret', context.env.TURNSTILE_SECRET_KEY);
    formData.append('response', token);
    if (ip) {
      formData.append('remoteip', ip);
    }

    const result = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      body: formData,
    });

    return await result.json();
  } catch (error) {
    console.error('Turnstile verification error:', error);
    return { success: false, error: 'Verification failed' };
  }
}

async function sha256Hex(message) {
  const encoder = new TextEncoder();
  const data = encoder.encode(message);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return arrayBufferToHex(hash);
}

async function hmac(key, message) {
  const encoder = new TextEncoder();
  const keyData = typeof key === 'string' ? encoder.encode(key) : key;
  const cryptoKey = await crypto.subtle.importKey('raw', keyData, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return await crypto.subtle.sign('HMAC', cryptoKey, encoder.encode(message));
}

async function hmacHex(key, message) {
  const result = await hmac(key, message);
  return arrayBufferToHex(result);
}

async function getSignatureKey(secretKey, dateStamp, region, service) {
  const kDate = await hmac('AWS4' + secretKey, dateStamp);
  const kRegion = await hmac(kDate, region);
  const kService = await hmac(kRegion, service);
  return await hmac(kService, 'aws4_request');
}

function arrayBufferToHex(buffer) {
  return [...new Uint8Array(buffer)].map(b => b.toString(16).padStart(2, '0')).join('');
}
