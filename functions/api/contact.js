import { SESClient, SendEmailCommand } from '@aws-sdk/client-ses';

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

    // Validate required fields
    if (!name || !email || !message) {
      return new Response(JSON.stringify({
        success: false,
        message: 'Please fill in all required fields.',
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // Validate Turnstile token
    if (!turnstileToken) {
      return new Response(JSON.stringify({
        success: false,
        message: 'CAPTCHA verification required. Please try again.',
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    const turnstileResult = await verifyTurnstileToken(
      turnstileToken,
      context.request.headers.get('CF-Connecting-IP'),
      context,
    );

    if (!turnstileResult.success) {
      return new Response(JSON.stringify({
        success: false,
        message: 'CAPTCHA verification failed. Please try again.',
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // Send email via SES
    const sesClient = new SESClient({
      region: context.env.AWS_REGION,
      credentials: {
        accessKeyId: context.env.AWS_ACCESS_KEY_ID,
        secretAccessKey: context.env.AWS_SECRET_ACCESS_KEY,
      },
    });

    const emailParams = {
      Source: context.env.FROM_EMAIL_ADDRESS,
      Destination: {
        ToAddresses: [context.env.TO_EMAIL_ADDRESS],
      },
      Message: {
        Subject: {
          Data: `New Enquiry from ${name} — JMC Environmental`,
          Charset: 'UTF-8',
        },
        Body: {
          Text: {
            Data: `
New Contact Form Submission
===========================

Name: ${name}
Email: ${email}
Company: ${company}
Phone: ${phone}
Service: ${service}

Message:
${message}
            `.trim(),
            Charset: 'UTF-8',
          },
          Html: {
            Data: `
<div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
  <h2 style="color: #0a1628; border-bottom: 2px solid #1e3a5f; padding-bottom: 10px;">New Contact Form Submission</h2>
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
</div>
            `.trim(),
            Charset: 'UTF-8',
          },
        },
      },
    };

    const command = new SendEmailCommand(emailParams);
    await sesClient.send(command);

    return new Response(JSON.stringify({
      success: true,
      message: 'Form submitted successfully.',
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });

  } catch (error) {
    console.error('Error processing form submission:', error);

    return new Response(JSON.stringify({
      success: false,
      message: 'An error occurred while processing your request. Please try again.',
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
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
