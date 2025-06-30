import nodemailer from "nodemailer";

// Environment configuration with validation
const MAIL_SERVICE = process.env.MAIL_SERVICE || "gmail";
const MAIL_USER = process.env.MAIL_USER;
const MAIL_PASSWORD = process.env.MAIL_PASSWORD;
const MAIL_FROM = process.env.MAIL_FROM;

// Validate environment variables
[MAIL_SERVICE, MAIL_USER, MAIL_PASSWORD, MAIL_FROM].forEach((secret) => {
  if (!secret) throw new Error(`${secret} environment variable is not defined`);
});

const transporter = nodemailer.createTransport({
  service: MAIL_SERVICE,
  pool: true,
  maxConnections: 5,
  maxMessages: Infinity,
  auth: {
    user: MAIL_USER,
    pass: MAIL_PASSWORD,
  },
  tls: {
    rejectUnauthorized: false,
  },
  connectionTimeout: 10_000,
  greetingTimeout: 5_000,
});

transporter.verify((error) => {
  if (error) {
    console.log("Connection error:", error);
  } else {
    console.log("Server is ready to take our messages");
  }
});

export async function sendEmail({ to, subject, text }) {
  try {
    const info = await transporter.sendMail({
      from: MAIL_FROM,
      to,
      subject,
      text,
    });
    console.log(`📧 Email sent: ${info.messageId} → ${to}`);
    return true;
  } catch (err) {
    console.log(`✉️ Failed to send to ${to}:`, err);
    return false;
  }
}
