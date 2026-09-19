import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional

from app.config import email_settings

logger = logging.getLogger(__name__)


class EmailService:
    def __init__(self) -> None:
        self.smtp_host = email_settings.SMTP_HOST
        self.smtp_port = email_settings.SMTP_PORT
        self.smtp_username = email_settings.SMTP_USERNAME
        self.smtp_password = email_settings.SMTP_PASSWORD
        self.from_email = email_settings.SMTP_FROM_EMAIL or email_settings.SMTP_USERNAME
        self.from_name = email_settings.SMTP_FROM_NAME

    def send(
        self,
        to_email: str,
        subject: str,
        plain_text: Optional[str] = None,
        html_content: Optional[str] = None,
    ) -> bool:
        if not plain_text and not html_content:
            logger.error("Either plain_text or html_content must be provided")
            return False

        if not self.smtp_username or not self.smtp_password:
            logger.warning(
                "SMTP credentials missing — email to %s skipped (subject: %s)",
                to_email,
                subject,
            )
            logger.info("Email body (dev):\n%s", plain_text or html_content)
            return False

        try:
            message = MIMEMultipart("alternative")
            message["Subject"] = subject
            message["From"] = f"{self.from_name} <{self.from_email}>"
            message["To"] = to_email

            if plain_text:
                message.attach(MIMEText(plain_text, "plain"))
            if html_content:
                message.attach(MIMEText(html_content, "html"))

            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                server.starttls()
                server.login(self.smtp_username, self.smtp_password)
                server.send_message(message)

            logger.info("Email sent successfully to %s", to_email)
            return True
        except Exception as e:
            logger.error("Failed to send email to %s: %s", to_email, e)
            return False


email_service = EmailService()


def verification_email(link: str) -> tuple[str, str, str]:
    subject = "Verify your email"
    plain = f"Verify your email by opening this link:\n\n{link}\n\nIf you did not sign up, ignore this email."
    html = f"""
    <div style="font-family:sans-serif;background:#0a192f;color:#ccd6f6;padding:24px">
      <h2 style="color:#64ffda">Verify your email</h2>
      <p>Click the button below to verify your account.</p>
      <p><a href="{link}" style="background:#64ffda;color:#0a192f;padding:12px 20px;border-radius:8px;text-decoration:none;font-weight:600">Verify email</a></p>
      <p style="color:#8892b0;font-size:12px">Or paste: {link}</p>
    </div>
    """
    return subject, plain, html


def password_reset_email(link: str) -> tuple[str, str, str]:
    subject = "Reset your password"
    plain = f"Reset your password using this link (expires soon):\n\n{link}\n\nIf you did not request this, ignore this email."
    html = f"""
    <div style="font-family:sans-serif;background:#0a192f;color:#ccd6f6;padding:24px">
      <h2 style="color:#64ffda">Reset your password</h2>
      <p>Click below to choose a new password.</p>
      <p><a href="{link}" style="background:#64ffda;color:#0a192f;padding:12px 20px;border-radius:8px;text-decoration:none;font-weight:600">Reset password</a></p>
      <p style="color:#8892b0;font-size:12px">Or paste: {link}</p>
    </div>
    """
    return subject, plain, html


def email_change_email(link: str, new_email: str) -> tuple[str, str, str]:
    subject = "Confirm your new email"
    plain = f"Confirm changing your account email to {new_email}:\n\n{link}"
    html = f"""
    <div style="font-family:sans-serif;background:#0a192f;color:#ccd6f6;padding:24px">
      <h2 style="color:#64ffda">Confirm email change</h2>
      <p>Confirm changing your account email to <strong>{new_email}</strong>.</p>
      <p><a href="{link}" style="background:#64ffda;color:#0a192f;padding:12px 20px;border-radius:8px;text-decoration:none;font-weight:600">Confirm</a></p>
    </div>
    """
    return subject, plain, html


def admin_temp_password_email(temp_password: str) -> tuple[str, str, str]:
    subject = "Your password was reset by an administrator"
    plain = (
        f"An administrator reset your password.\n\n"
        f"Temporary password: {temp_password}\n\n"
        f"Sign in and change it immediately."
    )
    html = f"""
    <div style="font-family:sans-serif;background:#0a192f;color:#ccd6f6;padding:24px">
      <h2 style="color:#64ffda">Password reset by admin</h2>
      <p>Temporary password:</p>
      <p style="font-size:18px;letter-spacing:1px"><code>{temp_password}</code></p>
      <p style="color:#8892b0">Sign in and change it as soon as possible.</p>
    </div>
    """
    return subject, plain, html
