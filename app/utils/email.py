import asyncio
import html as html_lib
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


    async def send_async(
        self,
        to_email: str,
        subject: str,
        plain_text: Optional[str] = None,
        html_content: Optional[str] = None,
    ) -> bool:
        """SMTP is blocking — run it off the event loop."""
        return await asyncio.to_thread(
            self.send, to_email, subject, plain_text, html_content
        )


    def send_background(
        self,
        to_email: str,
        subject: str,
        plain_text: Optional[str] = None,
        html_content: Optional[str] = None,
    ) -> None:
        """Fire-and-forget. Responses must not wait on SMTP: the wait would
        reveal which addresses exist (enumeration by timing)."""
        task = asyncio.get_running_loop().create_task(
            self.send_async(to_email, subject, plain_text, html_content)
        )
        _background_tasks.add(task)
        task.add_done_callback(_background_tasks.discard)


_background_tasks: set[asyncio.Task] = set()

email_service = EmailService()


def _e(value: str) -> str:
    return html_lib.escape(value, quote=True)


def _layout(title: str, body_html: str) -> str:
    return f"""
    <div style="font-family:sans-serif;background:#0a192f;color:#ccd6f6;padding:24px">
      <h2 style="color:#64ffda">{_e(title)}</h2>
      {body_html}
    </div>
    """


def _button(link: str, label: str) -> str:
    return (
        f'<p><a href="{_e(link)}" style="background:#64ffda;color:#0a192f;padding:12px 20px;'
        f'border-radius:8px;text-decoration:none;font-weight:600">{_e(label)}</a></p>'
        f'<p style="color:#8892b0;font-size:12px">Or paste: {_e(link)}</p>'
    )


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
      <p>Confirm changing your account email to <strong>{_e(new_email)}</strong>.</p>
      <p><a href="{link}" style="background:#64ffda;color:#0a192f;padding:12px 20px;border-radius:8px;text-decoration:none;font-weight:600">Confirm</a></p>
    </div>
    """
    return subject, plain, html


def admin_reset_link_email(link: str) -> tuple[str, str, str]:
    subject = "An administrator reset your password"
    plain = (
        "An administrator reset your password and signed you out everywhere.\n\n"
        f"Choose a new password with this link (single use):\n\n{link}"
    )
    html = _layout(
        "Choose a new password",
        "<p>An administrator reset your password and signed you out everywhere.</p>"
        + _button(link, "Choose new password"),
    )
    return subject, plain, html


def new_device_email(device: str, ip: str, when: str, sessions_link: str) -> tuple[str, str, str]:
    subject = "New sign-in to your account"
    plain = (
        f"Your account was just signed in from a new device.\n\n"
        f"Device: {device}\nIP address: {ip}\nTime: {when}\n\n"
        f"If this wasn't you, change your password and sign out other sessions:\n{sessions_link}"
    )
    html = _layout(
        "New sign-in",
        f"<p>Your account was just signed in from a new device.</p>"
        f"<p>Device: <strong>{_e(device)}</strong><br>IP address: {_e(ip)}<br>Time: {_e(when)}</p>"
        "<p>If this wasn't you, change your password and sign out other sessions.</p>"
        + _button(sessions_link, "Review sessions"),
    )
    return subject, plain, html


def password_changed_email(sessions_link: str) -> tuple[str, str, str]:
    subject = "Your password was changed"
    plain = (
        "Your password was just changed and other sessions were signed out.\n\n"
        f"If this wasn't you, reset your password immediately:\n{sessions_link}"
    )
    html = _layout(
        "Password changed",
        "<p>Your password was just changed and other sessions were signed out.</p>"
        "<p>If this wasn't you, reset your password immediately.</p>"
        + _button(sessions_link, "Review account"),
    )
    return subject, plain, html


def email_change_requested_notice(new_email: str) -> tuple[str, str, str]:
    subject = "Email change requested"
    plain = (
        f"Someone requested to change your account email to {new_email}.\n\n"
        "Nothing changes until the new address is confirmed. If this wasn't you, "
        "change your password now."
    )
    html = _layout(
        "Email change requested",
        f"<p>Someone requested to change your account email to <strong>{_e(new_email)}</strong>.</p>"
        "<p>Nothing changes until the new address is confirmed. If this wasn't you, change your password now.</p>",
    )
    return subject, plain, html


def email_changed_notice(new_email: str) -> tuple[str, str, str]:
    subject = "Your account email was changed"
    plain = (
        f"Your account email was changed to {new_email} and all sessions were signed out.\n\n"
        "If this wasn't you, contact the site owner immediately."
    )
    html = _layout(
        "Account email changed",
        f"<p>Your account email was changed to <strong>{_e(new_email)}</strong> and all sessions were signed out.</p>"
        "<p>If this wasn't you, contact the site owner immediately.</p>",
    )
    return subject, plain, html


def signup_existing_account_email(login_link: str, reset_link: str) -> tuple[str, str, str]:
    subject = "Sign-up attempt for your account"
    plain = (
        "Someone tried to create an account with this email, but you already have one.\n\n"
        f"Sign in: {login_link}\nForgot your password? {reset_link}\n\n"
        "If this wasn't you, you can ignore this email."
    )
    html = _layout(
        "You already have an account",
        "<p>Someone tried to create an account with this email, but you already have one.</p>"
        + _button(login_link, "Sign in")
        + f'<p><a href="{_e(reset_link)}" style="color:#64ffda">Forgot your password?</a></p>'
        "<p style=\"color:#8892b0\">If this wasn't you, you can ignore this email.</p>",
    )
    return subject, plain, html


def email_in_use_notice() -> tuple[str, str, str]:
    subject = "Someone tried to use your email address"
    plain = (
        "Someone with another account tried to change its email to this address. "
        "Nothing was changed. If you know why, you can ignore this email."
    )
    html = _layout(
        "Your address was requested",
        "<p>Someone with another account tried to change its email to this address.</p>"
        "<p>Nothing was changed. If you know why, you can ignore this email.</p>",
    )
    return subject, plain, html
