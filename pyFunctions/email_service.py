"""
Email service module using Resend API
Handles sending emails for password resets, notifications, etc.
"""
import os
import resend
from dotenv import load_dotenv

load_dotenv()

# Configure Resend API key
resend.api_key = os.getenv('RESEND_API_KEY')

def send_email(to_email: str, subject: str, html_content: str, from_email: str = None) -> dict:
    """
    Send an email using Resend API
    
    Args:
        to_email: Recipient email address
        subject: Email subject line
        html_content: HTML content of the email
        from_email: Sender email (defaults to RESEND_FROM_EMAIL env var)
    
    Returns:
        dict: Response from Resend API with 'success' and 'message' keys
    """
    if not resend.api_key:
        return {
            'success': False,
            'message': 'Resend API key not configured. Set RESEND_API_KEY in .env file'
        }
    
    if not from_email:
        from_email = os.getenv('RESEND_FROM_EMAIL', 'noreply@cybervantage.com')
    
    try:
        params = {
            "from": from_email,
            "to": [to_email],
            "subject": subject,
            "html": html_content,
        }
        
        response = resend.Emails.send(params)
        
        return {
            'success': True,
            'message': 'Email sent successfully',
            'id': response.get('id')
        }
    except Exception as e:
        return {
            'success': False,
            'message': f'Failed to send email: {str(e)}'
        }


def send_password_reset_email(to_email: str, reset_token: str, username: str) -> dict:
    """
    Send a password reset email with a reset link
    
    Args:
        to_email: User's email address
        reset_token: Password reset token
        username: User's username
    
    Returns:
        dict: Response from send_email function
    """
    app_url = os.getenv('APP_URL', 'http://localhost:5000').rstrip('/')
    reset_url = f"{app_url}/reset_password/{reset_token}"
    
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <style>
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                line-height: 1.6;
                color: #333;
                background-color: #f4f4f4;
                margin: 0;
                padding: 0;
            }}
            .container {{
                max-width: 600px;
                margin: 20px auto;
                background-color: #ffffff;
                border-radius: 8px;
                overflow: hidden;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }}
            .header {{
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                padding: 30px;
                text-align: center;
                color: #ffffff;
            }}
            .content {{
                padding: 40px 30px;
            }}
            .button {{
                display: inline-block;
                padding: 14px 28px;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: #ffffff;
                text-decoration: none;
                border-radius: 6px;
                margin: 20px 0;
                font-weight: bold;
            }}
            .footer {{
                background-color: #f8f9fa;
                padding: 20px;
                text-align: center;
                font-size: 12px;
                color: #6c757d;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🛡️ CyberVantage</h1>
                <p>Security Training Platform</p>
            </div>
            <div class="content">
                <h2>Password Reset Request</h2>
                <p>Hello {username},</p>
                <p>We received a request to reset your password for your CyberVantage account. Click the button below to reset your password:</p>
                <div style="text-align: center;">
                    <a href="{reset_url}" class="button">Reset Password</a>
                </div>
                <p>Or copy and paste this link into your browser:</p>
                <p style="word-break: break-all; color: #667eea;">{reset_url}</p>
                <p><strong>This link will expire in 1 hour.</strong></p>
                <p>If you didn't request a password reset, please ignore this email or contact support if you have concerns.</p>
            </div>
            <div class="footer">
                <p>© 2024 CyberVantage. All rights reserved.</p>
                <p>This is an automated email. Please do not reply.</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    return send_email(
        to_email=to_email,
        subject="CyberVantage - Password Reset Request",
        html_content=html_content
    )


def send_welcome_email(to_email: str, username: str) -> dict:
    """
    Send a welcome email to new users
    
    Args:
        to_email: User's email address
        username: User's username
    
    Returns:
        dict: Response from send_email function
    """
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <style>
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                line-height: 1.6;
                color: #333;
                background-color: #f4f4f4;
                margin: 0;
                padding: 0;
            }}
            .container {{
                max-width: 600px;
                margin: 20px auto;
                background-color: #ffffff;
                border-radius: 8px;
                overflow: hidden;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }}
            .header {{
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                padding: 30px;
                text-align: center;
                color: #ffffff;
            }}
            .content {{
                padding: 40px 30px;
            }}
            .feature {{
                margin: 20px 0;
                padding: 15px;
                background-color: #f8f9fa;
                border-left: 4px solid #667eea;
                border-radius: 4px;
            }}
            .footer {{
                background-color: #f8f9fa;
                padding: 20px;
                text-align: center;
                font-size: 12px;
                color: #6c757d;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🛡️ Welcome to CyberVantage!</h1>
            </div>
            <div class="content">
                <h2>Hello {username}! 👋</h2>
                <p>Thank you for joining CyberVantage - your journey to mastering cybersecurity starts now!</p>
                
                <div class="feature">
                    <h3>📚 Phase 1: Learn</h3>
                    <p>Start with interactive lessons about phishing, spam, and cyber safety.</p>
                </div>
                
                <div class="feature">
                    <h3>🎮 Phase 2: Simulate</h3>
                    <p>Practice identifying phishing emails in a safe environment.</p>
                </div>
                
                <div class="feature">
                    <h3>📊 Phase 3: Analysis</h3>
                    <p>Get personalized feedback and track your progress.</p>
                </div>
                
                <div class="feature">
                    <h3>🎯 Phase 4: Demonstrate</h3>
                    <p>Show your skills by creating your own phishing scenarios.</p>
                </div>
                
                <p><strong>Ready to get started?</strong> Log in to your dashboard and begin your cybersecurity training!</p>
            </div>
            <div class="footer">
                <p>© 2024 CyberVantage. All rights reserved.</p>
                <p>This is an automated email. Please do not reply.</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    return send_email(
        to_email=to_email,
        subject="Welcome to CyberVantage! 🛡️",
        html_content=html_content
    )


def send_notification_email(to_email: str, username: str, notification_type: str, message: str) -> dict:
    """
    Send a general notification email
    
    Args:
        to_email: User's email address
        username: User's username
        notification_type: Type of notification (e.g., 'Achievement', 'Reminder')
        message: Notification message content
    
    Returns:
        dict: Response from send_email function
    """
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <style>
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                line-height: 1.6;
                color: #333;
                background-color: #f4f4f4;
                margin: 0;
                padding: 0;
            }}
            .container {{
                max-width: 600px;
                margin: 20px auto;
                background-color: #ffffff;
                border-radius: 8px;
                overflow: hidden;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }}
            .header {{
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                padding: 30px;
                text-align: center;
                color: #ffffff;
            }}
            .content {{
                padding: 40px 30px;
            }}
            .footer {{
                background-color: #f8f9fa;
                padding: 20px;
                text-align: center;
                font-size: 12px;
                color: #6c757d;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🛡️ CyberVantage</h1>
                <p>{notification_type}</p>
            </div>
            <div class="content">
                <p>Hello {username},</p>
                {message}
            </div>
            <div class="footer">
                <p>© 2024 CyberVantage. All rights reserved.</p>
                <p>This is an automated email. Please do not reply.</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    return send_email(
        to_email=to_email,
        subject=f"CyberVantage - {notification_type}",
        html_content=html_content
    )


def send_otp_email(to_email: str, otp: str, username: str) -> dict:
    """
    Send an OTP email for password reset
    
    Args:
        to_email: User's email address
        otp: 6-digit OTP code
        username: User's username
    
    Returns:
        dict: Response from send_email function
    """
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <style>
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                line-height: 1.6;
                color: #333;
                background-color: #f4f4f4;
                margin: 0;
                padding: 0;
            }}
            .container {{
                max-width: 600px;
                margin: 20px auto;
                background-color: #ffffff;
                border-radius: 8px;
                overflow: hidden;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }}
            .header {{
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                padding: 30px;
                text-align: center;
                color: #ffffff;
            }}
            .content {{
                padding: 40px 30px;
                text-align: center;
            }}
            .otp-box {{
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: #ffffff;
                font-size: 32px;
                font-weight: bold;
                letter-spacing: 8px;
                padding: 20px;
                border-radius: 8px;
                margin: 30px 0;
                font-family: 'Courier New', monospace;
            }}
            .warning {{
                background-color: #fff3cd;
                border-left: 4px solid #ffc107;
                padding: 15px;
                margin: 20px 0;
                border-radius: 4px;
                text-align: left;
            }}
            .footer {{
                background-color: #f8f9fa;
                padding: 20px;
                text-align: center;
                font-size: 12px;
                color: #6c757d;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🛡️ CyberVantage</h1>
                <p>Password Reset Verification</p>
            </div>
            <div class="content">
                <h2>Password Reset OTP</h2>
                <p>Hello {username},</p>
                <p>You requested to reset your password. Use the OTP code below to complete the process:</p>
                
                <div class="otp-box">{otp}</div>
                
                <p><strong>This code will expire in 15 minutes.</strong></p>
                
                <div class="warning">
                    <p style="margin: 0;"><strong>⚠️ Security Notice:</strong></p>
                    <p style="margin: 5px 0 0 0;">Never share this code with anyone. CyberVantage staff will never ask for your OTP.</p>
                </div>
                
                <p>If you didn't request a password reset, please ignore this email or contact support immediately if you have concerns.</p>
            </div>
            <div class="footer">
                <p>© 2024 CyberVantage. All rights reserved.</p>
                <p>This is an automated email. Please do not reply.</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    return send_email(
        to_email=to_email,
        subject="CyberVantage - Password Reset OTP",
        html_content=html_content
    )
