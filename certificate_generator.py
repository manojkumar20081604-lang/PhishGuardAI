from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader
from datetime import datetime
import io
import os

class CertificateGenerator:
    def __init__(self):
        self.primary_color = colors.HexColor('#00d4ff')
        self.secondary_color = colors.HexColor('#7c3aed')
        self.gold_color = colors.HexColor('#ffd700')
        self.dark_bg = colors.HexColor('#0f0f23')
        
    def generate_certificate(self, user_name, quiz_score, total_questions, date=None):
        buffer = io.BytesIO()
        
        c = canvas.Canvas(buffer, pagesize=landscape(A4))
        width, height = landscape(A4)
        
        if date is None:
            date = datetime.now().strftime('%B %d, %Y')
        
        c.setFillColor(self.dark_bg)
        c.rect(0, 0, width, height, fill=True)
        
        c.setStrokeColor(self.primary_color)
        c.setLineWidth(3)
        c.roundRect(30, 30, width-60, height-60, 20, stroke=True)
        
        c.setStrokeColor(self.secondary_color)
        c.setLineWidth(2)
        c.roundRect(40, 40, width-80, height-80, 15, stroke=True)
        
        c.setFillColor(self.primary_color)
        c.setFont("Helvetica-Bold", 12)
        c.drawCentredString(width/2, height - 80, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        
        c.setFillColor(self.gold_color)
        c.setFont("Helvetica-Bold", 10)
        c.drawCentredString(width/2, height - 110, "★ ★ ★ CERTIFICATE OF ACHIEVEMENT ★ ★ ★")
        
        c.setFillColor(self.primary_color)
        c.setFont("Helvetica-Bold", 8)
        c.drawCentredString(width/2, height - 140, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        
        c.setFillColor(colors.white)
        c.setFont("Helvetica", 16)
        c.drawCentredString(width/2, height - 190, "This is to certify that")
        
        c.setFillColor(self.gold_color)
        c.setFont("Helvetica-Bold", 36)
        name_width = c.stringWidth(user_name, "Helvetica-Bold", 36)
        c.drawCentredString(width/2, height - 250, user_name)
        
        c.setStrokeColor(self.primary_color)
        c.setLineWidth(1)
        c.line(width/2 - name_width/2 - 20, height - 260, width/2 + name_width/2 + 20, height - 260)
        
        c.setFillColor(colors.white)
        c.setFont("Helvetica", 14)
        c.drawCentredString(width/2, height - 295, "has successfully completed the")
        
        c.setFillColor(self.primary_color)
        c.setFont("Helvetica-Bold", 22)
        c.drawCentredString(width/2, height - 330, "PHISHING DETECTION EXPERT TRAINING")
        
        percentage = (quiz_score / total_questions * 100) if total_questions > 0 else 0
        
        c.setFillColor(colors.white)
        c.setFont("Helvetica", 14)
        c.drawCentredString(width/2, height - 370, f"by scoring {quiz_score}/{total_questions} ({percentage:.0f}%) in the Cyber Security Quiz")
        
        c.setFont("Helvetica", 12)
        c.drawCentredString(width/2, height - 400, "Demonstrating knowledge in Phishing Detection, Email Security,")
        c.drawCentredString(width/2, height - 418, "URL Safety, and Social Engineering Awareness")
        
        c.setFillColor(self.secondary_color)
        c.setFont("Helvetica-Bold", 10)
        c.drawCentredString(width/2, height - 460, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        
        c.setFillColor(colors.lightgrey)
        c.setFont("Helvetica", 10)
        c.drawCentredString(width/2, 85, f"Certificate ID: CERT-{hash(user_name) % 100000:05d}-{datetime.now().strftime('%Y%m%d')}")
        c.drawCentredString(width/2, 70, f"Issued on: {date}")
        c.drawCentredString(width/2, 55, "PhishGuard - AI Phishing Detection System | www.phishguard.com")
        
        c.setFillColor(self.primary_color)
        c.setFont("Helvetica-Bold", 10)
        c.drawString(100, 70, "_______________________")
        c.drawString(100, 55, "Authorized Signature")
        
        c.drawRightString(width - 100, 70, "_______________________")
        c.drawRightString(width - 100, 55, "System Verified")
        
        shield_x = width/2 - 15
        shield_y = height/2 - 100
        c.setFillColor(self.primary_color)
        c.setStrokeColor(self.gold_color)
        c.setLineWidth(2)
        
        path = c.beginPath()
        path.moveTo(shield_x + 15, shield_y + 60)
        path.lineTo(shield_x, shield_y + 40)
        path.lineTo(shield_x, shield_y + 10)
        path.lineTo(shield_x + 15, shield_y)
        path.lineTo(shield_x + 30, shield_y + 10)
        path.lineTo(shield_x + 30, shield_y + 40)
        path.close()
        c.drawPath(path, fill=True, stroke=True)
        
        c.setFillColor(self.dark_bg)
        c.setFont("Helvetica-Bold", 20)
        c.drawCentredString(shield_x + 15, shield_y + 25, "✓")
        
        c.save()
        buffer.seek(0)
        return buffer
    
    def generate_badge(self, badge_name, badge_type):
        buffer = io.BytesIO()
        c = canvas.Canvas(buffer, pagesize=(200, 200))
        
        c.setFillColor(self.dark_bg)
        c.circle(100, 100, 95, fill=True)
        
        gradient_colors = {
            'bronze': colors.HexColor('#cd7f32'),
            'silver': colors.HexColor('#c0c0c0'),
            'gold': self.gold_color,
            'platinum': self.primary_color
        }
        
        color = gradient_colors.get(badge_type, self.primary_color)
        
        c.setStrokeColor(color)
        c.setLineWidth(5)
        c.circle(100, 100, 90, stroke=True)
        
        c.setFillColor(color)
        c.setFont("Helvetica-Bold", 12)
        c.drawCentredString(100, 115, "★ ★ ★")
        
        c.setFillColor(colors.white)
        c.setFont("Helvetica-Bold", 14)
        
        words = badge_name.split()
        if len(words) > 1:
            c.drawCentredString(100, 95, words[0])
            c.drawCentredString(100, 75, words[1])
        else:
            c.drawCentredString(100, 85, badge_name)
        
        c.setFillColor(color)
        c.setFont("Helvetica-Bold", 12)
        c.drawCentredString(100, 55, "★ ★ ★")
        
        c.setFillColor(colors.lightgrey)
        c.setFont("Helvetica", 8)
        c.drawCentredString(100, 30, "PhishGuard")
        
        c.save()
        buffer.seek(0)
        return buffer
