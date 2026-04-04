from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.units import inch
from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics import renderPDF
from datetime import datetime
import io
import os

class PDFReportGenerator:
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self.primary_color = colors.HexColor('#00d4ff')
        self.danger_color = colors.HexColor('#ef4444')
        self.warning_color = colors.HexColor('#f59e0b')
        self.success_color = colors.HexColor('#10b981')
        
    def generate_report(self, analysis_data, analysis_type, user_info=None):
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=0.75*inch,
            leftMargin=0.75*inch,
            topMargin=0.75*inch,
            bottomMargin=0.75*inch
        )
        
        elements = []
        
        elements.append(self._create_header(analysis_type))
        elements.append(Spacer(1, 20))
        
        if user_info:
            elements.append(self._create_user_info(user_info))
            elements.append(Spacer(1, 20))
        
        elements.append(self._create_summary(analysis_data))
        elements.append(Spacer(1, 20))
        
        if analysis_data.get('features'):
            elements.append(self._create_features_table(analysis_data['features']))
            elements.append(Spacer(1, 20))
        
        if analysis_data.get('warnings'):
            elements.append(self._create_warnings(analysis_data['warnings']))
            elements.append(Spacer(1, 20))
        
        elements.append(self._create_tips())
        elements.append(Spacer(1, 30))
        
        elements.append(self._create_footer())
        
        doc.build(elements)
        buffer.seek(0)
        return buffer
    
    def _create_header(self, analysis_type):
        title = f"PhishGuard - {analysis_type.title()} Analysis Report"
        
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=self.primary_color,
            spaceAfter=10,
            alignment=1
        )
        
        subtitle_style = ParagraphStyle(
            'Subtitle',
            parent=self.styles['Normal'],
            fontSize=12,
            textColor=colors.gray,
            alignment=1
        )
        
        elements = [
            Paragraph("🛡️ PhishGuard AI", title_style),
            Paragraph(f"Detailed {analysis_type.title()} Phishing Analysis", subtitle_style),
            Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", subtitle_style),
        ]
        
        return elements
    
    def _create_user_info(self, user_info):
        style = ParagraphStyle(
            'UserInfo',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=colors.gray
        )
        
        return Paragraph(
            f"<b>User:</b> {user_info.get('username', 'Anonymous')} | "
            f"<b>Email:</b> {user_info.get('email', 'N/A')}",
            style
        )
    
    def _create_summary(self, data):
        prediction = data.get('prediction', 'Unknown')
        confidence = data.get('confidence', 0)
        threat_level = data.get('threat_level', 'Unknown')
        
        if prediction == 'Phishing':
            pred_color = self.danger_color
            pred_icon = '⚠️'
        elif prediction == 'Suspicious':
            pred_color = self.warning_color
            pred_icon = '⚡'
        else:
            pred_color = self.success_color
            pred_icon = '✅'
        
        style = ParagraphStyle(
            'Summary',
            parent=self.styles['Heading2'],
            fontSize=18,
            textColor=pred_color,
            alignment=1,
            spaceBefore=10,
            spaceAfter=10
        )
        
        summary_data = [
            [f"{pred_icon} PREDICTION: {prediction.upper()}"],
            [f"Confidence Score: {confidence}%"],
            [f"Threat Level: {threat_level}"]
        ]
        
        table = Table(summary_data, colWidths=[5*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#1a1a2e')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 20),
            ('FONTSIZE', (0, 1), (-1, -1), 14),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 15),
            ('TOPPADDING', (0, 0), (-1, -1), 15),
            ('ROUNDEDCORNERS', [10, 10, 10, 10]),
        ]))
        
        return table
    
    def _create_features_table(self, features):
        title = Paragraph("📊 Extracted Features Analysis", 
                         ParagraphStyle('Title', parent=self.styles['Heading2'], 
                                       fontSize=14, textColor=self.primary_color, spaceAfter=10))
        
        feature_rows = []
        for key, value in features.items():
            formatted_key = key.replace('_', ' ').title()
            feature_rows.append([formatted_key, str(value)])
        
        table = Table(feature_rows, colWidths=[3*inch, 2*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#16213e')),
            ('BACKGROUND', (1, 0), (1, -1), colors.HexColor('#1a1a2e')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.white),
            ('ALIGN', (1, 0), (1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.gray),
        ]))
        
        return [title, table]
    
    def _create_warnings(self, warnings):
        title = Paragraph("⚠️ Detected Warnings & Red Flags", 
                         ParagraphStyle('Title', parent=self.styles['Heading2'], 
                                       fontSize=14, textColor=self.danger_color, spaceAfter=10))
        
        warning_items = []
        for i, warning in enumerate(warnings, 1):
            warning_items.append(
                Paragraph(f"{i}. {warning}", 
                         ParagraphStyle('Warning', parent=self.styles['Normal'],
                                       fontSize=11, textColor=colors.white,
                                       leftIndent=10, spaceBefore=5))
            )
        
        return [title, *warning_items]
    
    def _create_tips(self):
        title = Paragraph("💡 Security Recommendations", 
                         ParagraphStyle('Title', parent=self.styles['Heading2'], 
                                       fontSize=14, textColor=self.success_color, spaceAfter=10))
        
        tips = [
            "Never click on suspicious links, even if they appear to be from trusted sources",
            "Always verify the sender's identity through official channels",
            "Never share personal information, passwords, or OTPs via messages",
            "When in doubt, directly visit the official website instead of clicking links",
            "Report suspicious messages to the appropriate authorities"
        ]
        
        tip_items = []
        for tip in tips:
            tip_items.append(
                Paragraph(f"• {tip}", 
                         ParagraphStyle('Tip', parent=self.styles['Normal'],
                                       fontSize=10, textColor=colors.white,
                                       leftIndent=10, spaceBefore=3))
            )
        
        return [title, *tip_items]
    
    def _create_footer(self):
        footer_style = ParagraphStyle(
            'Footer',
            parent=self.styles['Normal'],
            fontSize=8,
            textColor=colors.gray,
            alignment=1
        )
        
        return Paragraph(
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━<br/>"
            "This report was generated by PhishGuard AI Phishing Detection System<br/>"
            "For educational purposes only. Always verify with official sources.",
            footer_style
        )
    
    def generate_statistics_report(self, statistics):
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4)
        
        elements = []
        
        title_style = ParagraphStyle(
            'Title',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=self.primary_color,
            alignment=1
        )
        
        elements.append(Paragraph("📊 PhishGuard Statistics Report", title_style))
        elements.append(Spacer(1, 20))
        elements.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 
                                 ParagraphStyle('Date', alignment=1)))
        elements.append(Spacer(1, 30))
        
        for stat in statistics:
            stat_table = Table(
                [[f"{stat['analysis_type'].upper()}"], 
                 [f"Total: {stat['total_analyses']} | Phishing: {stat['phishing_count']} | Safe: {stat['safe_count']}"]],
                colWidths=[5*inch]
            )
            stat_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#7c3aed')),
                ('BACKGROUND', (0, 1), (-1, 1), colors.HexColor('#1a1a2e')),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTSIZE', (0, 0), (-1, 0), 16),
                ('FONTSIZE', (0, 1), (-1, 1), 12),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 15),
                ('TOPPADDING', (0, 0), (-1, -1), 15),
            ]))
            elements.append(stat_table)
            elements.append(Spacer(1, 15))
        
        doc.build(elements)
        buffer.seek(0)
        return buffer
