from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.units import inch
from reportlab.graphics.shapes import Drawing, Rect, String, Circle, Line, Polygon
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics import renderPDF
from reportlab.pdfgen import canvas
from reportlab.graphics.shapes import Drawing, Rect
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
        self.dark_bg = colors.HexColor('#0f172a')
        self.card_bg = colors.HexColor('#1e293b')
        self.dark_red = colors.HexColor('#991b1b')
        self.neon_blue = colors.HexColor('#3b82f6')
        
    def generate_report(self, analysis_data, analysis_type, user_info=None):
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=0.5*inch,
            leftMargin=0.5*inch,
            topMargin=0.3*inch,
            bottomMargin=0.3*inch
        )
        
        elements = []
        
        elements.append(self._create_header(analysis_data, analysis_type))
        elements.append(Spacer(1, 15))
        
        elements.append(self._create_risk_meter(analysis_data))
        elements.append(Spacer(1, 15))
        
        elements.append(self._create_threat_analysis(analysis_data))
        elements.append(Spacer(1, 15))
        
        elements.append(self._create_comparison_table(analysis_data))
        elements.append(Spacer(1, 15))
        
        elements.append(self._create_protection_recommendations())
        elements.append(Spacer(1, 15))
        
        elements.append(self._create_scan_metadata(analysis_data, analysis_type, user_info))
        elements.append(Spacer(1, 10))
        
        elements.append(self._create_footer())
        
        doc.build(elements)
        buffer.seek(0)
        return buffer
    
    def _create_header(self, analysis_data, analysis_type):
        prediction = analysis_data.get('prediction', 'Unknown')
        
        if prediction == 'Phishing':
            header_bg = colors.HexColor('#7f1d1d')
            title_color = colors.HexColor('#ef4444')
            alert_text = "PHISHING ALERT"
        elif prediction == 'Suspicious':
            header_bg = colors.HexColor('#78350f')
            title_color = colors.HexColor('#f59e0b')
            alert_text = "SUSPICIOUS CONTENT"
        else:
            header_bg = colors.HexColor('#14532d')
            title_color = colors.HexColor('#10b981')
            alert_text = "SAFE CONTENT"
        
        header_data = [[
            Paragraph("""
                <font color="#00d4ff" size="20"><b>🛡️ PhishGuard AI</b></font><br/>
                <font color="#ef4444" size="28"><b>""" + alert_text + """</b></font><br/>
                <font color="#94a3b8" size="11">""" + analysis_type.title() + """ Analysis Report</font>
            """, ParagraphStyle('Header', alignment=1, leading=35)),
        ]]
        
        header_table = Table(header_data, colWidths=[7*inch])
        header_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), header_bg),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 25),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 25),
            ('LEFTPADDING', (0, 0), (-1, -1), 20),
            ('RIGHTPADDING', (0, 0), (-1, -1), 20),
            ('BOX', (0, 0), (-1, -1), 3, self.neon_blue),
        ]))
        
        return header_table
    
    def _create_risk_meter(self, analysis_data):
        confidence = analysis_data.get('confidence', 0)
        threat_level = analysis_data.get('threat_level', 'Unknown')
        
        if confidence >= 70:
            meter_color = colors.HexColor('#ef4444')
            meter_bg = colors.HexColor('#450a0a')
        elif confidence >= 40:
            meter_color = colors.HexColor('#f59e0b')
            meter_bg = colors.HexColor('#451a03')
        else:
            meter_color = colors.HexColor('#10b981')
            meter_bg = colors.HexColor('#14532d')
        
        meter_width = 5.5 * (confidence / 100)
        
        risk_content = f"""
        <font color="#e2e8f0" size="14"><b>THREAT LEVEL ANALYSIS</b></font><br/><br/>
        <font color="#94a3b8" size="11">Risk Score:</font> <font color="{meter_color.hexval()}" size="36"><b>{confidence}%</b></font><br/>
        <font color="#94a3b8" size="11">Threat Classification:</font> <font color="{meter_color.hexval()}" size="14"><b>{threat_level.upper()}</b></font>
        """
        
        meter_bar = f"""
        <font color="#64748b" size="9">0%</font>
        <font color="#64748b" size="9" position="end">100%</font>
        """
        
        risk_data = [[
            Paragraph(risk_content, ParagraphStyle('Risk', alignment=0, leading=30)),
        ]]
        
        risk_table = Table(risk_data, colWidths=[4*inch])
        risk_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), self.card_bg),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 20),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 20),
            ('LEFTPADDING', (0, 0), (-1, -1), 20),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#334155')),
        ]))
        
        meter_data = [[
            Paragraph(f"""
                <font color="#475569" size="8">0</font>
            """, ParagraphStyle('MeterStart', alignment=0)),
            Paragraph(f"""
                <font color="#475569" size="8">50</font>
            """, ParagraphStyle('MeterMid', alignment=1)),
            Paragraph(f"""
                <font color="#475569" size="8">100</font>
            """, ParagraphStyle('MeterEnd', alignment=2)),
        ]]
        
        meter_table = Table(meter_data, colWidths=[1.8*inch, 1.8*inch, 1.8*inch])
        meter_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), meter_bg),
            ('ALIGN', (0, 0), (0, 0), 'LEFT'),
            ('ALIGN', (1, 0), (1, 0), 'CENTER'),
            ('ALIGN', (2, 0), (2, 0), 'RIGHT'),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('LEFTPADDING', (0, 0), (-1, -1), 5),
            ('RIGHTPADDING', (0, 0), (-1, -1), 5),
        ]))
        
        container_data = [[risk_table], [meter_table]]
        container = Table(container_data, colWidths=[7*inch])
        container.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), self.card_bg),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#334155')),
        ]))
        
        return container
    
    def _create_threat_analysis(self, analysis_data):
        warnings = analysis_data.get('warnings', [])
        features = analysis_data.get('features', {})
        
        title_style = ParagraphStyle(
            'ThreatTitle',
            fontSize=14,
            textColor=colors.HexColor('#ef4444'),
            spaceBefore=5,
            spaceAfter=10
        )
        
        header = Paragraph("<b>🚨 DETAILED THREAT ANALYSIS</b>", title_style)
        
        threat_items = []
        if warnings:
            for warning in warnings:
                threat_items.append(Paragraph(
                    f"<font color='#ef4444'>⚠️</font> <font color='#fecaca'>{warning}</font>",
                    ParagraphStyle('Threat', fontSize=10, textColor=colors.white, leftIndent=10, spaceBefore=3, leading=14)
                ))
        else:
            threat_items.append(Paragraph(
                "<font color='#10b981'>✓</font> <font color='#a7f3d0'>No suspicious elements detected</font>",
                ParagraphStyle('Safe', fontSize=10, textColor=colors.white, leftIndent=10, spaceBefore=3)
            ))
        
        if features:
            feature_rows = []
            for key, value in features.items():
                formatted_key = key.replace('_', ' ').title()
                if value in ['Yes', 1, True, 'True']:
                    val_color = '#ef4444'
                    indicator = '🔴'
                elif value in ['No', 0, False, 'False']:
                    val_color = '#10b981'
                    indicator = '🟢'
                else:
                    val_color = '#94a3b8'
                    indicator = '⚪'
                feature_rows.append([
                    Paragraph(f"<font color='#94a3b8'>{formatted_key}</font>", ParagraphStyle('Key', fontSize=9)),
                    Paragraph(f"<font color='{val_color}'>{indicator} {value}</font>", ParagraphStyle('Val', fontSize=9))
                ])
            
            feature_table = Table(feature_rows, colWidths=[2.5*inch, 2*inch])
            feature_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#1e293b')),
                ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#0f172a')),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('LEFTPADDING', (0, 0), (-1, -1), 10),
                ('RIGHTPADDING', (0, 0), (-1, -1), 10),
                ('LINEBELOW', (0, 0), (-1, -2), 0.5, colors.HexColor('#334155')),
            ]))
            threat_items.append(Spacer(1, 10))
            threat_items.append(feature_table)
        
        container = Table([[item] for item in [header] + threat_items], colWidths=[7*inch])
        container.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#1e293b')),
            ('TOPPADDING', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('LEFTPADDING', (0, 0), (-1, -1), 15),
            ('RIGHTPADDING', (0, 0), (-1, -1), 15),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#334155')),
        ]))
        
        return container
    
    def _create_comparison_table(self, analysis_data):
        title = Paragraph("<b>📋 SECURITY INDICATORS CHECKLIST</b>", 
                         ParagraphStyle('CompareTitle', fontSize=14, textColor=self.primary_color, spaceBefore=5, spaceAfter=10))
        
        good_indicators = [
            "HTTPS secure connection",
            "Legitimate domain name",
            "No suspicious characters",
            "Proper email formatting",
            "No urgency tactics"
        ]
        
        bad_indicators = [
            "Misspelled domain/URL",
            "Suspicious attachments",
            "Urgent action required",
            "Request for personal data",
            "Unknown sender"
        ]
        
        found_issues = analysis_data.get('warnings', [])
        
        good_col = []
        for item in good_indicators:
            good_col.append(Paragraph(
                f"<font color='#10b981'>✓</font> <font color='#d1fae5'>{item}</font>",
                ParagraphStyle('Good', fontSize=9, spaceBefore=4, leading=12)
            ))
        
        bad_col = []
        for item in bad_indicators:
            found = any(issue.lower() in item.lower() or item.lower() in issue.lower() for issue in found_issues)
            if found:
                bad_col.append(Paragraph(
                    f"<font color='#ef4444'>⚠️</font> <font color='#fecaca'>{item}</font>",
                    ParagraphStyle('Bad', fontSize=9, spaceBefore=4, leading=12)
                ))
            else:
                bad_col.append(Paragraph(
                    f"<font color='#64748b'>○</font> <font color='#94a3b8'>{item}</font>",
                    ParagraphStyle('Bad', fontSize=9, spaceBefore=4, leading=12)
                ))
        
        good_header = Paragraph("<b>✓ GOOD SIGNS</b>", ParagraphStyle('GoodHeader', fontSize=11, textColor=colors.HexColor('#10b981')))
        bad_header = Paragraph("<b>⚠️ WARNING SIGNS</b>", ParagraphStyle('BadHeader', fontSize=11, textColor=colors.HexColor('#ef4444')))
        
        good_content = [good_header] + good_col
        bad_content = [bad_header] + bad_col
        
        compare_data = [[good_content, bad_content]]
        compare_table = Table(compare_data, colWidths=[3.3*inch, 3.3*inch])
        compare_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, 0), colors.HexColor('#064e3b')),
            ('BACKGROUND', (1, 0), (1, 0), colors.HexColor('#7f1d1d')),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('TOPPADDING', (0, 0), (-1, -1), 12),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('LEFTPADDING', (0, 0), (-1, -1), 15),
            ('RIGHTPADDING', (0, 0), (-1, -1), 15),
            ('LINEAFTER', (0, 0), (0, 0), 1, colors.HexColor('#334155')),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#334155')),
        ]))
        
        container = Table([[title], [compare_table]], colWidths=[7*inch])
        container.setStyle(TableStyle([
            ('TOPPADDING', (0, 0), (-1, -1), 0),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
        ]))
        
        return container
    
    def _create_protection_recommendations(self):
        title = Paragraph("<b>🛡️ PROTECTION RECOMMENDATIONS</b>", 
                         ParagraphStyle('RecTitle', fontSize=14, textColor=colors.HexColor('#3b82f6'), spaceBefore=5, spaceAfter=10))
        
        recommendations = [
            ("Do NOT click", "Avoid clicking on suspicious links or attachments"),
            ("Verify Source", "Confirm the sender's identity through official channels"),
            ("No Personal Data", "Never share passwords, OTPs, or personal information"),
            ("Report", "Report suspicious activity to the appropriate authorities"),
            ("Use Incognito", "When in doubt, visit official websites directly"),
        ]
        
        rec_rows = []
        for action, desc in recommendations:
            rec_rows.append([
                Paragraph(f"<font color='#3b82f6'><b>{action}</b></font>", 
                         ParagraphStyle('Action', fontSize=10)),
                Paragraph(f"<font color='#94a3b8'>{desc}</font>", 
                         ParagraphStyle('Desc', fontSize=10))
            ])
        
        rec_table = Table(rec_rows, colWidths=[1.8*inch, 4.8*inch])
        rec_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#1e3a5f')),
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#172554')),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('LEFTPADDING', (0, 0), (-1, -1), 12),
            ('LINEBELOW', (0, 0), (-1, -2), 0.5, colors.HexColor('#1e40af')),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#3b82f6')),
        ]))
        
        return Table([[title], [rec_table]], colWidths=[7*inch])
    
    def _create_scan_metadata(self, analysis_data, analysis_type, user_info):
        content = analysis_data.get('content', analysis_data.get('url', 'N/A'))
        if len(content) > 60:
            content = content[:60] + "..."
        
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        metadata = [
            ["SCAN INFORMATION", ""],
            [f"<font color='#94a3b8'>Analysis Type:</font>", f"<font color='#e2e8f0'>{analysis_type.title()}</font>"],
            [f"<font color='#94a3b8'>Content Scanned:</font>", f"<font color='#e2e8f0'>{content}</font>"],
            [f"<font color='#94a3b8'>Scan Date:</font>", f"<font color='#e2e8f0'>{timestamp}</font>"],
            [f"<font color='#94a3b8'>Device:</font>", f"<font color='#e2e8f0'>Web Browser</font>"],
            [f"<font color='#94a3b8'>Location:</font>", f"<font color='#e2e8f0'>Client Device</font>"],
        ]
        
        if user_info:
            metadata.append([f"<font color='#94a3b8'>User:</font>", f"<font color='#e2e8f0'>{user_info.get('username', 'Anonymous')}</font>"])
        
        meta_rows = []
        for i, (label, value) in enumerate(metadata):
            if i == 0:
                meta_rows.append([
                    Paragraph(f"<font color='#00d4ff'><b>{label}</b></font>", 
                             ParagraphStyle('MetaLabel', fontSize=11)),
                    ""
                ])
            else:
                meta_rows.append([
                    Paragraph(label, ParagraphStyle('MetaLabel', fontSize=9)),
                    Paragraph(value, ParagraphStyle('MetaValue', fontSize=9))
                ])
        
        meta_table = Table(meta_rows, colWidths=[2*inch, 4.6*inch])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#0f172a')),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('LEFTPADDING', (0, 0), (-1, -1), 10),
            ('SPAN', (0, 0), (-1, 0)),
            ('LINEBELOW', (0, 1), (-1, -2), 0.5, colors.HexColor('#1e293b')),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#334155')),
        ]))
        
        return meta_table
    
    def _create_footer(self):
        footer_data = [[
            Paragraph("""
                <font color="#64748b" size="8">━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━</font><br/>
                <font color="#00d4ff" size="10"><b>Stay Safe Online</b></font><br/>
                <font color="#64748b" size="7">This report was generated by PhishGuard AI Phishing Detection System</font><br/>
                <font color="#475569" size="6">For educational purposes only. Always verify with official sources.</font>
            """, ParagraphStyle('Footer', alignment=1, leading=14))
        ]]
        
        footer_table = Table(footer_data, colWidths=[7*inch])
        footer_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#0f172a')),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('TOPPADDING', (0, 0), (-1, -1), 15),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
        ]))
        
        return footer_table
    
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
