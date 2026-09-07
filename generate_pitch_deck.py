"""
generate_pitch_deck.py
----------------------
Generates a 16:9 widescreen PowerPoint presentation (.pptx)
for Smart India Hackathon (SIH 2026) - Team Binary Battalion.
Embeds high-resolution infographics, dark cyber theme, and speaker notes.
"""

import os
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.enum.text import PP_ALIGN
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE

# Artifact directory with images
ARTIFACT_DIR = r"C:\Users\Ayush\.gemini\antigravity\brain\85418af8-8151-46c5-a95f-5cbe74d55877"
IMG_LANDSCAPE = os.path.join(ARTIFACT_DIR, "phishing_threat_landscape_1788771206256.jpg")
IMG_ARCH = os.path.join(ARTIFACT_DIR, "soc_architecture_infographic_1788771148309.jpg")
IMG_COMPARE = os.path.join(ARTIFACT_DIR, "competitive_comparison_infographic_1788771180867.jpg")

OUT_DESKTOP = r"C:\Users\Ayush\OneDrive\Desktop\PhishGuard_SIH2026_PitchDeck.pptx"
OUT_WORKSPACE = r"c:\Users\Ayush\OneDrive\Desktop\phishguard (1)\PhishGuard_SIH2026_PitchDeck.pptx"

prs = Presentation()
prs.slide_width = Inches(13.333)
prs.slide_height = Inches(7.5)
blank_layout = prs.slide_layouts[6]

# Colors
BG_COLOR = RGBColor(9, 14, 26)       # #090E1A Dark Navy Slate
CARD_BG = RGBColor(15, 23, 42)       # #0F172A
CYAN = RGBColor(56, 189, 248)        # #38BDF8
GREEN = RGBColor(16, 185, 129)       # #10B981
RED = RGBColor(239, 68, 68)          # #EF4444
WHITE = RGBColor(248, 250, 252)      # #F8FAFC
SLATE = RGBColor(148, 163, 184)      # #94A3B8

def set_slide_background(slide):
    background = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, prs.slide_width, prs.slide_height)
    background.fill.solid()
    background.fill.fore_color.rgb = BG_COLOR
    background.line.fill.background()
    return background

def add_header(slide, title_text, category_text="SMART INDIA HACKATHON 2026 | BINARY BATTALION"):
    header_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.4), Inches(11.7), Inches(1.0))
    tf = header_box.text_frame
    tf.word_wrap = True
    tf.margin_left = tf.margin_top = tf.margin_right = tf.margin_bottom = 0
    
    p_cat = tf.paragraphs[0]
    p_cat.text = category_text.upper()
    p_cat.font.size = Pt(11)
    p_cat.font.bold = True
    p_cat.font.color.rgb = CYAN
    
    p_title = tf.add_paragraph()
    p_title.text = title_text
    p_title.font.size = Pt(24)
    p_title.font.bold = True
    p_title.font.color.rgb = WHITE
    p_title.space_before = Pt(4)

def add_notes(slide, notes_text):
    notes_slide = slide.notes_slide
    text_frame = notes_slide.notes_text_frame
    text_frame.text = notes_text

# ==============================================================================
# SLIDE 1: TITLE SLIDE
# ==============================================================================
s1 = prs.slides.add_slide(blank_layout)
set_slide_background(s1)

tb1 = s1.shapes.add_textbox(Inches(1.0), Inches(1.6), Inches(11.3), Inches(4.5))
tf1 = tb1.text_frame
tf1.word_wrap = True

p = tf1.paragraphs[0]
p.text = "SMART INDIA HACKATHON 2026 • CYBERSECURITY DIVISION"
p.font.size = Pt(14)
p.font.bold = True
p.font.color.rgb = CYAN

p = tf1.add_paragraph()
p.text = "PHISHGUARD SOC"
p.font.size = Pt(46)
p.font.bold = True
p.font.color.rgb = WHITE
p.space_before = Pt(12)

p = tf1.add_paragraph()
p.text = "AI-Powered Email Threat Detection, 3D Origin Geolocation & Forensic Intelligence Platform"
p.font.size = Pt(20)
p.font.color.rgb = CYAN
p.space_before = Pt(8)

p = tf1.add_paragraph()
p.text = "From In-Inbox Threat Interception to Section 65B Court-Admissible Dossier in Under 2 Seconds"
p.font.size = Pt(15)
p.font.color.rgb = SLATE
p.space_before = Pt(14)

p = tf1.add_paragraph()
p.text = "Team: Binary Battalion  •  Problem Statement: Advanced Email Threat Attribution & Forensic Analysis"
p.font.size = Pt(13)
p.font.color.rgb = GREEN
p.space_before = Pt(36)

add_notes(s1, "Good morning, respected judges. Over 91% of successful cyber breaches and banking frauds in India start with a single malicious email. Today, our team — Binary Battalion — presents PhishGuard: an end-to-end cyber threat intelligence and forensic platform that transforms how organizations, citizens, and cyber police investigate and neutralize phishing attacks.")

# ==============================================================================
# SLIDE 2: PROBLEM STATEMENT & THREAT LANDSCAPE (With Infographic 1)
# ==============================================================================
s2 = prs.slides.add_slide(blank_layout)
set_slide_background(s2)
add_header(s2, "The Threat Landscape: Weaponized Phishing & Investigation Gaps")

# Left Column (Text & Metrics)
tb2 = s2.shapes.add_textbox(Inches(0.8), Inches(1.5), Inches(4.8), Inches(5.4))
tf2 = tb2.text_frame
tf2.word_wrap = True

def add_bullet(tf, heading, text, color=WHITE):
    p = tf.add_paragraph()
    p.text = "• " + heading + ": "
    p.font.bold = True
    p.font.size = Pt(13)
    p.font.color.rgb = CYAN
    p.space_before = Pt(10)
    run = p.add_run()
    run.text = text
    run.font.bold = False
    run.font.color.rgb = color

p0 = tf2.paragraphs[0]
p0.text = "91% of cyber attacks start with spear-phishing."
p0.font.bold = True
p0.font.size = Pt(16)
p0.font.color.rgb = RED

add_bullet(tf2, "Indian Financial Scams", "Massive wave of fake SBI, HDFC, and Income Tax notices coercing victims into entering PAN & Aadhaar.")
add_bullet(tf2, "CEO Fraud & Wire Diversion", "Business Email Compromise (BEC) redirecting vendor payments to offshore accounts.")
add_bullet(tf2, "Dark-Web Bulletproof Hosting", "Attackers deploy disposable servers in non-extradition countries, evading domestic takedowns.")
add_bullet(tf2, "The Forensic Bottleneck", "Standard spam filters hide the evidence. Manual header analysis takes 2+ hours per incident, and evidence fails court admissibility.")

# Right Column (Infographic Image)
if os.path.exists(IMG_LANDSCAPE):
    s2.shapes.add_picture(IMG_LANDSCAPE, Inches(5.8), Inches(1.5), width=Inches(6.8))

add_notes(s2, "Judges, look at the screen. Scammers are no longer just sending generic spam. In India, they deploy weaponized financial fraud: fake SBI KYC panics, CFO wire diversion, and dark-web bulletproof hosting. When a victim or enterprise is attacked, existing tools drop the email into a spam folder without investigation. Cyber cells take hours to trace headers manually, and critical digital evidence is routinely rejected in court because proper chain-of-custody hashes were never preserved.")

# ==============================================================================
# SLIDE 3: PROPOSED SOLUTION (Core Pillars)
# ==============================================================================
s3 = prs.slides.add_slide(blank_layout)
set_slide_background(s3)
add_header(s3, "The Solution: PhishGuard Autonomous Forensic SOC")

cards = [
    ("🛡️ In-Inbox Chrome Sentinel", "1-Click 'Scan with PhishGuard' injected directly into Gmail & Outlook Web. Seamless citizen and enterprise protection with zero file uploads required.", CYAN),
    ("🧠 AI Semantic NLP Classifier", "Real-time natural language processing evaluating psychological urgency triggers, banking coercion, and executive wire diversion tactics.", GREEN),
    ("🌐 3D Global Origin Geolocation", "Automated hop-by-hop relay reconstruction mapping physical server origin, detecting bulletproof datacenters, and rendering 3D flight arcs.", CYAN),
    ("🕸️ Campaign Attribution Graph", "Network graph theory correlating isolated phishing incidents across domains, IPs, and registrars to unmask coordinated crime syndicates.", GREEN),
    ("⚖️ Section 65B BSA Court Dossier", "Automated export of court-admissible digital forensic reports with SHA-256 evidence hashes adhering to Bharatiya Sakshya Adhiniyam standards.", CYAN),
    ("⚡ 1-Click Automated Playbooks", "Instant generation of firewall containment rules (iptables, Palo Alto, Cisco) to block attacker infrastructure across the entire organization in seconds.", GREEN)
]

for idx, (ctitle, cdesc, ccolor) in enumerate(cards):
    row = idx // 3
    col = idx % 3
    x = Inches(0.8 + col * 4.0)
    y = Inches(1.6 + row * 2.7)
    
    shape = s3.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, x, y, Inches(3.7), Inches(2.4))
    shape.fill.solid()
    shape.fill.fore_color.rgb = CARD_BG
    shape.line.color.rgb = ccolor
    shape.line.width = Pt(1.5)
    
    tf = shape.text_frame
    tf.word_wrap = True
    tf.margin_left = tf.margin_right = tf.margin_top = tf.margin_bottom = Inches(0.2)
    
    p = tf.paragraphs[0]
    p.text = ctitle
    p.font.size = Pt(14)
    p.font.bold = True
    p.font.color.rgb = ccolor
    
    p2 = tf.add_paragraph()
    p2.text = cdesc
    p2.font.size = Pt(11)
    p2.font.color.rgb = WHITE
    p2.space_before = Pt(8)

add_notes(s3, "To solve this, we built PhishGuard. It operates on two powerful levels: First, a seamless Chrome browser extension that gives every citizen and corporate employee a 1-click cyber analyst right inside their daily Gmail or Outlook inbox. Second, an enterprise SOC dashboard that unwinds the email's hidden postal stamps, plots the attacker's physical server across the globe on a 3D trajectory, connects shared attack infrastructure into syndicate clusters, and generates an FIR-ready legal dossier in seconds.")

# ==============================================================================
# SLIDE 4: SYSTEM ARCHITECTURE & 5-STEP PIPELINE (With Infographic 2)
# ==============================================================================
s4 = prs.slides.add_slide(blank_layout)
set_slide_background(s4)
add_header(s4, "System Architecture: The 5-Step Forensic Pipeline")

if os.path.exists(IMG_ARCH):
    s4.shapes.add_picture(IMG_ARCH, Inches(0.8), Inches(1.5), width=Inches(11.7))

add_notes(s4, "Here is our 5-step automated pipeline. The moment an email is scanned, PhishGuard hashes the file with SHA-256 for legal integrity. Step 2 validates cryptographic authentication. Step 3 combines NLP machine learning with live DNS and GeoIP resolution to trace the physical server. Step 4 links this attack to historical incidents using graph theory, and Step 5 generates instant firewall containment rules and a court-certified forensic dossier.")

# ==============================================================================
# SLIDE 5: COMPETITIVE ADVANTAGE (With Infographic 3)
# ==============================================================================
s5 = prs.slides.add_slide(blank_layout)
set_slide_background(s5)
add_header(s5, "Competitive Advantage: Beyond the Traditional Spam Filter")

if os.path.exists(IMG_COMPARE):
    s5.shapes.add_picture(IMG_COMPARE, Inches(0.8), Inches(1.5), width=Inches(11.7))

add_notes(s5, "Judges, this slide summarizes why PhishGuard is fundamentally superior. Traditional spam filters are passive black boxes — they hide the evidence. Enterprise gateways cost lakhs of rupees and still cannot produce Indian court-compliant documentation. PhishGuard is built from the ground up for Indian sovereignty: zero-cost open threat intelligence, instant 3D origin traceability, and full Section 65B legal admissibility.")

# ==============================================================================
# SLIDE 6: LIVE DEMONSTRATION & REAL USE CASES
# ==============================================================================
s6 = prs.slides.add_slide(blank_layout)
set_slide_background(s6)
add_header(s6, "Operational Proof: Real-World Attack Scenarios")

scenarios = [
    ("Scenario 1: Indian Banking & KYC Fraud", "Target: SBI NetBanking Users\n• Mechanism: Panicking users with 24-hr account suspension notice.\n• Forensic Finding: Spoofed 'sbi-kyc-update.com' + SPF Fail + Origin in St. Petersburg Datacenter (45.155.204.12).\n• Outcome: Instant Critical Threat alert + Section 65B police FIR draft.", RED),
    ("Scenario 2: Cross-Campaign Syndicate Discovery", "Target: Banking & Corporate Enterprise\n• Mechanism: Microsoft 365 credential harvesting and PayPal payment fraud.\n• Forensic Finding: NetworkX graph links both separate emails to the exact same bulletproof IP!\n• Outcome: Unmasks entire transnational attack cluster.", CYAN),
    ("Scenario 3: Executive BEC Wire Transfer Diversion", "Target: Corporate Finance Department\n• Mechanism: CFO impersonation demanding emergency offshore wire transfer.\n• Forensic Finding: NLP detects financial diversion cues; Origin resolves to an anonymized Tor exit node (185.220.101.5).\n• Outcome: Blocked before financial transaction executes.", RED),
    ("Scenario 4: Live In-Inbox Gmail Sentinel Audit", "Target: Daily Consumer Mailbox\n• Mechanism: Real promotional & corporate emails audited via Chrome Extension.\n• Forensic Finding: Automated Mail Gateway DNS resolution pinpoints server coordinates in California.\n• Outcome: Proves zero-friction 1-click real-world usability.", GREEN),
]

for idx, (stitle, sbody, scolor) in enumerate(scenarios):
    row = idx // 2
    col = idx % 2
    x = Inches(0.8 + col * 5.9)
    y = Inches(1.6 + row * 2.7)
    
    shape = s6.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, x, y, Inches(5.6), Inches(2.4))
    shape.fill.solid()
    shape.fill.fore_color.rgb = CARD_BG
    shape.line.color.rgb = scolor
    shape.line.width = Pt(1.5)
    
    tf = shape.text_frame
    tf.word_wrap = True
    tf.margin_left = tf.margin_right = tf.margin_top = tf.margin_bottom = Inches(0.2)
    
    p = tf.paragraphs[0]
    p.text = stitle
    p.font.size = Pt(14)
    p.font.bold = True
    p.font.color.rgb = scolor
    
    p2 = tf.add_paragraph()
    p2.text = sbody
    p2.font.size = Pt(11)
    p2.font.color.rgb = WHITE
    p2.space_before = Pt(6)

add_notes(s6, "During our live demo, we will demonstrate 4 realistic attack scenarios: from catching lookalike SBI banking scams to discovering that an attack on an Indian bank and an attack on an IT firm share the exact same attacker IP in Eastern Europe. And we can do this live on our real personal Gmail right in front of you.")

# ==============================================================================
# SLIDE 7: REGULATORY COMPLIANCE & TECH STACK
# ==============================================================================
s7 = prs.slides.add_slide(blank_layout)
set_slide_background(s7)
add_header(s7, "Legal Admissibility, Standards Compliance & Tech Stack")

# Left: Legal & Standards
shape_l = s7.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(1.6), Inches(5.6), Inches(5.2))
shape_l.fill.solid()
shape_l.fill.fore_color.rgb = CARD_BG
shape_l.line.color.rgb = CYAN
shape_l.line.width = Pt(1.5)

tf_l = shape_l.text_frame
tf_l.word_wrap = True
tf_l.margin_left = tf_l.margin_right = tf_l.margin_top = tf_l.margin_bottom = Inches(0.25)

p = tf_l.paragraphs[0]
p.text = "🏛️ Sovereign Legal & Regulatory Framework"
p.font.size = Pt(16)
p.font.bold = True
p.font.color.rgb = CYAN

add_bullet(tf_l, "Section 65B BSA (India)", "Tamper-evident SHA-256 and MD5 chain-of-custody hashes adhering to Bharatiya Sakshya Adhiniyam standards for digital evidence.")
add_bullet(tf_l, "IT Act, 2000 Compliance", "Maps evidence to Section 66C (Identity Theft) and Section 66D (Cheating by Personation Using Computer Resource).")
add_bullet(tf_l, "CERT-In Threat Package", "Generates standardized machine-readable JSON IOC packages for national incident coordination.")
add_bullet(tf_l, "ISO/IEC 27037 Standard", "Conforms to international digital evidence preservation and handling guidelines.")

# Right: Tech Stack
shape_r = s7.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(6.9), Inches(1.6), Inches(5.6), Inches(5.2))
shape_r.fill.solid()
shape_r.fill.fore_color.rgb = CARD_BG
shape_r.line.color.rgb = GREEN
shape_r.line.width = Pt(1.5)

tf_r = shape_r.text_frame
tf_r.word_wrap = True
tf_r.margin_left = tf_r.margin_right = tf_r.margin_top = tf_r.margin_bottom = Inches(0.25)

p = tf_r.paragraphs[0]
p.text = "⚙️ Production Technology Stack"
p.font.size = Pt(16)
p.font.bold = True
p.font.color.rgb = GREEN

add_bullet(tf_r, "In-Inbox Extension", "Chrome Manifest V3, Service Workers, DOM Observers (Gmail & Outlook Web support).")
add_bullet(tf_r, "AI & Machine Learning", "Scikit-Learn TF-IDF NLP model, heuristic banking threat categorization, social engineering urgency scoring.")
add_bullet(tf_r, "Graph Theory & Correlation", "NetworkX graph clustering + Vis.js physics-driven interactive network simulation.")
add_bullet(tf_r, "3D Visualization", "Pydeck (Uber Deck.gl engine) rendering 3D global flight trajectory arcs on Carto Dark Matter tiles.")
add_bullet(tf_r, "Forensic Reporting", "ReportLab PDF Engine generating court-certified digital evidence dossiers.")

add_notes(s7, "A cyber tool is useless in India if the evidence cannot stand up in court. Every report PhishGuard generates is backed by immutable SHA-256 cryptographic hashes and carries an automated Section 65B BSA certificate. An investigator can hand our PDF dossier directly to the magistrate or attach it to a Cyber Crime FIR on Day 1.")

# ==============================================================================
# SLIDE 8: FUTURE SCOPE, NATIONAL IMPACT & CONCLUSION
# ==============================================================================
s8 = prs.slides.add_slide(blank_layout)
set_slide_background(s8)
add_header(s8, "Future Roadmap, National Impact & Conclusion")

roadmap = [
    ("🇮🇳 National Cyber Portal (cybercrime.gov.in)", "1-Click automated FIR filing pipeline generating pre-filled police incident reports directly for the Ministry of Home Affairs NCRP portal.", CYAN),
    ("📱 Computer Vision 'Quishing' Scanner", "Deep-scan engine detecting malicious QR codes embedded in email images designed to bypass text filters and trigger fraudulent UPI payments.", GREEN),
    ("🤖 Autonomous AI Counter-Scammer", "Autonomous honeypot bot that engages scammers with believable decoy responses to extract their real bank accounts and UPI IDs for law enforcement.", CYAN),
    ("🏢 Enterprise SIEM & SOAR Connectors", "Native telemetry export to enterprise security centers via Splunk, IBM QRadar, Microsoft Sentinel, and Cisco SecureX.", GREEN)
]

for idx, (rtitle, rdesc, rcolor) in enumerate(roadmap):
    row = idx // 2
    col = idx % 2
    x = Inches(0.8 + col * 5.9)
    y = Inches(1.6 + row * 2.2)
    
    shape = s8.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, x, y, Inches(5.6), Inches(1.9))
    shape.fill.solid()
    shape.fill.fore_color.rgb = CARD_BG
    shape.line.color.rgb = rcolor
    shape.line.width = Pt(1.5)
    
    tf = shape.text_frame
    tf.word_wrap = True
    tf.margin_left = tf.margin_right = tf.margin_top = tf.margin_bottom = Inches(0.18)
    
    p = tf.paragraphs[0]
    p.text = rtitle
    p.font.size = Pt(13)
    p.font.bold = True
    p.font.color.rgb = rcolor
    
    p2 = tf.add_paragraph()
    p2.text = rdesc
    p2.font.size = Pt(10.5)
    p2.font.color.rgb = WHITE
    p2.space_before = Pt(4)

# Bottom Callout
bottom_box = s8.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(6.1), Inches(11.7), Inches(0.9))
bottom_box.fill.solid()
bottom_box.fill.fore_color.rgb = RGBColor(23, 37, 84)
bottom_box.line.color.rgb = CYAN
bottom_box.line.width = Pt(1)

tf_b = bottom_box.text_frame
tf_b.word_wrap = True
p = tf_b.paragraphs[0]
p.text = "🏆 PhishGuard: Empowering India's Cyber Defense from Inbox to Courtroom. Thank You!"
p.font.size = Pt(14)
p.font.bold = True
p.font.color.rgb = WHITE
p.alignment = PP_ALIGN.CENTER

add_notes(s8, "Looking ahead, PhishGuard is architected to integrate directly with India's National Cyber Crime Reporting Portal (cybercrime.gov.in) and CERT-In. By eliminating the manual investigation bottleneck and automating court evidence, PhishGuard empowers enterprises, financial institutions, and law enforcement agencies to stay one step ahead of international cybercrime syndicates. Thank you, and we are ready for your questions!")

# Save presentations
prs.save(OUT_DESKTOP)
prs.save(OUT_WORKSPACE)
print(f"Presentation saved successfully to:\n  - {OUT_DESKTOP}\n  - {OUT_WORKSPACE}")
