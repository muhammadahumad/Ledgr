import os
import json
import base64
import urllib.request
import urllib.parse
import urllib.error
import re
from datetime import datetime, timedelta
from functools import wraps
from enum import Enum
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import secrets

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

db_url = os.environ.get('DATABASE_URL', 'sqlite:///ledgr.db')
if db_url.startswith('postgres://'):
    db_url = db_url.replace('postgres://', 'postgresql://', 1)
app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)

db = SQLAlchemy(app)

ANTHROPIC_KEY = os.environ.get('ANTHROPIC_KEY', '')
ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', 'muahumadhu@gmail.com')

# ── Plans ─────────────────────────────────────────────────────────────────────
PLANS = {
    'free':     {'name': 'Free',     'price': 0,   'uploads': 10,  'modules': ['documents']},
    'pro':      {'name': 'Pro',      'price': 15,  'uploads': 500, 'modules': ['documents', 'inventory', 'payroll']},
    'business': {'name': 'Business', 'price': 35,  'uploads': 9999,'modules': ['documents', 'inventory', 'payroll', 'pos', 'reports']},
}

# ── Tax Rules by Region ───────────────────────────────────────────────────────
TAX_RULES = {
    'MV': {'name': 'Maldives', 'currency': 'MVR', 'tax_name': 'GST', 'tax_rate': 0.08, 'authority': 'MIRA', 'tin_format': 'XXXXXXXGSTXXX'},
    'AE': {'name': 'UAE',      'currency': 'AED', 'tax_name': 'VAT', 'tax_rate': 0.05, 'authority': 'FTA',  'tin_format': 'TRN XXXXXXXXXXXXXXX'},
    'PK': {'name': 'Pakistan', 'currency': 'PKR', 'tax_name': 'GST', 'tax_rate': 0.17, 'authority': 'FBR',  'tin_format': 'XXXXXXX-X'},
    'CN': {'name': 'China',    'currency': 'CNY', 'tax_name': 'VAT', 'tax_rate': 0.13, 'authority': 'SAT',  'tin_format': 'XXXXXXXXXXXXXXXXXX'},
    'LK': {'name': 'Sri Lanka','currency': 'LKR', 'tax_name': 'VAT', 'tax_rate': 0.18, 'authority': 'IRD',  'tin_format': 'XXXXXXXXX'},
    'IN': {'name': 'India',    'currency': 'INR', 'tax_name': 'GST', 'tax_rate': 0.18, 'authority': 'CBIC', 'tin_format': 'XXAAAAAAAAAAXXX'},
}

# ── Models ────────────────────────────────────────────────────────────────────

class Business(db.Model):
    __tablename__ = 'businesses'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    region = db.Column(db.String(5), default='MV')
    base_currency = db.Column(db.String(3), default='MVR')
    tax_id = db.Column(db.String(50))
    has_inventory = db.Column(db.Boolean, default=False)
    has_payroll = db.Column(db.Boolean, default=False)
    has_pos = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    users = db.relationship('User', backref='business', lazy=True)
    documents = db.relationship('Document', backref='business', lazy=True)
    ledger_entries = db.relationship('LedgerEntry', backref='business', lazy=True)
    products = db.relationship('Product', backref='business', lazy=True)
    employees = db.relationship('Employee', backref='business', lazy=True)

    def tax_rules(self):
        return TAX_RULES.get(self.region, TAX_RULES['MV'])


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    business_id = db.Column(db.Integer, db.ForeignKey('businesses.id'))
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), default='owner')
    plan = db.Column(db.String(20), default='free')
    uploads_this_month = db.Column(db.Integer, default=0)
    uploads_reset_date = db.Column(db.DateTime)
    plan_activated_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, pw): self.password_hash = generate_password_hash(pw)
    def check_password(self, pw): return check_password_hash(self.password_hash, pw)
    def get_plan(self): return PLANS.get(self.plan, PLANS['free'])

    def can_upload(self):
        self._reset_uploads_if_needed()
        plan = self.get_plan()
        return (self.uploads_this_month or 0) < plan['uploads']

    def uploads_remaining(self):
        self._reset_uploads_if_needed()
        plan = self.get_plan()
        if plan['uploads'] >= 9999: return 9999
        return max(0, plan['uploads'] - (self.uploads_this_month or 0))

    def _reset_uploads_if_needed(self):
        now = datetime.utcnow()
        if not self.uploads_reset_date or now >= self.uploads_reset_date:
            self.uploads_this_month = 0
            next_month = datetime(now.year, now.month, 1) + timedelta(days=32)
            self.uploads_reset_date = next_month.replace(day=1)
            try: db.session.commit()
            except: pass

    def increment_uploads(self):
        self._reset_uploads_if_needed()
        self.uploads_this_month = (self.uploads_this_month or 0) + 1
        db.session.commit()


class Document(db.Model):
    __tablename__ = 'documents'
    id = db.Column(db.Integer, primary_key=True)
    business_id = db.Column(db.Integer, db.ForeignKey('businesses.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    doc_type = db.Column(db.String(20), default='BILL')
    vendor_name = db.Column(db.String(200))
    vendor_tax_id = db.Column(db.String(50))
    invoice_number = db.Column(db.String(100))
    invoice_date = db.Column(db.Date)
    due_date = db.Column(db.Date)
    currency = db.Column(db.String(3), default='MVR')
    subtotal = db.Column(db.Numeric(12, 2), default=0)
    tax_amount = db.Column(db.Numeric(12, 2), default=0)
    total_amount = db.Column(db.Numeric(12, 2), default=0)
    # Global Compliance Engine — IRN, QR codes, PINT-AE, e-Fapiao, MIRA fields
    compliance_data = db.Column(db.Text, default='{}')
    raw_ai_data = db.Column(db.Text)
    status = db.Column(db.String(20), default='PENDING')
    ledger_posted = db.Column(db.Boolean, default=False)
    xero_id = db.Column(db.String(50))
    zoho_id = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref='documents')

    def get_compliance_data(self):
        try: return json.loads(self.compliance_data or '{}')
        except: return {}


class LedgerEntry(db.Model):
    __tablename__ = 'ledger_entries'
    id = db.Column(db.Integer, primary_key=True)
    business_id = db.Column(db.Integer, db.ForeignKey('businesses.id'))
    document_id = db.Column(db.Integer, db.ForeignKey('documents.id'), nullable=True)
    entry_type = db.Column(db.String(20))  # REVENUE, EXPENSE, PAYROLL, TAX, SALE
    amount = db.Column(db.Numeric(12, 2))
    tax_amount = db.Column(db.Numeric(12, 2), default=0)
    currency = db.Column(db.String(3), default='MVR')
    description = db.Column(db.String(255))
    category = db.Column(db.String(100))
    is_reconciled = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    document = db.relationship('Document', backref='ledger_entries')


class Product(db.Model):
    __tablename__ = 'inventory'
    id = db.Column(db.Integer, primary_key=True)
    business_id = db.Column(db.Integer, db.ForeignKey('businesses.id'))
    sku = db.Column(db.String(50), index=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    category = db.Column(db.String(50))
    stock_level = db.Column(db.Integer, default=0)
    reorder_level = db.Column(db.Integer, default=10)
    unit_cost = db.Column(db.Numeric(12, 2), default=0)
    unit_price = db.Column(db.Numeric(12, 2), default=0)
    currency = db.Column(db.String(3), default='MVR')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Sale(db.Model):
    __tablename__ = 'sales'
    id = db.Column(db.Integer, primary_key=True)
    business_id = db.Column(db.Integer, db.ForeignKey('businesses.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    total_sale = db.Column(db.Numeric(12, 2))
    tax_amount = db.Column(db.Numeric(12, 2), default=0)
    currency = db.Column(db.String(3), default='MVR')
    payment_method = db.Column(db.String(20), default='Cash')
    note = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    items = db.Column(db.Text)


class Employee(db.Model):
    __tablename__ = 'employees'
    id = db.Column(db.Integer, primary_key=True)
    business_id = db.Column(db.Integer, db.ForeignKey('businesses.id'))
    full_name = db.Column(db.String(100), nullable=False)
    employee_id = db.Column(db.String(50))
    position = db.Column(db.String(100))
    department = db.Column(db.String(100))
    nationality = db.Column(db.String(50))
    passport_number = db.Column(db.String(50))
    visa_number = db.Column(db.String(50))
    visa_expiry = db.Column(db.Date)
    work_permit_number = db.Column(db.String(50))
    work_permit_expiry = db.Column(db.Date)
    id_card_number = db.Column(db.String(50))
    phone = db.Column(db.String(30))
    email = db.Column(db.String(150))
    monthly_salary = db.Column(db.Numeric(12, 2))
    allowances = db.Column(db.Numeric(12, 2), default=0)
    currency = db.Column(db.String(3), default='MVR')
    joined_date = db.Column(db.Date)
    contract_end_date = db.Column(db.Date)
    employment_type = db.Column(db.String(20), default='Full-time')
    is_active = db.Column(db.Boolean, default=True)


class PayrollEntry(db.Model):
    __tablename__ = 'payroll'
    id = db.Column(db.Integer, primary_key=True)
    business_id = db.Column(db.Integer, db.ForeignKey('businesses.id'))
    employee_id = db.Column(db.Integer, db.ForeignKey('employees.id'))
    period_month = db.Column(db.Integer)
    period_year = db.Column(db.Integer)
    base_salary = db.Column(db.Numeric(12, 2))
    allowances = db.Column(db.Numeric(12, 2), default=0)
    deductions = db.Column(db.Numeric(12, 2), default=0)
    net_pay = db.Column(db.Numeric(12, 2))
    currency = db.Column(db.String(3), default='MVR')
    paid_date = db.Column(db.Date)
    status = db.Column(db.String(20), default='PENDING')
    employee = db.relationship('Employee', backref='payroll_entries')


with app.app_context():
    try:
        db.create_all()
        print('LEDGR database ready')
    except Exception as e:
        print(f'DB error: {e}')


# ── Auth helpers ──────────────────────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


def current_user():
    if 'user_id' in session:
        return User.query.get(session['user_id'])
    return None


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = current_user()
        if not user or user.email != ADMIN_EMAIL:
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated


# ── AI Engine ─────────────────────────────────────────────────────────────────

def extract_document_with_ai(file_b64, media_type, region='MV'):
    tax = TAX_RULES.get(region, TAX_RULES['MV'])
    compliance_hint = {
        'MV': 'Extract MIRA TIN (format: XXXXXXXGSTXXX). Note GST category code (GST501-GST505).',
        'AE': 'Extract TRN number (15 digits). Note VAT registration, supply type, PINT-AE fields if visible.',
        'PK': 'Extract NTN/STRN. Extract FBR IRN and QR code data if visible. Note section 153 withholding rate.',
        'CN': 'Extract Fapiao number and seller tax ID (18 digits). Note e-Fapiao verification code if visible.',
        'LK': 'Extract VAT registration number (9 digits). Note SVT number if applicable.',
        'IN': 'Extract GSTIN (15 characters). Note HSN/SAC codes and reverse charge if applicable.',
    }.get(region, '')

    prompt = f'''You are LEDGR, an expert AI accountant for {tax["name"]} businesses.
Analyse this document and extract ALL financial data with compliance fields.
Rules: currency={tax["currency"]}, tax={tax["tax_name"]} at {tax["tax_rate"]*100}%, authority={tax["authority"]}.
{compliance_hint}

Return ONLY valid JSON (no extra text):
{{
  "doc_type": "BILL",
  "vendor_name": "vendor name",
  "vendor_tax_id": "tax id or null",
  "invoice_number": "invoice number",
  "invoice_date": "YYYY-MM-DD",
  "due_date": "YYYY-MM-DD or null",
  "currency": "{tax["currency"]}",
  "subtotal": 0.00,
  "tax_amount": 0.00,
  "total_amount": 0.00,
  "category": "Office Supplies",
  "confidence": "high",
  "notes": "",
  "line_items": [{{"description": "item", "quantity": 1, "unit_price": 0.00, "total": 0.00}}],
  "compliance_data": {{
    "irn": "IRN or FBR number if visible",
    "qr_code": "QR code data if visible",
    "withholding_rate": null,
    "supply_type": "standard",
    "verified": false,
    "region_specific": {{}}
  }}
}}

doc_type: BILL, RECEIPT, INVOICE, PAYROLL_SLIP, or BANK_STATEMENT
category: Office Supplies, Utilities, Travel, Meals, Professional Services, Inventory Purchase, Payroll, Tax Payment, or Other
confidence: high if document is clear, low if blurry or incomplete'''

    content_item = (
        {'type': 'document', 'source': {'type': 'base64', 'media_type': 'application/pdf', 'data': file_b64}}
        if media_type == 'application/pdf' else
        {'type': 'image', 'source': {'type': 'base64', 'media_type': media_type, 'data': file_b64}}
    )

    req_body = json.dumps({
        'model': 'claude-sonnet-4-20250514',
        'max_tokens': 4096,
        'messages': [{'role': 'user', 'content': [content_item, {'type': 'text', 'text': prompt}]}]
    }).encode()

    req = urllib.request.Request('https://api.anthropic.com/v1/messages',
        data=req_body,
        headers={
            'Content-Type': 'application/json',
            'x-api-key': ANTHROPIC_KEY,
            'anthropic-version': '2023-06-01'
        })

    with urllib.request.urlopen(req) as resp:
        result = json.loads(resp.read())
        text = result['content'][0]['text']
        match = re.search(r'\{[\s\S]*\}', text)
        if not match:
            raise ValueError('Could not parse AI response')
        return json.loads(match.group())


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        business_name = request.form.get('business_name', '').strip()
        region = request.form.get('region', 'MV')

        if not name or not email or not password or not business_name:
            flash('Please fill in all required fields', 'error')
            return render_template('register.html', regions=TAX_RULES)

        if User.query.filter_by(email=email).first():
            flash('An account with this email already exists', 'error')
            return render_template('register.html', regions=TAX_RULES)

        tax = TAX_RULES.get(region, TAX_RULES['MV'])
        business = Business(
            name=business_name,
            region=region,
            base_currency=tax['currency']
        )
        db.session.add(business)
        db.session.flush()

        user = User(name=name, email=email, business_id=business.id, role='owner')
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        session['user_id'] = user.id
        session['business_id'] = business.id
        session['user_name'] = user.name
        session['plan'] = 'Free'
        session.permanent = True
        flash(f'Welcome to LEDGR, {name}! Your business workspace is ready.', 'success')
        return redirect(url_for('dashboard'))

    return render_template('register.html', regions=TAX_RULES)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            session['user_id'] = user.id
            session['business_id'] = user.business_id
            session['user_name'] = user.name
            session['plan'] = user.plan.title()
            session.permanent = True
            return redirect(url_for('dashboard'))
        flash('Invalid email or password', 'error')
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():
    user = current_user()
    business = user.business
    tax = business.tax_rules()

    total_docs = Document.query.filter_by(business_id=business.id).count()
    total_expense = db.session.query(db.func.sum(LedgerEntry.amount)).filter_by(
        business_id=business.id, entry_type='EXPENSE').scalar() or 0
    total_revenue = db.session.query(db.func.sum(LedgerEntry.amount)).filter_by(
        business_id=business.id, entry_type='REVENUE').scalar() or 0
    pending_docs = Document.query.filter_by(business_id=business.id, status='PENDING').count()

    recent_docs = Document.query.filter_by(business_id=business.id).order_by(
        Document.created_at.desc()).limit(8).all()

    return render_template('dashboard.html', user=user, business=business, tax=tax,
                           total_docs=total_docs, total_expense=total_expense,
                           total_revenue=total_revenue, pending_docs=pending_docs,
                           recent_docs=recent_docs, plan=user.get_plan())


@app.route('/upload')
@login_required
def upload():
    user = current_user()
    business = user.business
    return render_template('upload.html', user=user, business=business,
                           tax=business.tax_rules(), plan=user.get_plan())


@app.route('/ledger')
@login_required
def ledger():
    user = current_user()
    business = user.business
    entries = LedgerEntry.query.filter_by(business_id=business.id).order_by(
        LedgerEntry.timestamp.desc()).limit(100).all()
    total_expense = db.session.query(db.func.sum(LedgerEntry.amount)).filter_by(
        business_id=business.id, entry_type='EXPENSE').scalar() or 0
    total_revenue = db.session.query(db.func.sum(LedgerEntry.amount)).filter_by(
        business_id=business.id, entry_type='REVENUE').scalar() or 0
    return render_template('ledger.html', user=user, business=business,
                           entries=entries, total_expense=total_expense,
                           total_revenue=total_revenue, tax=business.tax_rules())


@app.route('/inventory')
@login_required
def inventory():
    user = current_user()
    business = user.business
    products = Product.query.filter_by(business_id=business.id).order_by(Product.name).all()
    low_stock = [p for p in products if p.stock_level <= p.reorder_level]
    return render_template('inventory.html', user=user, business=business,
                           products=products, low_stock=low_stock)


@app.route('/payroll')
@login_required
def payroll():
    user = current_user()
    business = user.business
    employees = Employee.query.filter_by(business_id=business.id, is_active=True).all()
    total_payroll = sum(float(e.monthly_salary or 0) for e in employees)
    return render_template('payroll.html', user=user, business=business,
                           employees=employees, total_payroll=total_payroll)


@app.route('/settings')
@login_required
def settings():
    user = current_user()
    business = user.business
    return render_template('settings.html', user=user, business=business,
                           tax=business.tax_rules(), regions=TAX_RULES)


# ── API Endpoints ─────────────────────────────────────────────────────────────

@app.route('/api/upload', methods=['POST'])
@login_required
def api_upload():
    user = current_user()
    business = user.business

    if not user.can_upload():
        return jsonify({'ok': False, 'error': f'Upload limit reached. Upgrade your plan to continue.',
                        'upgrade': True})

    if not ANTHROPIC_KEY:
        return jsonify({'ok': False, 'error': 'AI engine not configured'})

    data = request.get_json()
    file_b64 = data.get('file')
    media_type = data.get('media_type', 'image/jpeg')

    try:
        extracted = extract_document_with_ai(file_b64, media_type, business.region)
        user.increment_uploads()

        inv_date = None
        due_date = None
        try:
            if extracted.get('invoice_date'):
                inv_date = datetime.strptime(extracted['invoice_date'], '%Y-%m-%d').date()
            if extracted.get('due_date'):
                due_date = datetime.strptime(extracted['due_date'], '%Y-%m-%d').date()
        except:
            pass

        doc = Document(
            business_id=business.id,
            user_id=user.id,
            doc_type=extracted.get('doc_type', 'BILL'),
            vendor_name=extracted.get('vendor_name', ''),
            vendor_tax_id=extracted.get('vendor_tax_id'),
            invoice_number=extracted.get('invoice_number', ''),
            invoice_date=inv_date,
            due_date=due_date,
            currency=extracted.get('currency', business.base_currency),
            subtotal=float(extracted.get('subtotal') or 0),
            tax_amount=float(extracted.get('tax_amount') or 0),
            total_amount=float(extracted.get('total_amount') or 0),
            compliance_data=json.dumps(extracted.get('compliance_data', {})),
            raw_ai_data=json.dumps(extracted),
            status='PROCESSED'
        )
        db.session.add(doc)
        db.session.flush()

        entry = LedgerEntry(
            business_id=business.id,
            document_id=doc.id,
            entry_type='EXPENSE',
            amount=float(extracted.get('total_amount') or 0),
            tax_amount=float(extracted.get('tax_amount') or 0),
            currency=extracted.get('currency', business.base_currency),
            description=f"{extracted.get('doc_type','BILL')} — {extracted.get('vendor_name','')}",
            category=extracted.get('category', 'Other')
        )
        db.session.add(entry)
        doc.ledger_posted = True
        db.session.commit()

        return jsonify({
            'ok': True,
            'document_id': doc.id,
            'extracted': extracted,
            'ledger_id': entry.id,
            'uploads_remaining': user.uploads_remaining(),
            'message': f'Document processed and posted to your LEDGR. {extracted.get("confidence","").upper()} confidence extraction.'
        })

    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})


@app.route('/api/ledger/summary')
@login_required
def api_ledger_summary():
    user = current_user()
    business = user.business
    month = request.args.get('month', datetime.utcnow().month)
    year = request.args.get('year', datetime.utcnow().year)

    entries = LedgerEntry.query.filter(
        LedgerEntry.business_id == business.id,
        db.extract('month', LedgerEntry.timestamp) == month,
        db.extract('year', LedgerEntry.timestamp) == year
    ).all()

    summary = {}
    for e in entries:
        cat = e.category or 'Other'
        if cat not in summary:
            summary[cat] = {'expense': 0, 'revenue': 0, 'count': 0}
        if e.entry_type == 'EXPENSE':
            summary[cat]['expense'] += float(e.amount or 0)
        elif e.entry_type == 'REVENUE':
            summary[cat]['revenue'] += float(e.amount or 0)
        summary[cat]['count'] += 1

    return jsonify({'ok': True, 'summary': summary, 'currency': business.base_currency})


@app.route('/api/inventory/update', methods=['POST'])
@login_required
def api_inventory_update():
    user = current_user()
    data = request.get_json()
    product_id = data.get('product_id')

    if product_id:
        product = Product.query.filter_by(id=product_id, business_id=user.business_id).first()
        if product:
            product.stock_level = data.get('stock_level', product.stock_level)
            product.unit_price = data.get('unit_price', product.unit_price)
            db.session.commit()
            return jsonify({'ok': True, 'message': 'Inventory updated'})
    else:
        product = Product(
            business_id=user.business_id,
            sku=data.get('sku', ''),
            name=data.get('name', ''),
            category=data.get('category', ''),
            stock_level=data.get('stock_level', 0),
            reorder_level=data.get('reorder_level', 10),
            unit_cost=data.get('unit_cost', 0),
            unit_price=data.get('unit_price', 0),
            currency=user.business.base_currency
        )
        db.session.add(product)
        db.session.commit()
        return jsonify({'ok': True, 'product_id': product.id, 'message': 'Product added'})

    return jsonify({'ok': False, 'error': 'Product not found'})


@app.route('/api/employee/add', methods=['POST'])
@login_required
def api_employee_add():
    user = current_user()
    data = request.get_json()

    def parse_date(d):
        try: return datetime.strptime(d, '%Y-%m-%d').date() if d else None
        except: return None

    employee = Employee(
        business_id=user.business_id,
        full_name=data.get('full_name', ''),
        employee_id=data.get('employee_id', ''),
        position=data.get('position', ''),
        department=data.get('department', ''),
        nationality=data.get('nationality', ''),
        passport_number=data.get('passport_number', ''),
        visa_number=data.get('visa_number', ''),
        visa_expiry=parse_date(data.get('visa_expiry')),
        work_permit_number=data.get('work_permit_number', ''),
        work_permit_expiry=parse_date(data.get('work_permit_expiry')),
        id_card_number=data.get('id_card_number', ''),
        phone=data.get('phone', ''),
        email=data.get('email', ''),
        monthly_salary=data.get('monthly_salary', 0),
        allowances=data.get('allowances', 0),
        currency=user.business.base_currency,
        joined_date=parse_date(data.get('joined_date')),
        contract_end_date=parse_date(data.get('contract_end_date')),
        employment_type=data.get('employment_type', 'Full-time')
    )
    db.session.add(employee)

    entry = LedgerEntry(
        business_id=user.business_id,
        entry_type='PAYROLL',
        amount=float(data.get('monthly_salary', 0)),
        currency=user.business.base_currency,
        description=f'Employee added: {data.get("full_name","")}',
        category='Payroll'
    )
    db.session.add(entry)
    db.session.commit()

    return jsonify({'ok': True, 'employee_id': employee.id, 'message': 'Employee added to LEDGR'})


@app.route('/api/status')
@login_required
def api_status():
    user = current_user()
    return jsonify({
        'ok': True,
        'plan': user.plan,
        'uploads_remaining': user.uploads_remaining(),
        'region': user.business.region,
        'currency': user.business.base_currency
    })


# ── Admin ─────────────────────────────────────────────────────────────────────

@app.route('/admin')
@login_required
@admin_required
def admin():
    users = User.query.order_by(User.created_at.desc()).all()
    businesses = Business.query.all()
    total_docs = Document.query.count()
    stats = {
        'total_users': len(users),
        'total_businesses': len(businesses),
        'total_docs': total_docs,
        'free_users': sum(1 for u in users if u.plan == 'free'),
        'pro_users': sum(1 for u in users if u.plan == 'pro'),
        'business_users': sum(1 for u in users if u.plan == 'business'),
    }
    return render_template('admin.html', users=users, stats=stats, plans=PLANS)


@app.route('/admin/api/upgrade', methods=['POST'])
@login_required
@admin_required
def admin_upgrade():
    data = request.get_json()
    user = User.query.get(data.get('user_id'))
    if not user:
        return jsonify({'ok': False, 'error': 'User not found'})
    user.plan = data.get('plan', 'free')
    user.plan_activated_at = datetime.utcnow()
    db.session.commit()
    return jsonify({'ok': True, 'message': f'Plan updated to {user.plan}'})


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

# ── Upgrade request ───────────────────────────────────────────────────────────

@app.route('/api/request-upgrade', methods=['POST'])
@login_required
def api_request_upgrade():
    user = current_user()
    data = request.get_json()
    plan = data.get('plan', 'pro')
    print(f'UPGRADE REQUEST: {user.name} ({user.email}) → {plan}')
    return jsonify({
        'ok': True,
        'message': f'Upgrade request for {plan.title()} plan received. We will contact you at {user.email} within 24 hours.'
    })
