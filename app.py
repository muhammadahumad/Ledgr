import os, json, base64, urllib.request, urllib.parse, urllib.error, re
from decimal import Decimal, ROUND_HALF_UP
from datetime import datetime, timedelta, date
from functools import wraps
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import secrets

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
db_url = os.environ.get('DATABASE_URL', 'sqlite:///ledgr.db')
if db_url.startswith('postgres://'): db_url = db_url.replace('postgres://', 'postgresql://', 1)
app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)

@app.template_filter('from_json')
def from_json_filter(value):
    """Parse JSON string in templates"""
    try:
        import json as _json
        if isinstance(value, str):
            return _json.loads(value)
        return value
    except:
        return {}
db = SQLAlchemy(app)

ANTHROPIC_KEY = os.environ.get('ANTHROPIC_KEY', '')
ADMIN_EMAIL   = os.environ.get('ADMIN_EMAIL', 'muahumadhu@gmail.com')

# ── Config dicts ──────────────────────────────────────────────────────────────
TAX_RULES = {
    'MV': {'name':'Maldives','currency':'MVR','tax_name':'GST','tax_rate':0.08,
           'tax_rate_tourism':0.17,'authority':'MIRA','tin_format':'XXXXXXXGSTXXX',
           'threshold':1000000,'filing':'monthly',
           'requires_dual_tin':True,'rtl':False},
    'AE': {'name':'UAE','currency':'AED','tax_name':'VAT','tax_rate':0.05,
           'authority':'FTA','tin_format':'100XXXXXXXXXXXX',
           'threshold':375000,'filing':'quarterly',
           'requires_dual_tin':True,'rtl':True,'emirate_required':True},
    'SA': {'name':'Saudi Arabia','currency':'SAR','tax_name':'VAT','tax_rate':0.15,
           'authority':'ZATCA','tin_format':'3XXXXXXXXXXXXX3',
           'threshold':0,'filing':'monthly',
           'requires_dual_tin':True,'rtl':True,'zatca_phase2':True},
    'PK': {'name':'Pakistan','currency':'PKR','tax_name':'GST','tax_rate':0.18,
           'tax_rate_luxury':0.25,'authority':'FBR','tin_format':'XXXXXXX-X',
           'threshold':8000000,'filing':'monthly',
           'requires_dual_tin':True,'rtl':False},
    'OM': {'name':'Oman','currency':'OMR','tax_name':'VAT','tax_rate':0.05,
           'authority':'Tax Oman','tin_format':'OMXXXXXXXXXXXXXXX',
           'threshold':38500,'filing':'quarterly',
           'requires_dual_tin':True,'rtl':True},
    'CN': {'name':'China','currency':'CNY','tax_name':'VAT','tax_rate':0.13,
           'authority':'SAT','tin_format':'XXXXXXXXXXXXXXXXXX',
           'threshold':500000,'filing':'monthly',
           'requires_dual_tin':True,'rtl':False},
    'LK': {'name':'Sri Lanka','currency':'LKR','tax_name':'VAT','tax_rate':0.18,
           'authority':'IRD','tin_format':'XXXXXXXXX',
           'threshold':80000000,'filing':'monthly',
           'requires_dual_tin':False,'rtl':False},
    'IN': {'name':'India','currency':'INR','tax_name':'GST','tax_rate':0.18,
           'authority':'GSTN','tin_format':'XXAAAAAAAAAAXXX',
           'threshold':2000000,'filing':'monthly',
           'requires_dual_tin':True,'rtl':False,'irn_required':True},
    'EG': {'name':'Egypt','currency':'EGP','tax_name':'VAT','tax_rate':0.14,
           'authority':'ETA','tin_format':'XXXXXXXXX',
           'threshold':500000,'filing':'monthly',
           'requires_dual_tin':True,'rtl':False},
    'ID': {'name':'Indonesia','currency':'IDR','tax_name':'PPN','tax_rate':0.11,
           'authority':'DGT','tin_format':'XX.XXX.XXX.X-XXX.XXX',
           'threshold':4800000000,'filing':'monthly',
           'requires_dual_tin':True,'rtl':False,'nsfp_required':True},
}
TAX_THRESHOLDS = {
    'MV':{'amount':1000000,'currency':'MVR','authority':'MIRA','tax':'GST'},
    'AE':{'amount':375000, 'currency':'AED','authority':'FTA', 'tax':'VAT'},
    'PK':{'amount':8000000,'currency':'PKR','authority':'FBR', 'tax':'GST'},
    'CN':{'amount':500000, 'currency':'CNY','authority':'SAT', 'tax':'VAT'},
    'LK':{'amount':80000000,'currency':'LKR','authority':'IRD','tax':'VAT'},
    'IN':{'amount':2000000,'currency':'INR','authority':'CBIC','tax':'GST'},
}
BUSINESS_TYPES = {
    'sole_proprietor':{'name':'Sole Proprietor','accounting':'simple'},
    'partnership':    {'name':'Partnership',    'accounting':'standard'},
    'limited_company':{'name':'Limited Company','accounting':'full'},
    'llc':            {'name':'LLC',            'accounting':'full'},
    'cooperative':    {'name':'Cooperative',    'accounting':'standard'},
    'ngo':            {'name':'NGO / Non-Profit','accounting':'standard'},
    'other':          {'name':'Other',          'accounting':'simple'},
}

INDUSTRY_TYPES = {
    'general':      {'name':'General Business',    'service_charge':False, 'expiry_tracking':False, 'archetype':'general'},
    'hospitality':  {'name':'Hospitality / F&B',   'service_charge':True,  'expiry_tracking':False, 'archetype':'hospitality'},
    'retail':       {'name':'Retail / Grocery',     'service_charge':False, 'expiry_tracking':False, 'archetype':'retail'},
    'healthcare':   {'name':'Healthcare / Pharmacy','service_charge':False, 'expiry_tracking':True,  'archetype':'healthcare'},
    'construction': {'name':'Construction / Trade', 'service_charge':False, 'expiry_tracking':False, 'archetype':'construction'},
    'professional': {'name':'Professional Services','service_charge':False, 'expiry_tracking':False, 'archetype':'professional'},
    'education':    {'name':'Education',            'service_charge':False, 'expiry_tracking':False, 'archetype':'education'},
    'logistics':    {'name':'Logistics / Delivery', 'service_charge':False, 'expiry_tracking':False, 'archetype':'logistics'},
}

# Industry-specific Chart of Accounts additions
INDUSTRY_COA = {
    'hospitality': [
        ('2120', 'Service Charge Payable', 'LIABILITY'),
        ('4010', 'Food & Beverage Revenue', 'REVENUE'),
        ('4020', 'Service Charge Collected', 'REVENUE'),
        ('5010', 'Food & Beverage Cost', 'EXPENSE'),
        ('5020', 'Kitchen Supplies', 'EXPENSE'),
    ],
    'healthcare': [
        ('1210', 'Inventory - Medicine', 'ASSET'),
        ('1220', 'Inventory - Medical Supplies', 'ASSET'),
        ('4030', 'Dispensing Revenue', 'REVENUE'),
        ('4040', 'Consultation Revenue', 'REVENUE'),
        ('5030', 'Medicine Purchases', 'EXPENSE'),
    ],
    'retail': [
        ('1230', 'Inventory - Goods for Resale', 'ASSET'),
        ('4050', 'Retail Sales Revenue', 'REVENUE'),
        ('5040', 'Purchases - Goods for Resale', 'EXPENSE'),
        ('5050', 'Shrinkage & Write-offs', 'EXPENSE'),
    ],
    'construction': [
        ('1240', 'Construction Materials', 'ASSET'),
        ('1250', 'Work in Progress', 'ASSET'),
        ('4060', 'Contract Revenue', 'REVENUE'),
        ('5060', 'Materials Cost', 'EXPENSE'),
        ('5070', 'Subcontractor Costs', 'EXPENSE'),
        ('5080', 'Equipment Rental', 'EXPENSE'),
    ],
}

PLANS = {
    'free':    {'name':'Free',    'price':0, 'uploads':10,   'businesses':1},
    'pro':     {'name':'Pro',     'price':15,'uploads':500,  'businesses':10},
    'business':{'name':'Business','price':35,'uploads':99999,'businesses':99999},
}
DEFAULT_COA = {
    'ASSET':    [('1000','Cash on Hand'),('1010','Bank Account - Primary'),('1020','Bank Account - Secondary'),
                 ('1100','Accounts Receivable'),('1110','Customer Tabs (Credit Sales)'),
                 ('1200','Inventory'),('1300','Prepaid Expenses'),
                 ('1500','Fixed Assets'),('1510','Equipment'),('1520','Furniture & Fittings')],
    'LIABILITY':[('2000','Accounts Payable'),('2100','Accrued Expenses'),
                 ('2210','GST/VAT Payable'),('2300','Salaries Payable'),
                 ('2400','Short-term Loans'),('2500','Long-term Loans')],
    'EQUITY':   [('3000','Owner Capital'),('3100','Retained Earnings'),
                 ('3200','Current Year Profit/Loss'),('3300','Owner Drawings')],
    'REVENUE':  [('4000','Sales Revenue'),('4010','Service Revenue'),('4020','Other Income')],
    'EXPENSE':  [('5000','Cost of Goods Sold'),('5100','Salaries & Wages'),('5110','Allowances'),
                 ('5200','Rent'),('5300','Utilities'),('5400','Office Supplies'),
                 ('5500','Marketing'),('5600','Professional Services'),
                 ('5700','Travel'),('5800','Meals & Entertainment'),
                 ('5900','Bank Charges'),('6000','Depreciation'),('6200','Tax Expense'),('6900','Miscellaneous')],
}

# ── Models ────────────────────────────────────────────────────────────────────
class Business(db.Model):
    __tablename__ = 'businesses'
    id = db.Column(db.Integer, primary_key=True)
    # Core identity
    name = db.Column(db.String(100), nullable=False)
    legal_name = db.Column(db.String(200))           # Full legal registered name
    business_type = db.Column(db.String(30), default='sole_proprietor')
    region = db.Column(db.String(5), default='MV')
    base_currency = db.Column(db.String(3), default='MVR')
    secondary_currency = db.Column(db.String(3))     # e.g. USD for Maldives businesses
    # Legal registration
    registration_number = db.Column(db.String(100))  # Company reg number
    tax_id = db.Column(db.String(50))                # General tax ID
    tax_registration_number = db.Column(db.String(50))  # GST/VAT reg number
    tax_registration_date = db.Column(db.Date)
    # Address
    address_line1 = db.Column(db.String(200))
    address_line2 = db.Column(db.String(200))
    city = db.Column(db.String(100))
    country = db.Column(db.String(100))
    phone = db.Column(db.String(30))
    email = db.Column(db.String(150))
    website = db.Column(db.String(200))
    # Branding
    logo_data = db.Column(db.Text)                   # base64 logo
    logo_type = db.Column(db.String(30))             # image/png etc
    # Banking
    bank_name = db.Column(db.String(100))
    bank_account_name = db.Column(db.String(100))
    bank_account_number = db.Column(db.String(50))
    bank_swift = db.Column(db.String(20))
    # Invoice settings
    invoice_prefix = db.Column(db.String(10), default='INV')
    quote_prefix = db.Column(db.String(10), default='QUO')
    invoice_notes = db.Column(db.Text)               # Default payment terms
    invoice_counter = db.Column(db.Integer, default=0)
    quote_counter = db.Column(db.Integer, default=0)
    # Module toggles
    industry_type = db.Column(db.String(30), default='general')
    has_inventory = db.Column(db.Boolean, default=False)
    has_payroll = db.Column(db.Boolean, default=False)
    has_pos = db.Column(db.Boolean, default=True)
    has_full_accounting = db.Column(db.Boolean, default=False)
    has_service_charge = db.Column(db.Boolean, default=False)
    service_charge_rate = db.Column(db.Numeric(5,4), default=0.10)
    has_expiry_tracking = db.Column(db.Boolean, default=False)
    has_multi_location = db.Column(db.Boolean, default=False)
    # Tax settings
    is_tax_registered = db.Column(db.Boolean, default=False)
    collect_tax_on_sales = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def tax_rules(self): return TAX_RULES.get(self.region, TAX_RULES['MV'])
    def btype(self): return BUSINESS_TYPES.get(self.business_type, BUSINESS_TYPES['sole_proprietor'])
    def btype_name(self): return self.btype()['name']
    def btype_accounting(self): return self.btype()['accounting']
    def industry(self): return INDUSTRY_TYPES.get(self.industry_type or 'general', INDUSTRY_TYPES['general'])
    def display_name(self): return self.legal_name or self.name
    def full_address(self):
        parts = [p for p in [self.address_line1, self.address_line2, self.city, self.country] if p]
        return ', '.join(parts)
    def next_invoice_number(self):
        self.invoice_counter = (self.invoice_counter or 0) + 1
        db.session.commit()
        return f"{self.invoice_prefix or 'INV'}-{datetime.utcnow().year}-{self.invoice_counter:04d}"
    def next_quote_number(self):
        self.quote_counter = (self.quote_counter or 0) + 1
        db.session.commit()
        return f"{self.quote_prefix or 'QUO'}-{datetime.utcnow().year}-{self.quote_counter:04d}" 

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
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    business = db.relationship('Business', backref='users', foreign_keys=[business_id])
    def set_password(self, pw): self.password_hash = generate_password_hash(pw)
    def check_password(self, pw): return check_password_hash(self.password_hash, pw)
    def get_plan(self): return PLANS.get(self.plan, PLANS['free'])
    def _reset_uploads(self):
        now = datetime.utcnow()
        if not self.uploads_reset_date or now >= self.uploads_reset_date:
            self.uploads_this_month = 0
            nxt = datetime(now.year, now.month, 1) + timedelta(days=32)
            self.uploads_reset_date = nxt.replace(day=1)
            try: db.session.commit()
            except: pass
    def can_upload(self):
        self._reset_uploads()
        return (self.uploads_this_month or 0) < self.get_plan()['uploads']
    def uploads_remaining(self):
        self._reset_uploads()
        p = self.get_plan()
        return 9999 if p['uploads'] >= 9999 else max(0, p['uploads'] - (self.uploads_this_month or 0))
    def increment_uploads(self):
        self._reset_uploads()
        self.uploads_this_month = (self.uploads_this_month or 0) + 1
        db.session.commit()

class UserBusiness(db.Model):
    __tablename__ = 'user_businesses'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    business_id = db.Column(db.Integer, db.ForeignKey('businesses.id'), nullable=False)
    role = db.Column(db.String(20), default='owner')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    business = db.relationship('Business', backref='memberships')
    user = db.relationship('User', backref='memberships')

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
    subtotal = db.Column(db.Numeric(12,2), default=0)
    tax_amount = db.Column(db.Numeric(12,2), default=0)
    total_amount = db.Column(db.Numeric(12,2), default=0)
    compliance_data = db.Column(db.Text, default='{}')
    raw_ai_data = db.Column(db.Text)
    status = db.Column(db.String(20), default='PENDING')
    ledger_posted = db.Column(db.Boolean, default=False)
    posted_to_account_id = db.Column(db.Integer, db.ForeignKey('accounts.id'), nullable=True)
    posted_to_account_name = db.Column(db.String(100))  # Cached for display
    payment_status = db.Column(db.String(20), default='UNPAID')  # UNPAID, PAID, PARTIAL
    file_data = db.Column(db.Text)  # base64 stored soft copy
    file_type = db.Column(db.String(30))  # image/jpeg, application/pdf
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref='documents')
    business = db.relationship('Business', backref='documents')

class Account(db.Model):
    __tablename__ = 'accounts'
    id = db.Column(db.Integer, primary_key=True)
    business_id = db.Column(db.Integer, db.ForeignKey('businesses.id'))
    code = db.Column(db.String(10), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    account_type = db.Column(db.String(20))
    is_active = db.Column(db.Boolean, default=True)
    opening_balance = db.Column(db.Numeric(12,2), default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    def balance(self):
        debits  = db.session.query(db.func.sum(JournalLine.debit)).filter_by(account_id=self.id).scalar() or 0
        credits = db.session.query(db.func.sum(JournalLine.credit)).filter_by(account_id=self.id).scalar() or 0
        ob = float(self.opening_balance or 0)
        return ob + float(debits) - float(credits) if self.account_type in ('ASSET','EXPENSE') else ob + float(credits) - float(debits)

class JournalEntry(db.Model):
    __tablename__ = 'journal_entries'
    id = db.Column(db.Integer, primary_key=True)
    business_id = db.Column(db.Integer, db.ForeignKey('businesses.id'))
    date = db.Column(db.DateTime, default=datetime.utcnow)
    description = db.Column(db.String(255))
    reference = db.Column(db.String(100))
    entry_type = db.Column(db.String(30))
    document_id = db.Column(db.Integer, db.ForeignKey('documents.id'), nullable=True)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    lines = db.relationship('JournalLine', backref='entry', lazy=True, cascade='all, delete-orphan')

class JournalLine(db.Model):
    __tablename__ = 'journal_lines'
    id = db.Column(db.Integer, primary_key=True)
    journal_entry_id = db.Column(db.Integer, db.ForeignKey('journal_entries.id'))
    account_id = db.Column(db.Integer, db.ForeignKey('accounts.id'))
    description = db.Column(db.String(255))
    debit  = db.Column(db.Numeric(12,2), default=0)
    credit = db.Column(db.Numeric(12,2), default=0)
    account = db.relationship('Account', backref='journal_lines')

class LedgerEntry(db.Model):
    __tablename__ = 'ledger_entries'
    id = db.Column(db.Integer, primary_key=True)
    business_id = db.Column(db.Integer, db.ForeignKey('businesses.id'))
    document_id = db.Column(db.Integer, db.ForeignKey('documents.id'), nullable=True)
    entry_type = db.Column(db.String(20))
    amount = db.Column(db.Numeric(12,2))
    tax_amount = db.Column(db.Numeric(12,2), default=0)
    currency = db.Column(db.String(3), default='MVR')
    description = db.Column(db.String(255))
    category = db.Column(db.String(100))
    is_reconciled = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)

class Product(db.Model):
    __tablename__ = 'inventory'
    id = db.Column(db.Integer, primary_key=True)
    business_id = db.Column(db.Integer, db.ForeignKey('businesses.id'))
    sku = db.Column(db.String(50))
    barcode = db.Column(db.String(50))
    name = db.Column(db.String(200), nullable=False)
    category = db.Column(db.String(50))
    unit = db.Column(db.String(20), default='pcs')  # pcs, kg, litre, box, etc
    stock_level = db.Column(db.Numeric(12,3), default=0)  # Total across all locations
    reorder_level = db.Column(db.Numeric(12,3), default=10)
    unit_cost = db.Column(db.Numeric(12,2), default=0)
    unit_price = db.Column(db.Numeric(12,2), default=0)
    currency = db.Column(db.String(3), default='MVR')
    has_expiry = db.Column(db.Boolean, default=False)
    supplier_id = db.Column(db.Integer, db.ForeignKey('suppliers.id'), nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Customer(db.Model):
    __tablename__ = 'customers'
    id = db.Column(db.Integer, primary_key=True)
    business_id = db.Column(db.Integer, db.ForeignKey('businesses.id'))
    name = db.Column(db.String(200), nullable=False)
    phone = db.Column(db.String(30))
    email = db.Column(db.String(150))
    address = db.Column(db.Text)
    city = db.Column(db.String(100))
    country = db.Column(db.String(10), default='MV')
    # Tax & compliance
    customer_type = db.Column(db.String(20), default='individual')  # individual / business
    tax_id = db.Column(db.String(100))        # TIN / TRN / GSTIN / NTN etc
    registration_number = db.Column(db.String(100))
    is_tax_registered = db.Column(db.Boolean, default=False)
    # CRM
    notes = db.Column(db.Text)
    is_vip = db.Column(db.Boolean, default=False)
    credit_limit = db.Column(db.Numeric(12,2), default=0)
    outstanding_balance = db.Column(db.Numeric(12,2), default=0)
    total_spent = db.Column(db.Numeric(12,2), default=0)
    visit_count = db.Column(db.Integer, default=0)
    last_visit = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    business = db.relationship('Business', backref='customers')
    def is_business_customer(self): return self.customer_type == 'business'



class Supplier(db.Model):
    """Vendors/Suppliers — auto-populated from document uploads"""
    __tablename__ = 'suppliers'
    id = db.Column(db.Integer, primary_key=True)
    business_id = db.Column(db.Integer, db.ForeignKey('businesses.id'))
    name = db.Column(db.String(200), nullable=False)
    tax_id = db.Column(db.String(50))           # Vendor TIN/VAT number
    email = db.Column(db.String(150))
    phone = db.Column(db.String(30))
    address = db.Column(db.Text)
    currency = db.Column(db.String(3), default='MVR')
    payment_terms = db.Column(db.String(50), default='Net 30')
    notes = db.Column(db.Text)
    total_purchases = db.Column(db.Numeric(12,2), default=0)
    is_active = db.Column(db.Boolean, default=True)
    auto_detected = db.Column(db.Boolean, default=False)  # True if added from upload
    has_transactions = db.Column(db.Boolean, default=False)  # Prevent hard delete if True
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    business = db.relationship('Business', backref='suppliers')

class POSSale(db.Model):
    __tablename__ = 'pos_sales'
    id = db.Column(db.Integer, primary_key=True)
    business_id = db.Column(db.Integer, db.ForeignKey('businesses.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    customer_id = db.Column(db.Integer, db.ForeignKey('customers.id'), nullable=True)
    amount = db.Column(db.Numeric(12,2), nullable=False)
    tax_amount = db.Column(db.Numeric(12,2), default=0)
    currency = db.Column(db.String(3), default='MVR')
    payment_method = db.Column(db.String(20), default='Cash')
    note = db.Column(db.String(200))
    category = db.Column(db.String(50), default='Sale')
    is_credit = db.Column(db.Boolean, default=False)
    location_id = db.Column(db.Integer, db.ForeignKey('locations.id'), nullable=True)
    service_charge = db.Column(db.Numeric(12,2), default=0)
    journal_entry_id = db.Column(db.Integer, db.ForeignKey('journal_entries.id'), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    customer = db.relationship('Customer', backref='sales')
    location = db.relationship('Location', backref='sales')

class Employee(db.Model):
    __tablename__ = 'employees'
    id = db.Column(db.Integer, primary_key=True)
    business_id = db.Column(db.Integer, db.ForeignKey('businesses.id'))
    # Core
    full_name = db.Column(db.String(200), nullable=False)
    employee_id = db.Column(db.String(50))
    position = db.Column(db.String(100))
    department = db.Column(db.String(100))
    location_id = db.Column(db.Integer, db.ForeignKey('locations.id'), nullable=True)
    # Employment type
    employment_type = db.Column(db.String(20), default='local')  # local / foreign
    contract_type = db.Column(db.String(20), default='permanent')  # permanent / fixed / part_time / probation
    start_date = db.Column(db.Date)
    end_date = db.Column(db.Date)
    is_active = db.Column(db.Boolean, default=True)
    # Identity
    nationality = db.Column(db.String(50))
    country_of_work = db.Column(db.String(10), default='MV')
    id_card_number = db.Column(db.String(50))
    passport_number = db.Column(db.String(50))
    passport_expiry = db.Column(db.Date)
    # Visa & Work Permit
    visa_number = db.Column(db.String(50))
    visa_type = db.Column(db.String(50))
    visa_expiry = db.Column(db.Date)
    work_permit_number = db.Column(db.String(50))
    work_permit_expiry = db.Column(db.Date)
    # Maldives-specific
    quota_slot_number = db.Column(db.String(50))
    quota_fee_paid = db.Column(db.Numeric(12,2), default=0)
    security_deposit = db.Column(db.Numeric(12,2), default=0)
    deposit_paid_date = db.Column(db.Date)
    medical_expiry = db.Column(db.Date)
    insurance_provider = db.Column(db.String(100))
    insurance_expiry = db.Column(db.Date)
    insurance_cost = db.Column(db.Numeric(12,2), default=0)
    # Contact
    phone = db.Column(db.String(30))
    email = db.Column(db.String(150))
    emergency_contact = db.Column(db.String(200))
    # Salary & Benefits
    monthly_salary = db.Column(db.Numeric(12,2))
    allowances = db.Column(db.Numeric(12,2), default=0)
    housing_allowance = db.Column(db.Numeric(12,2), default=0)
    transport_allowance = db.Column(db.Numeric(12,2), default=0)
    currency = db.Column(db.String(3), default='MVR')
    # Statutory deductions
    pension_employee = db.Column(db.Numeric(12,2), default=0)  # 7% MV, 12% IN
    pension_employer = db.Column(db.Numeric(12,2), default=0)
    social_insurance = db.Column(db.Numeric(12,2), default=0)  # GOSI, BPJS, etc
    gratuity_accrued = db.Column(db.Numeric(12,2), default=0)  # End of service
    # Bank
    bank_name = db.Column(db.String(100))
    bank_account = db.Column(db.String(50))
    # Notes
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    business = db.relationship('Business', backref='employees')

    def total_cost(self):
        """True monthly cost including all statutory contributions"""
        base = float(self.monthly_salary or 0)
        allow = float(self.allowances or 0) + float(self.housing_allowance or 0) + float(self.transport_allowance or 0)
        pension = float(self.pension_employer or 0)
        social = float(self.social_insurance or 0)
        # Amortize one-time costs over 12 months
        visa_amort = float(self.quota_fee_paid or 0) / 12
        insurance_amort = float(self.insurance_cost or 0) / 12
        deposit_amort = 0  # deposit is refundable — show separately
        return round(base + allow + pension + social + visa_amort + insurance_amort, 2)

    def days_to_visa_expiry(self):
        if not self.visa_expiry: return None
        from datetime import date
        return (self.visa_expiry - date.today()).days

    def days_to_medical_expiry(self):
        if not self.medical_expiry: return None
        from datetime import date
        return (self.medical_expiry - date.today()).days

    def compliance_alerts(self):
        alerts = []
        visa_days = self.days_to_visa_expiry()
        if visa_days is not None and visa_days <= 45:
            alerts.append({'type':'visa','days':visa_days,'msg':'Visa expires in ' + str(visa_days) + ' days'})
        med_days = self.days_to_medical_expiry()
        if med_days is not None and med_days <= 30:
            alerts.append({'type':'medical','days':med_days,'msg':'Medical report expires in ' + str(med_days) + ' days'})
        if self.work_permit_expiry:
            from datetime import date
            wp_days = (self.work_permit_expiry - date.today()).days
            if wp_days <= 45:
                alerts.append({'type':'work_permit','days':wp_days,'msg':'Work permit expires in ' + str(wp_days) + ' days'})
        return alerts

class AIConversation(db.Model):
    __tablename__ = 'ai_conversations'
    id = db.Column(db.Integer, primary_key=True)
    business_id = db.Column(db.Integer, db.ForeignKey('businesses.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    role = db.Column(db.String(10))
    message = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Invoice(db.Model):
    __tablename__ = 'invoices'
    id = db.Column(db.Integer, primary_key=True)
    business_id = db.Column(db.Integer, db.ForeignKey('businesses.id'))
    customer_id = db.Column(db.Integer, db.ForeignKey('customers.id'), nullable=True)
    # Core
    invoice_number = db.Column(db.String(50))
    po_number = db.Column(db.String(100))
    invoice_date = db.Column(db.Date, default=date.today)
    due_date = db.Column(db.Date)
    currency = db.Column(db.String(3), default='MVR')
    exchange_rate = db.Column(db.Numeric(10,4), default=1)
    subtotal = db.Column(db.Numeric(12,2), default=0)
    discount_amount = db.Column(db.Numeric(12,2), default=0)
    tax_amount = db.Column(db.Numeric(12,2), default=0)
    total_amount = db.Column(db.Numeric(12,2), default=0)
    amount_paid = db.Column(db.Numeric(12,2), default=0)
    status = db.Column(db.String(20), default='DRAFT')
    payment_terms = db.Column(db.String(100))
    notes = db.Column(db.Text)
    items = db.Column(db.Text, default='[]')
    # Global compliance — 9 countries
    legal_seller_name = db.Column(db.String(200))
    seller_trn_vat_number = db.Column(db.String(50))
    buyer_legal_name = db.Column(db.String(200))
    buyer_trn_vat_number = db.Column(db.String(50))
    irn = db.Column(db.String(100))
    qr_code_data = db.Column(db.Text)
    uuid = db.Column(db.String(100))
    cryptographic_stamp = db.Column(db.Text)
    nsfp = db.Column(db.String(100))
    hs_code = db.Column(db.String(20))
    emirate = db.Column(db.String(50))
    transaction_type_code = db.Column(db.String(20))
    supply_type = db.Column(db.String(20), default='standard')
    clearance_status = db.Column(db.String(20), default='PENDING')
    clearance_date = db.Column(db.DateTime)
    clearance_reference = db.Column(db.String(100))
    total_excl_tax_local = db.Column(db.Numeric(12,2))
    total_vat_local = db.Column(db.Numeric(12,2))
    total_incl_tax_local = db.Column(db.Numeric(12,2))
    line_items = db.Column(db.Text, default='[]')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    customer = db.relationship('Customer', backref='invoices')
    business = db.relationship('Business', backref='invoices')
    def amount_due(self): return float(self.total_amount or 0) - float(self.amount_paid or 0)



class Quotation(db.Model):
    """Estimates & Quotations — pre-sale documents"""
    __tablename__ = 'quotations'
    id = db.Column(db.Integer, primary_key=True)
    business_id = db.Column(db.Integer, db.ForeignKey('businesses.id'))
    customer_id = db.Column(db.Integer, db.ForeignKey('customers.id'), nullable=True)
    quote_number = db.Column(db.String(50))
    quote_date = db.Column(db.Date, default=date.today)
    valid_until = db.Column(db.Date)
    currency = db.Column(db.String(3), default='MVR')
    exchange_rate = db.Column(db.Numeric(10,4), default=1)
    subtotal = db.Column(db.Numeric(12,2), default=0)
    discount_amount = db.Column(db.Numeric(12,2), default=0)
    tax_amount = db.Column(db.Numeric(12,2), default=0)
    total_amount = db.Column(db.Numeric(12,2), default=0)
    status = db.Column(db.String(20), default='DRAFT')
    notes = db.Column(db.Text)
    terms = db.Column(db.Text)                   # Payment/delivery terms
    items = db.Column(db.Text, default='[]')
    converted_invoice_id = db.Column(db.Integer, db.ForeignKey('invoices.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    customer = db.relationship('Customer', backref='quotations')
    business = db.relationship('Business', backref='quotations')


class BankAccount(db.Model):
    __tablename__ = 'bank_accounts'
    id = db.Column(db.Integer, primary_key=True)
    business_id = db.Column(db.Integer, db.ForeignKey('businesses.id'))
    bank_name = db.Column(db.String(100))
    account_name = db.Column(db.String(100))
    account_number = db.Column(db.String(50))
    currency = db.Column(db.String(3), default='MVR')
    opening_balance = db.Column(db.Numeric(12,2), default=0)
    current_balance = db.Column(db.Numeric(12,2), default=0)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    business = db.relationship('Business', backref='bank_accounts')


class BankTransaction(db.Model):
    __tablename__ = 'bank_transactions'
    id = db.Column(db.Integer, primary_key=True)
    business_id = db.Column(db.Integer, db.ForeignKey('businesses.id'))
    bank_account_id = db.Column(db.Integer, db.ForeignKey('bank_accounts.id'), nullable=True)
    document_id = db.Column(db.Integer, db.ForeignKey('documents.id'), nullable=True)
    txn_date = db.Column(db.Date)
    description = db.Column(db.String(255))
    reference = db.Column(db.String(100))
    debit = db.Column(db.Numeric(12,2), default=0)
    credit = db.Column(db.Numeric(12,2), default=0)
    balance = db.Column(db.Numeric(12,2), default=0)
    category = db.Column(db.String(100))
    is_reconciled = db.Column(db.Boolean, default=False)
    journal_entry_id = db.Column(db.Integer, db.ForeignKey('journal_entries.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)



class Location(db.Model):
    """Branch / Outlet / Warehouse"""
    __tablename__ = 'locations'
    id = db.Column(db.Integer, primary_key=True)
    business_id = db.Column(db.Integer, db.ForeignKey('businesses.id'))
    name = db.Column(db.String(100), nullable=False)  # e.g. "Male Branch"
    address = db.Column(db.Text)
    location_type = db.Column(db.String(20), default='branch')  # branch / warehouse / outlet / virtual
    is_warehouse = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    business = db.relationship('Business', backref='locations')
    products = db.relationship('ProductLocation', backref='location', lazy=True)


class ProductLocation(db.Model):
    """Stock level per product per location — no shared inventory between branches"""
    __tablename__ = 'product_locations'
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('inventory.id'), nullable=False)
    location_id = db.Column(db.Integer, db.ForeignKey('locations.id'), nullable=False)
    stock_quantity = db.Column(db.Numeric(12,2), default=0)
    reorder_level = db.Column(db.Integer, default=10)
    product = db.relationship('Product', backref='location_stock')


class Payment(db.Model):
    """Records of payments made or received"""
    __tablename__ = 'payments'
    id = db.Column(db.Integer, primary_key=True)
    business_id = db.Column(db.Integer, db.ForeignKey('businesses.id'))
    payment_type = db.Column(db.String(20))  # OUTGOING (AP) / INCOMING (AR)
    payment_method = db.Column(db.String(30), default='Bank Transfer')  # Cash / Bank Transfer / Cheque / Card
    bank_account_id = db.Column(db.Integer, db.ForeignKey('bank_accounts.id'), nullable=True)
    payment_date = db.Column(db.Date, default=date.today)
    amount = db.Column(db.Numeric(12,2), nullable=False)
    currency = db.Column(db.String(3), default='MVR')
    reference = db.Column(db.String(100))  # Cheque number, transfer ref
    notes = db.Column(db.Text)
    # Links
    supplier_id = db.Column(db.Integer, db.ForeignKey('suppliers.id'), nullable=True)
    customer_id = db.Column(db.Integer, db.ForeignKey('customers.id'), nullable=True)
    journal_entry_id = db.Column(db.Integer, db.ForeignKey('journal_entries.id'), nullable=True)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    business = db.relationship('Business', backref='payments')


class PaymentAllocation(db.Model):
    """Links a payment to specific documents/invoices"""
    __tablename__ = 'payment_allocations'
    id = db.Column(db.Integer, primary_key=True)
    payment_id = db.Column(db.Integer, db.ForeignKey('payments.id'))
    document_id = db.Column(db.Integer, db.ForeignKey('documents.id'), nullable=True)
    invoice_id = db.Column(db.Integer, db.ForeignKey('invoices.id'), nullable=True)
    amount_allocated = db.Column(db.Numeric(12,2), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)



class PayrollRun(db.Model):
    """Record of each payroll run for audit trail"""
    __tablename__ = 'payroll_runs'
    id = db.Column(db.Integer, primary_key=True)
    business_id = db.Column(db.Integer, db.ForeignKey('businesses.id'), nullable=False)
    month = db.Column(db.String(7))  # YYYY-MM
    total_gross = db.Column(db.Numeric(12,2))
    total_employer_contrib = db.Column(db.Numeric(12,2))
    total_net = db.Column(db.Numeric(12,2))
    employees_processed = db.Column(db.Integer)
    status = db.Column(db.String(20), default='COMPLETED')
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    business = db.relationship('Business', backref='payroll_runs')

with app.app_context():
    try:
        db.create_all()
        print('LEDGR database ready')
    except Exception as e:
        print(f'DB error: {e}')

# ── Helpers ───────────────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session: return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

@app.context_processor
def inject_globals():
    """Inject today's date and current business into all templates"""
    from datetime import date
    ctx = {'today': date.today().strftime('%Y-%m-%d'), 'today_date': date.today()}
    if 'user_id' in session:
        b = current_business()
        if b:
            ctx['current_biz'] = b
    return ctx

def business_required(f):
    """Ensures a valid business is selected — redirects to add_business if not"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session: return redirect(url_for('login'))
        b = current_business()
        if not b:
            flash('Please create or select a business to continue.', 'error')
            return redirect(url_for('add_business'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        u = current_user()
        if not u or u.email != ADMIN_EMAIL: return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated

def current_user():
    if 'user_id' in session: return User.query.get(session['user_id'])
    return None

def current_business():
    """Returns current business with access verification and safe fallback"""
    user = current_user()
    if not user:
        return None
    bid = session.get('business_id')
    if bid:
        # Verify user has access via UserBusiness
        ub = UserBusiness.query.filter_by(user_id=user.id, business_id=bid).first()
        if ub:
            return ub.business
        # Legacy: check direct business_id on user
        if user.business_id == bid:
            b = Business.query.get(bid)
            if b:
                # Create UserBusiness record for legacy users
                ub = UserBusiness(user_id=user.id, business_id=bid, role='owner')
                db.session.add(ub)
                try: db.session.commit()
                except: db.session.rollback()
                return b
    # Fallback: find first accessible business
    ub = UserBusiness.query.filter_by(user_id=user.id).first()
    if ub:
        session['business_id'] = ub.business_id
        session['business_name'] = ub.business.name
        return ub.business
    # Last resort: user's direct business
    if user.business_id:
        b = Business.query.get(user.business_id)
        if b:
            ub = UserBusiness(user_id=user.id, business_id=b.id, role='owner')
            db.session.add(ub)
            try: db.session.commit()
            except: db.session.rollback()
            session['business_id'] = b.id
            session['business_name'] = b.name
            return b
    return None

def create_default_coa(business_id, industry_type='general'):
    try:
        # Standard accounts
        for acct_type, accounts in DEFAULT_COA.items():
            for code, name in accounts:
                if not Account.query.filter_by(business_id=business_id, code=code).first():
                    db.session.add(Account(business_id=business_id, code=code, name=name, account_type=acct_type))
        # Industry-specific accounts
        industry_accounts = INDUSTRY_COA.get(industry_type or 'general', [])
        for code, name, acct_type in industry_accounts:
            if not Account.query.filter_by(business_id=business_id, code=code).first():
                db.session.add(Account(business_id=business_id, code=code, name=name, account_type=acct_type))
        # Create default location if none exists
        if not Location.query.filter_by(business_id=business_id).first():
            db.session.add(Location(business_id=business_id, name='Main Branch', is_warehouse=False))
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print("CoA creation error: " + str(e))

def get_account(business_id, code):
    return Account.query.filter_by(business_id=business_id, code=code, is_active=True).first()

def api_business_guard():
    """Returns (business, error_response) for API routes"""
    b = current_business()
    if not b:
        return None, jsonify({'ok':False,'error':'No business selected. Please create or select a business.'})
    return b, None

def post_journal(business_id, user_id, description, reference, entry_type, lines, document_id=None):
    lines = [l for l in lines if l]
    total_d = sum(float(l.get('debit',0)) for l in lines)
    total_c = sum(float(l.get('credit',0)) for l in lines)
    if abs(total_d - total_c) > 0.02:
        raise ValueError(f'Unbalanced: debits={total_d:.2f} credits={total_c:.2f}')
    entry = JournalEntry(business_id=business_id, description=description, reference=reference,
                         entry_type=entry_type, document_id=document_id, created_by=user_id)
    db.session.add(entry)
    db.session.flush()
    for l in lines:
        acct = get_account(business_id, l['account_code'])
        if acct:
            db.session.add(JournalLine(journal_entry_id=entry.id, account_id=acct.id,
                                       description=l.get('description', description),
                                       debit=float(l.get('debit',0)), credit=float(l.get('credit',0))))
    db.session.commit()
    return entry

def check_threshold(business):
    t = TAX_THRESHOLDS.get(business.region)
    if not t: return None
    since = datetime.utcnow() - timedelta(days=365)
    revenue = db.session.query(db.func.sum(LedgerEntry.amount)).filter(
        LedgerEntry.business_id==business.id, LedgerEntry.entry_type=='REVENUE',
        LedgerEntry.timestamp>=since).scalar() or 0
    pct = float(revenue) / t['amount'] * 100 if t['amount'] > 0 else 0
    return {'rolling_revenue':float(revenue),'threshold':t['amount'],'currency':t['currency'],
            'percentage':round(pct,1),'authority':t['authority'],'tax':t['tax'],
            'warning':pct>=80,'exceeded':pct>=100}

def extract_with_ai(file_b64, media_type, region='MV'):
    tax = TAX_RULES.get(region, TAX_RULES['MV'])
    compliance_hints = {'MV':'Extract MIRA TIN (XXXXXXXGSTXXX format). Note GST category.',
                        'AE':'Extract TRN (15 digits). Note VAT registration and PINT-AE fields.',
                        'PK':'Extract NTN/STRN. Extract FBR IRN and QR code data.',
                        'CN':'Extract Fapiao number and seller tax ID (18 digits).',
                        'LK':'Extract VAT registration number (9 digits).',
                        'IN':'Extract GSTIN (15 chars). Note HSN/SAC codes.'}.get(region,'')
    currency = tax["currency"]
    tax_name = tax["tax_name"]
    tax_rate = tax["tax_rate"]*100
    authority = tax["authority"]
    country = tax["name"]
    prompt = (
        "You are LEDGR AI, an expert accountant for " + country + " businesses. "
        "Analyse this document carefully and extract all financial data. "
        "Rules: currency=" + currency + ", tax=" + tax_name + " at " + str(tax_rate) + "%, authority=" + authority + ". "
        + compliance_hints + " "
        "IMPORTANT — Identify doc_type correctly: "
        "INVOICE = a tax invoice issued TO a customer (they owe you money). "
        "BILL = a bill/invoice received FROM a supplier (you owe them money). "
        "RECEIPT = proof of payment already made. "
        "PAYROLL_SLIP = employee salary slip. "
        "BANK_STATEMENT = bank account transaction listing. "
        "Return ONLY valid JSON: "
        '{"doc_type":"BILL","vendor_name":"","vendor_tax_id":null,"invoice_number":"",'
        '"invoice_date":"YYYY-MM-DD","due_date":null,"currency":"' + currency + '",'
        '"subtotal":0.00,"tax_amount":0.00,"total_amount":0.00,'
        '"legal_seller_name":"","seller_trn_vat_number":"","buyer_legal_name":"","buyer_trn_vat_number":"",'
        '"category":"Other","confidence":"high","notes":"",'
        '"line_items":[{"description":"","quantity":1,"unit_price":0.00,"total":0.00}],'
        '"compliance_data":{"irn":null,"qr_code":null,"supply_type":"standard","uuid":null,"hs_code":null}}'
        " category options: Office Supplies, Utilities, Travel, Meals, Professional Services, Inventory Purchase, Payroll, Tax Payment, Other"
    )
    content = ({'type':'document','source':{'type':'base64','media_type':'application/pdf','data':file_b64}}
               if media_type=='application/pdf' else
               {'type':'image','source':{'type':'base64','media_type':media_type,'data':file_b64}})
    body = json.dumps({'model':'claude-sonnet-4-6','max_tokens':2048,
                       'messages':[{'role':'user','content':[content,{'type':'text','text':prompt}]}]}).encode()
    req = urllib.request.Request('https://api.anthropic.com/v1/messages', data=body,
                                 headers={'Content-Type':'application/json','x-api-key':ANTHROPIC_KEY,'anthropic-version':'2023-06-01'})
    with urllib.request.urlopen(req, timeout=60) as resp:
        result = json.loads(resp.read())
        text = result['content'][0]['text']
        m = re.search(r'\{[\s\S]*\}', text)
        if not m: raise ValueError('Could not parse AI response')
        return json.loads(m.group())

# ── Auth ──────────────────────────────────────────────────────────────────────
@app.route('/')
def index():
    return redirect(url_for('dashboard') if 'user_id' in session else url_for('login'))

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email','').strip().lower()
        pw    = request.form.get('password','')
        user  = User.query.filter_by(email=email).first()
        if user and user.check_password(pw):
            session.permanent = True
            session['user_id'] = user.id
            session['user_name'] = user.name
            session['plan'] = user.plan.title()
            # Find first accessible business
            ub = UserBusiness.query.filter_by(user_id=user.id).first()
            if ub:
                session['business_id'] = ub.business_id
                session['business_name'] = ub.business.name
            elif user.business_id:
                session['business_id'] = user.business_id
                b = Business.query.get(user.business_id)
                session['business_name'] = b.name if b else 'My Business'
                # Create missing UserBusiness record
                existing = UserBusiness.query.filter_by(user_id=user.id, business_id=user.business_id).first()
                if not existing:
                    db.session.add(UserBusiness(user_id=user.id, business_id=user.business_id, role='owner'))
                    try: db.session.commit()
                    except: db.session.rollback()
            return redirect(url_for('dashboard'))
        flash('Invalid email or password', 'error')
    return render_template('login.html')

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name','').strip()
        email = request.form.get('email','').strip().lower()
        pw = request.form.get('password','')
        bname = request.form.get('business_name','').strip()
        region = request.form.get('region','MV')
        btype = request.form.get('business_type','sole_proprietor')
        if not all([name,email,pw,bname]):
            flash('Please fill in all required fields','error')
            return render_template('register.html', regions=TAX_RULES, business_types=BUSINESS_TYPES)
        if User.query.filter_by(email=email).first():
            flash('An account with this email already exists','error')
            return render_template('register.html', regions=TAX_RULES, business_types=BUSINESS_TYPES)
        tax = TAX_RULES.get(region, TAX_RULES['MV'])
        bt  = BUSINESS_TYPES.get(btype, BUSINESS_TYPES['sole_proprietor'])
        industry = request.form.get('industry_type', 'general')
        ind = INDUSTRY_TYPES.get(industry, INDUSTRY_TYPES['general'])
        business = Business(name=bname, region=region, base_currency=tax['currency'],
                            business_type=btype, has_full_accounting=bt['accounting']=='full',
                            has_pos=True, industry_type=industry,
                            has_service_charge=ind['service_charge'],
                            has_expiry_tracking=ind['expiry_tracking'])
        db.session.add(business)
        db.session.flush()
        user = User(name=name, email=email, business_id=business.id, role='owner')
        user.set_password(pw)
        db.session.add(user)
        db.session.flush()
        db.session.add(UserBusiness(user_id=user.id, business_id=business.id, role='owner'))
        db.session.commit()
        create_default_coa(business.id, industry)
        session.permanent = True
        session['user_id'] = user.id
        session['business_id'] = business.id
        session['user_name'] = user.name
        session['plan'] = 'Free'
        session['business_name'] = bname
        flash(f'Welcome to LEDGR, {name}! Your {bt["name"]} workspace is ready.','success')
        return redirect(url_for('dashboard'))
    return render_template('register.html', regions=TAX_RULES, business_types=BUSINESS_TYPES)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# ── Core Pages ────────────────────────────────────────────────────────────────
@app.route('/dashboard')
@login_required
def dashboard():
    user = current_user()
    business = current_business()
    tax = business.tax_rules()
    total_expense = float(db.session.query(db.func.sum(LedgerEntry.amount)).filter_by(business_id=business.id,entry_type='EXPENSE').scalar() or 0)
    total_revenue = float(db.session.query(db.func.sum(LedgerEntry.amount)).filter_by(business_id=business.id,entry_type='REVENUE').scalar() or 0)
    total_docs = Document.query.filter_by(business_id=business.id).count()
    total_customers = Customer.query.filter_by(business_id=business.id).count()
    recent_docs = Document.query.filter_by(business_id=business.id).order_by(Document.created_at.desc()).limit(6).all()
    low_stock = Product.query.filter(Product.business_id==business.id, Product.stock_level<=Product.reorder_level).limit(5).all() if business.has_inventory else []
    threshold = check_threshold(business)
    # Today POS
    today_pos = float(db.session.query(db.func.sum(POSSale.amount)).filter(
        POSSale.business_id==business.id,
        db.func.date(POSSale.timestamp)==datetime.utcnow().date()).scalar() or 0)
    # User's businesses for switcher
    user_businesses = UserBusiness.query.filter_by(user_id=user.id).all()
    return render_template('dashboard.html', user=user, business=business, tax=tax,
                           total_expense=total_expense, total_revenue=total_revenue,
                           total_docs=total_docs, total_customers=total_customers,
                           recent_docs=recent_docs, low_stock=low_stock, threshold=threshold,
                           today_pos=today_pos, user_businesses=user_businesses, plan=user.get_plan(),
                           btype_name=business.btype()['name'])

@app.route('/upload')
@login_required
def upload():
    user = current_user(); business = current_business()
    return render_template('upload.html', user=user, business=business, tax=business.tax_rules(), plan=user.get_plan())

@app.route('/ledger')
@login_required
def ledger():
    user = current_user(); business = current_business()
    entries = LedgerEntry.query.filter_by(business_id=business.id).order_by(LedgerEntry.timestamp.desc()).limit(100).all()
    total_expense = float(db.session.query(db.func.sum(LedgerEntry.amount)).filter_by(business_id=business.id,entry_type='EXPENSE').scalar() or 0)
    total_revenue = float(db.session.query(db.func.sum(LedgerEntry.amount)).filter_by(business_id=business.id,entry_type='REVENUE').scalar() or 0)
    return render_template('ledger.html', user=user, business=business, entries=entries,
                           total_expense=total_expense, total_revenue=total_revenue, tax=business.tax_rules())

@app.route('/accounts')
@login_required
def chart_of_accounts():
    user = current_user(); business = current_business()
    accounts = Account.query.filter_by(business_id=business.id, is_active=True).order_by(Account.code).all()
    if not accounts:
        create_default_coa(business.id, industry)
        accounts = Account.query.filter_by(business_id=business.id, is_active=True).order_by(Account.code).all()
    grouped = {}
    for a in accounts:
        grouped.setdefault(a.account_type, []).append(a)
    return render_template('accounts.html', user=user, business=business, grouped=grouped, tax=business.tax_rules())

@app.route('/journal')
@login_required
def journal():
    user = current_user(); business = current_business()
    entries = JournalEntry.query.filter_by(business_id=business.id).order_by(JournalEntry.date.desc()).limit(50).all()
    return render_template('journal.html', user=user, business=business, entries=entries, tax=business.tax_rules())

@app.route('/inventory')
@login_required
def inventory():
    user = current_user(); business = current_business()
    products = Product.query.filter_by(business_id=business.id).order_by(Product.name).all()
    low_stock = [p for p in products if p.stock_level <= p.reorder_level]
    return render_template('inventory.html', user=user, business=business, products=products, low_stock=low_stock)

@app.route('/payroll')
@login_required
def payroll():
    user = current_user(); business = current_business()
    try:
        employees = Employee.query.filter_by(business_id=business.id, is_active=True).all()
    except Exception:
        employees = []
    total_payroll = sum(float(e.monthly_salary or 0) + float(e.allowances or 0) for e in employees)
    return render_template('payroll.html', user=user, business=business, employees=employees, total_payroll=total_payroll)

# POS route moved below with full location/service charge support

@app.route('/customers')
@login_required
def customers():
    user = current_user(); business = current_business()
    try:
        customer_list = Customer.query.filter_by(business_id=business.id).order_by(Customer.total_spent.desc()).all()
    except Exception:
        customer_list = []
    total_outstanding = sum(float(c.outstanding_balance or 0) for c in customer_list)
    vip_count = sum(1 for c in customer_list if c.is_vip)
    return render_template('customers.html', user=user, business=business, customers=customer_list,
                           total_outstanding=total_outstanding, vip_count=vip_count, tax=business.tax_rules())

@app.route('/invoices')
@login_required
def invoices():
    user = current_user(); business = current_business()
    invoice_list = Invoice.query.filter_by(business_id=business.id).order_by(Invoice.created_at.desc()).all()
    customers_list = Customer.query.filter_by(business_id=business.id).order_by(Customer.name).all()
    products_list = []
    if business.has_inventory:
        products_list = Product.query.filter_by(business_id=business.id).filter(
            db.or_(Product.is_active==True, Product.is_active==None)
        ).order_by(Product.name).all()
    return render_template('invoices.html', user=user, business=business, invoices=invoice_list,
                           customers=customers_list, products=products_list, tax=business.tax_rules())

@app.route('/reports')
@login_required
def reports():
    user = current_user(); business = current_business()
    tax = business.tax_rules()
    threshold = check_threshold(business)
    total_revenue = float(db.session.query(db.func.sum(LedgerEntry.amount)).filter_by(business_id=business.id,entry_type='REVENUE').scalar() or 0)
    total_expenses = float(db.session.query(db.func.sum(LedgerEntry.amount)).filter_by(business_id=business.id,entry_type='EXPENSE').scalar() or 0)
    total_tax = float(db.session.query(db.func.sum(LedgerEntry.tax_amount)).filter_by(business_id=business.id).scalar() or 0)
    net_profit = total_revenue - total_expenses
    assets = Account.query.filter_by(business_id=business.id, account_type='ASSET', is_active=True).all()
    liabilities = Account.query.filter_by(business_id=business.id, account_type='LIABILITY', is_active=True).all()
    equity = Account.query.filter_by(business_id=business.id, account_type='EQUITY', is_active=True).all()
    total_assets = sum(a.balance() for a in assets)
    total_liabilities = sum(a.balance() for a in liabilities)
    total_equity = sum(a.balance() for a in equity) + net_profit
    return render_template('reports.html', user=user, business=business, tax=tax, threshold=threshold,
                           total_revenue=total_revenue, total_expenses=total_expenses, total_tax=total_tax,
                           net_profit=net_profit, total_assets=total_assets, total_liabilities=total_liabilities,
                           total_equity=total_equity)

@app.route('/settings')
@login_required
def settings():
    user = current_user(); business = current_business()
    user_businesses = UserBusiness.query.filter_by(user_id=user.id).all()
    threshold = TAX_THRESHOLDS.get(business.region, {})
    return render_template('settings.html', user=user, business=business, tax=business.tax_rules(),
                           regions=TAX_RULES, business_types=BUSINESS_TYPES,
                           user_businesses=user_businesses, threshold_info=threshold)

@app.route('/ai')
@login_required
def ai_accountant():
    user = current_user(); business = current_business()
    history = AIConversation.query.filter_by(business_id=business.id).order_by(AIConversation.created_at.asc()).limit(30).all()
    return render_template('ai.html', user=user, business=business, history=history, tax=business.tax_rules())



@app.route("/api/business/settings", methods=["POST"])
@login_required
def api_business_settings():
    """Save business module toggles and settings"""
    business, err = api_business_guard()
    if err: return err
    data = request.get_json()
    # Boolean toggle fields
    bool_fields = ['has_pos','has_inventory','has_payroll','has_full_accounting',
                   'has_multi_location','has_service_charge','has_expiry_tracking',
                   'is_tax_registered','collect_tax_on_sales']
    for field in bool_fields:
        if field in data:
            setattr(business, field, bool(data[field]))
    # Numeric fields
    numeric_fields = ['service_charge_rate']
    for field in numeric_fields:
        if field in data:
            try: setattr(business, field, float(data[field]))
            except: pass
    # Text fields
    text_fields = ['industry_type','region','business_type','secondary_currency',
                   'invoice_prefix','quote_prefix','invoice_notes']
    for field in text_fields:
        if field in data and data[field] is not None:
            setattr(business, field, data[field])
    try:
        db.session.commit()
        return jsonify({"ok":True,"message":"Settings saved"})
    except Exception as e:
        db.session.rollback()
        return jsonify({"ok":False,"error":str(e)})



@app.route("/api/business/profile", methods=["POST"])
@login_required
def api_business_profile():
    business, err = api_business_guard()
    if err: return err
    data = request.get_json()
    text_fields = ["name","legal_name","registration_number","phone","email","website",
                   "address_line1","address_line2","city","country","tax_id",
                   "tax_registration_number","bank_name","bank_account_name",
                   "bank_account_number","bank_swift","secondary_currency",
                   "invoice_prefix","quote_prefix","invoice_notes"]
    for field in text_fields:
        if field in data and data[field] is not None:
            setattr(business, field, data[field])
    if data.get("logo_data"):
        business.logo_data = data["logo_data"]
        business.logo_type = data.get("logo_type","image/png")
    db.session.commit()
    return jsonify({"ok":True,"message":"Business profile updated"})


@app.route("/api/business/logo")
@login_required
def api_business_logo():
    business, err = api_business_guard()
    if err: return ("", 404)
    if business.logo_data:
        import base64 as b64lib
        from flask import Response
        img_data = b64lib.b64decode(business.logo_data)
        return Response(img_data, mimetype=business.logo_type or "image/png")
    return "", 404




# ── Locations & Branches ──────────────────────────────────────────────────────

@app.route("/locations")
@business_required
def locations():
    user = current_user(); business = current_business()
    locs = Location.query.filter_by(business_id=business.id, is_active=True).order_by(Location.name).all()
    return render_template("locations.html", user=user, business=business,
                           locations=locs, tax=business.tax_rules())


@app.route("/api/location/add", methods=["POST"])
@login_required
def api_location_add():
    business, err = api_business_guard()
    if err: return err
    data = request.get_json()
    name = data.get("name","").strip()
    if not name: return jsonify({"ok":False,"error":"Location name required"})
    loc = Location(business_id=business.id, name=name,
                   address=data.get("address",""),
                   is_warehouse=data.get("is_warehouse",False))
    db.session.add(loc)
    db.session.commit()
    return jsonify({"ok":True,"location_id":loc.id,"name":loc.name})


@app.route("/api/location/<int:loc_id>/delete", methods=["POST"])
@login_required
def api_location_delete(loc_id):
    business, err = api_business_guard()
    if err: return err
    loc = Location.query.filter_by(id=loc_id, business_id=business.id).first()
    if not loc: return jsonify({"ok":False,"error":"Not found"})
    # Check if it has sales
    sale_count = POSSale.query.filter_by(location_id=loc_id).count()
    if sale_count > 0:
        return jsonify({"ok":False,"error":"Cannot delete — this location has sales records"})
    loc.is_active = False
    db.session.commit()
    return jsonify({"ok":True})


@app.route("/api/location/<int:loc_id>/stock")
@login_required
def api_location_stock(loc_id):
    business, err = api_business_guard()
    if err: return jsonify([])
    loc = Location.query.filter_by(id=loc_id, business_id=business.id).first()
    if not loc: return jsonify([])
    stock = ProductLocation.query.filter_by(location_id=loc_id).all()
    return jsonify([{
        "product_id": s.product_id,
        "product_name": s.product.name if s.product else "Unknown",
        "stock_quantity": float(s.stock_quantity),
        "reorder_level": s.reorder_level,
        "low_stock": float(s.stock_quantity) <= s.reorder_level
    } for s in stock])


@app.route("/api/location/transfer", methods=["POST"])
@login_required
def api_location_transfer():
    """Inter-branch stock transfer"""
    user = current_user()
    business, err = api_business_guard()
    if err: return err
    data = request.get_json()
    from_loc_id = data.get("from_location_id")
    to_loc_id = data.get("to_location_id")
    product_id = data.get("product_id")
    qty = float(data.get("quantity", 0))
    if qty <= 0: return jsonify({"ok":False,"error":"Quantity must be greater than zero"})
    if from_loc_id == to_loc_id: return jsonify({"ok":False,"error":"Cannot transfer to same location"})

    from_stock = ProductLocation.query.filter_by(
        product_id=product_id, location_id=from_loc_id).first()
    if not from_stock or float(from_stock.stock_quantity) < qty:
        return jsonify({"ok":False,"error":"Insufficient stock at source location"})

    to_stock = ProductLocation.query.filter_by(
        product_id=product_id, location_id=to_loc_id).first()
    if not to_stock:
        to_stock = ProductLocation(product_id=product_id, location_id=to_loc_id, stock_quantity=0)
        db.session.add(to_stock)

    from_stock.stock_quantity = float(from_stock.stock_quantity) - qty
    to_stock.stock_quantity = float(to_stock.stock_quantity) + qty

    # Post journal entry for transfer
    product = Product.query.get(product_id)
    try:
        post_journal(business.id, user.id,
                    "Stock Transfer: " + (product.name if product else str(product_id)),
                    "TRF-" + str(from_loc_id) + "-" + str(to_loc_id),
                    "TRANSFER",
                    [{"account_code":"1200","debit":0,"credit":0,"description":"Inter-branch transfer"}])
    except Exception as e:
        print("Transfer journal error: " + str(e))

    db.session.commit()
    from_loc = Location.query.get(from_loc_id)
    to_loc = Location.query.get(to_loc_id)
    return jsonify({"ok":True,
                    "message": str(qty) + " units transferred from " +
                               (from_loc.name if from_loc else "?") + " to " +
                               (to_loc.name if to_loc else "?")})


# ── Service Charge (Hospitality only) ─────────────────────────────────────────

@app.route("/api/business/industry", methods=["POST"])
@login_required
def api_business_industry():
    business, err = api_business_guard()
    if err: return err
    data = request.get_json()
    industry = data.get("industry_type","general")
    ind = INDUSTRY_TYPES.get(industry, INDUSTRY_TYPES["general"])
    business.industry_type = industry
    # Apply industry defaults — only set what makes sense
    business.has_service_charge = ind["service_charge"]
    business.has_expiry_tracking = ind["expiry_tracking"]
    # Add industry CoA accounts if missing
    for code, name, acct_type in INDUSTRY_COA.get(industry, []):
        if not Account.query.filter_by(business_id=business.id, code=code).first():
            db.session.add(Account(business_id=business.id, code=code,
                                   name=name, account_type=acct_type))
    db.session.commit()
    return jsonify({"ok":True,"industry":ind["name"],
                    "service_charge":ind["service_charge"],
                    "expiry_tracking":ind["expiry_tracking"]})





# ── Professional Invoices & Quotes ────────────────────────────────────────────

@app.route("/invoice/<int:inv_id>/pdf")
@login_required
def invoice_pdf(inv_id):
    business = current_business()
    inv = Invoice.query.filter_by(id=inv_id, business_id=business.id).first()
    if not inv: return "Invoice not found", 404
    items = json.loads(inv.items or "[]")
    html = render_template("invoice_pdf.html", business=business, invoice=inv,
                           items=items, tax=business.tax_rules(), doc_type="INVOICE")
    return html


@app.route("/quote/<int:qid>/pdf")
@login_required
def quote_pdf(qid):
    business = current_business()
    quote = Quotation.query.filter_by(id=qid, business_id=business.id).first()
    if not quote: return "Quote not found", 404
    items = json.loads(quote.items or "[]")
    html = render_template("invoice_pdf.html", business=business, invoice=quote,
                           items=items, tax=business.tax_rules(), doc_type="QUOTATION")
    return html


@app.route("/api/invoice/<int:inv_id>/email", methods=["POST"])
@login_required
def api_invoice_email(inv_id):
    """Send invoice via email using simple mailto link"""
    business = current_business()
    inv = Invoice.query.filter_by(id=inv_id, business_id=business.id).first()
    if not inv: return jsonify({"ok":False,"error":"Invoice not found"})
    items = json.loads(inv.items or "[]")
    customer_email = ""
    if inv.customer and inv.customer.email:
        customer_email = inv.customer.email
    # Build email content
    lines = []
    for item in items:
        lines.append(item.get("desc","Item") + " x" + str(item.get("qty",1)) + 
                    " = " + str(inv.currency) + " " + str(float(item.get("total",0))))
    nl = "\n"
    body_parts = [
        "Dear " + (inv.customer.name if inv.customer else "Customer") + "," + nl + nl,
        "Please find your invoice details below." + nl + nl,
        "Invoice: " + (inv.invoice_number or "") + nl,
        "Date: " + (inv.invoice_date.strftime("%d %b %Y") if inv.invoice_date else "") + nl,
        "Due: " + (inv.due_date.strftime("%d %b %Y") if inv.due_date else "On receipt") + nl + nl,
        "Items:" + nl + nl.join(lines) + nl + nl,
        "Subtotal: " + str(inv.currency) + " " + str(float(inv.subtotal or 0)) + nl,
    ]
    if float(inv.tax_amount or 0) > 0:
        body_parts.append("Tax: " + str(inv.currency) + " " + str(float(inv.tax_amount or 0)) + nl)
    body_parts.append("TOTAL DUE: " + str(inv.currency) + " " + str(float(inv.total_amount or 0)) + nl + nl)
    if inv.notes: body_parts.append(inv.notes + nl + nl)
    body_parts.append("Bank Details:" + nl)
    if business.bank_name: body_parts.append(business.bank_name + nl)
    if business.bank_account_name: body_parts.append(business.bank_account_name + nl)
    if business.bank_account_number: body_parts.append("Account: " + business.bank_account_number + nl)
    if business.bank_swift: body_parts.append("SWIFT: " + business.bank_swift + nl)
    body_parts.append(nl + "Powered by LEDGR | ledgrglobal.com")
    body = "".join(body_parts)
    subject = "Invoice " + (inv.invoice_number or "") + " from " + business.display_name()
    mailto = "mailto:" + urllib.parse.quote(customer_email) + "?subject=" + urllib.parse.quote(subject) + "&body=" + urllib.parse.quote(body)
    return jsonify({"ok":True,"mailto":mailto,"customer_email":customer_email,
                    "subject":subject,"has_email":bool(customer_email)})


@app.route("/api/quote/<int:qid>/email", methods=["POST"])
@login_required  
def api_quote_email(qid):
    business = current_business()
    quote = Quotation.query.filter_by(id=qid, business_id=business.id).first()
    if not quote: return jsonify({"ok":False,"error":"Quote not found"})
    items = json.loads(quote.items or "[]")
    customer_email = ""
    if quote.customer and quote.customer.email:
        customer_email = quote.customer.email
    lines = []
    for item in items:
        lines.append(item.get("desc","Item") + " x" + str(item.get("qty",1)) +
                    " = " + str(quote.currency) + " " + str(float(item.get("total",0))))
    nl = "\n"
    body_parts = [
        "Dear " + (quote.customer.name if quote.customer else "Customer") + "," + nl + nl,
        "Please find our quotation below." + nl + nl,
        "Quote: " + (quote.quote_number or "") + nl,
        "Date: " + (quote.quote_date.strftime("%d %b %Y") if quote.quote_date else "") + nl,
        "Valid Until: " + (quote.valid_until.strftime("%d %b %Y") if quote.valid_until else "14 days") + nl + nl,
        "Items:" + nl + nl.join(lines) + nl + nl,
        "Subtotal: " + str(quote.currency) + " " + str(float(quote.subtotal or 0)) + nl,
    ]
    if float(quote.tax_amount or 0) > 0:
        body_parts.append("Tax: " + str(quote.currency) + " " + str(float(quote.tax_amount or 0)) + nl)
    body_parts.append("TOTAL: " + str(quote.currency) + " " + str(float(quote.total_amount or 0)) + nl + nl)
    if quote.notes: body_parts.append(quote.notes + nl + nl)
    body_parts.append("This is a quotation only. Please confirm your acceptance to proceed." + nl + nl)
    body_parts.append("Powered by LEDGR | ledgrglobal.com")
    body = "".join(body_parts)
    subject = "Quotation " + (quote.quote_number or "") + " from " + business.display_name()
    mailto = "mailto:" + urllib.parse.quote(customer_email) + "?subject=" + urllib.parse.quote(subject) + "&body=" + urllib.parse.quote(body)
    return jsonify({"ok":True,"mailto":mailto,"customer_email":customer_email,
                    "subject":subject,"has_email":bool(customer_email)})


# ── Multicurrency Bank Reconciliation ─────────────────────────────────────────

@app.route("/bank/reconcile/<int:account_id>")
@business_required
def bank_reconcile(account_id):
    user = current_user(); business = current_business()
    acct = BankAccount.query.filter_by(id=account_id, business_id=business.id).first()
    if not acct: return redirect(url_for("bank"))
    transactions = BankTransaction.query.filter_by(
        bank_account_id=account_id).order_by(BankTransaction.txn_date.desc()).limit(100).all()
    return render_template("bank_reconcile.html", user=user, business=business,
                           account=acct, transactions=transactions, tax=business.tax_rules())


@app.route("/api/bank/reconcile", methods=["POST"])
@login_required
def api_bank_reconcile():
    business, err = api_business_guard()
    if err: return err
    data = request.get_json()
    account_id = data.get("account_id")
    statement_balance = float(data.get("statement_balance", 0))
    acct = BankAccount.query.filter_by(id=account_id, business_id=business.id).first()
    if not acct: return jsonify({"ok":False,"error":"Account not found"})
    # Calculate book balance from transactions
    txns = BankTransaction.query.filter_by(bank_account_id=account_id).all()
    book_balance = float(acct.opening_balance or 0)
    for t in txns:
        book_balance += float(t.credit or 0) - float(t.debit or 0)
    variance = statement_balance - book_balance
    acct.current_balance = statement_balance
    db.session.commit()
    return jsonify({"ok":True,"statement_balance":statement_balance,
                    "book_balance":round(book_balance,2),
                    "variance":round(variance,2),
                    "reconciled":abs(variance) < 0.01,
                    "currency":acct.currency})


@app.route("/api/bank/add-account", methods=["POST"])
@login_required
def api_bank_add_account_v2():
    business, err = api_business_guard()
    if err: return err
    data = request.get_json()
    acct = BankAccount(business_id=business.id,
                       bank_name=data.get("bank_name",""),
                       account_name=data.get("account_name",""),
                       account_number=data.get("account_number",""),
                       currency=data.get("currency", business.base_currency),
                       opening_balance=float(data.get("opening_balance",0)),
                       current_balance=float(data.get("opening_balance",0)))
    db.session.add(acct)
    db.session.commit()
    return jsonify({"ok":True,"account_id":acct.id,"name":acct.account_name,
                    "currency":acct.currency})





# ── Onboarding Wizard ─────────────────────────────────────────────────────────

@app.route("/setup/wizard")
@login_required
def setup_wizard():
    user = current_user()
    return render_template("wizard.html", user=user,
                           tax_rules=TAX_RULES, industry_types=INDUSTRY_TYPES,
                           business_types=BUSINESS_TYPES)


@app.route("/setup/wizard/complete", methods=["POST"])
@login_required
def setup_wizard_complete():
    user = current_user()
    data = request.get_json()

    region = data.get("region", "MV")
    business_type = data.get("business_type", "sole_proprietor")
    industry = data.get("industry_type", "general")
    business_name = data.get("business_name", "").strip()
    num_locations = int(data.get("num_locations", 1))
    location_names = data.get("location_names", [])

    if not business_name:
        return jsonify({"ok": False, "error": "Business name required"})

    tax = TAX_RULES.get(region, TAX_RULES["MV"])
    bt = BUSINESS_TYPES.get(business_type, BUSINESS_TYPES["sole_proprietor"])
    ind = INDUSTRY_TYPES.get(industry, INDUSTRY_TYPES["general"])

    # Create business
    business = Business(
        name=business_name,
        region=region,
        base_currency=tax["currency"],
        business_type=business_type,
        industry_type=industry,
        has_pos=True,
        has_full_accounting=(bt["accounting"] == "full"),
        has_service_charge=ind["service_charge"],
        has_expiry_tracking=ind["expiry_tracking"],
        has_multi_location=(num_locations > 1),
        is_tax_registered=False
    )
    db.session.add(business)
    db.session.flush()

    # Link user to business
    ub = UserBusiness(user_id=user.id, business_id=business.id, role="owner")
    db.session.add(ub)

    # Create Chart of Accounts
    for acct_type, accounts in DEFAULT_COA.items():
        for code, name in accounts:
            if not Account.query.filter_by(business_id=business.id, code=code).first():
                db.session.add(Account(business_id=business.id, code=code,
                                       name=name, account_type=acct_type))

    for code, name, acct_type in INDUSTRY_COA.get(industry, []):
        if not Account.query.filter_by(business_id=business.id, code=code).first():
            db.session.add(Account(business_id=business.id, code=code,
                                   name=name, account_type=acct_type))

    # Create locations
    for i in range(max(1, num_locations)):
        loc_name = location_names[i] if i < len(location_names) else ("Main Branch" if i == 0 else "Branch " + str(i + 1))
        db.session.add(Location(business_id=business.id, name=loc_name))

    # Update user session
    session["business_id"] = business.id
    session["business_name"] = business.name

    db.session.commit()

    return jsonify({"ok": True, "business_id": business.id,
                    "redirect": "/dashboard",
                    "message": "Welcome to LEDGR! Your " + ind["name"] + " workspace is ready."})


# ── Shareable Public Receipt ───────────────────────────────────────────────────

@app.route("/receipt/<token>")
def public_receipt(token):
    """Public shareable receipt — no login required"""
    import hashlib
    # Find sale by token (hash of sale id + secret)
    # Try to decode token as sale_id
    try:
        sale_id = int(token.split("-")[0])
        sale = POSSale.query.get(sale_id)
        if not sale:
            return "Receipt not found", 404
        # Verify token
        expected = hashlib.md5(
            (str(sale.id) + str(sale.business_id) + app.secret_key[:8]).encode()
        ).hexdigest()[:8]
        if token != str(sale.id) + "-" + expected:
            return "Invalid receipt link", 403
        business = Business.query.get(sale.business_id)
        return render_template("public_receipt.html", sale=sale, business=business)
    except Exception as e:
        return "Receipt not found", 404


@app.route("/api/pos/receipt-link/<int:sale_id>")
@login_required
def api_receipt_link(sale_id):
    """Generate shareable receipt link"""
    import hashlib
    business = current_business()
    sale = POSSale.query.filter_by(id=sale_id, business_id=business.id).first()
    if not sale:
        return jsonify({"ok": False, "error": "Sale not found"})
    token = str(sale.id) + "-" + hashlib.md5(
        (str(sale.id) + str(sale.business_id) + app.secret_key[:8]).encode()
    ).hexdigest()[:8]
    base_url = "https://ledgrglobal.com"
    receipt_url = base_url + "/receipt/" + token
    wa_url = "https://wa.me/?text=" + urllib.parse.quote(
        "Your receipt from " + business.display_name() + "\n" +
        business.base_currency + " " + str(float(sale.amount)) + "\n" +
        "View receipt: " + receipt_url
    )
    viber_url = "viber://forward?text=" + urllib.parse.quote(
        "Your receipt from " + business.display_name() + "\n" +
        business.base_currency + " " + str(float(sale.amount)) + "\n" +
        "View receipt: " + receipt_url
    )
    return jsonify({"ok": True, "receipt_url": receipt_url,
                    "wa_url": wa_url, "viber_url": viber_url, "token": token})


# ── Accountant Portal ──────────────────────────────────────────────────────────

@app.route("/accountant")
@login_required
def accountant_portal():
    user = current_user()
    # Get all businesses this user has accountant or owner access to
    user_businesses = UserBusiness.query.filter_by(user_id=user.id).all()
    clients = []
    for ub in user_businesses:
        b = ub.business
        if not b:
            continue
        # Calculate key metrics per client
        from sqlalchemy import func as sqlfunc
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        revenue = db.session.query(sqlfunc.sum(LedgerEntry.amount)).filter(
            LedgerEntry.business_id == b.id,
            LedgerEntry.entry_type == "REVENUE",
            LedgerEntry.timestamp >= thirty_days_ago
        ).scalar() or 0
        expenses = db.session.query(sqlfunc.sum(LedgerEntry.amount)).filter(
            LedgerEntry.business_id == b.id,
            LedgerEntry.entry_type == "EXPENSE",
            LedgerEntry.timestamp >= thirty_days_ago
        ).scalar() or 0
        pending_docs = Document.query.filter_by(
            business_id=b.id, status="PENDING").count()
        threshold = check_threshold(b)
        clients.append({
            "business": b,
            "role": ub.role,
            "revenue_30d": float(revenue),
            "expenses_30d": float(expenses),
            "profit_30d": float(revenue) - float(expenses),
            "pending_docs": pending_docs,
            "threshold": threshold,
            "tax": b.tax_rules()
        })
    return render_template("accountant.html", user=user, clients=clients)


@app.route("/accountant/switch/<int:business_id>")
@login_required
def accountant_switch(business_id):
    """Accountant switches to a client business"""
    user = current_user()
    ub = UserBusiness.query.filter_by(user_id=user.id, business_id=business_id).first()
    if not ub:
        flash("You do not have access to this business", "error")
        return redirect(url_for("accountant_portal"))
    session["business_id"] = business_id
    session["business_name"] = ub.business.name
    flash("Switched to " + ub.business.name, "success")
    return redirect(url_for("dashboard"))





# ── Compliance Reports ────────────────────────────────────────────────────────

@app.route("/reports/compliance")
@business_required
def compliance_reports():
    user = current_user(); business = current_business()
    tax = business.tax_rules()
    return render_template("compliance.html", user=user, business=business, tax=tax)


@app.route("/api/reports/mira-g1")
@login_required
def api_mira_g1():
    """MIRA G1 Tax Return Mirror — Maldives only"""
    business, err = api_business_guard()
    if err: return err
    if business.region != "MV":
        return jsonify({"ok":False,"error":"MIRA G1 is for Maldives businesses only"})
    period = request.args.get("period","monthly")
    from datetime import date
    today = date.today()
    if period == "monthly":
        start = date(today.year, today.month, 1)
        end = today
    else:
        q = (today.month - 1) // 3
        start = date(today.year, q*3+1, 1)
        end = today
    # Get ledger entries
    entries = LedgerEntry.query.filter(
        LedgerEntry.business_id==business.id,
        LedgerEntry.timestamp>=datetime.combine(start, datetime.min.time()),
        LedgerEntry.timestamp<=datetime.combine(end, datetime.max.time())
    ).all()
    # Separate standard GST (8%) and T-GST (17%) sales
    standard_sales = sum(float(e.amount) for e in entries if e.entry_type=="REVENUE" and e.category!="Tourism")
    tourism_sales = sum(float(e.amount) for e in entries if e.entry_type=="REVENUE" and e.category=="Tourism")
    standard_tax = round(standard_sales * 0.08 / 1.08, 2)
    tourism_tax = round(tourism_sales * 0.17 / 1.17, 2)
    total_purchases = sum(float(e.amount) for e in entries if e.entry_type=="EXPENSE")
    input_tax = sum(float(e.tax_amount or 0) for e in entries if e.entry_type=="EXPENSE")
    net_tax = round(standard_tax + tourism_tax - input_tax, 2)
    return jsonify({"ok":True,"period":{"start":str(start),"end":str(end),"type":period},
        "g1":{
            "box1_standard_sales":round(standard_sales,2),
            "box2_tourism_sales":round(tourism_sales,2),
            "box3_total_output_tax":round(standard_tax+tourism_tax,2),
            "box4_standard_tax_8pct":standard_tax,
            "box5_tourism_tax_17pct":tourism_tax,
            "box6_total_purchases":round(total_purchases,2),
            "box7_input_tax_claimable":round(input_tax,2),
            "box8_net_tax_payable":net_tax,
            "currency":"MVR",
            "filing_deadline":"28th of following month"
        }})


@app.route("/api/reports/fbr-annex-c")
@login_required
def api_fbr_annex_c():
    """FBR Annex-C Sales Export — Pakistan only"""
    business, err = api_business_guard()
    if err: return err
    if business.region != "PK":
        return jsonify({"ok":False,"error":"FBR Annex-C is for Pakistan businesses only"})
    # Get invoices for current month
    from datetime import date
    today = date.today()
    start = date(today.year, today.month, 1)
    invoices = Invoice.query.filter(
        Invoice.business_id==business.id,
        Invoice.invoice_date>=start
    ).all()
    rows = []
    for inv in invoices:
        rows.append({
            "sr_no": inv.id,
            "buyer_name": inv.customer.name if inv.customer else "Walk-in",
            "buyer_ntn": inv.customer.tax_id if inv.customer and hasattr(inv.customer,'tax_id') else "",
            "buyer_strn": "",
            "invoice_no": inv.invoice_number or "",
            "invoice_date": str(inv.invoice_date) if inv.invoice_date else "",
            "hs_code": "",
            "value_excl_tax": float(inv.subtotal or 0),
            "sales_tax_rate": 18,
            "sales_tax_amount": float(inv.tax_amount or 0),
            "total_value": float(inv.total_amount or 0),
            "currency": inv.currency
        })
    # Generate CSV
    import io, csv
    output = io.StringIO()
    if rows:
        writer = csv.DictWriter(output, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    csv_content = output.getvalue()
    from flask import Response
    return Response(csv_content, mimetype="text/csv",
                   headers={"Content-Disposition":"attachment;filename=FBR_AnnexC_"+str(today)+".csv"})


@app.route("/api/reports/fta-201")
@login_required
def api_fta_201():
    """UAE FTA Form 201 Summary"""
    business, err = api_business_guard()
    if err: return err
    if business.region != "AE":
        return jsonify({"ok":False,"error":"FTA Form 201 is for UAE businesses only"})
    from datetime import date
    today = date.today()
    q = (today.month - 1) // 3
    start = date(today.year, q*3+1, 1)
    entries = LedgerEntry.query.filter(
        LedgerEntry.business_id==business.id,
        LedgerEntry.timestamp>=datetime.combine(start, datetime.min.time()),
        LedgerEntry.entry_type=="REVENUE"
    ).all()
    total_sales = sum(float(e.amount) for e in entries)
    total_tax = sum(float(e.tax_amount or 0) for e in entries)
    standard_rated = total_sales
    return jsonify({"ok":True,
        "form_201":{
            "quarter":f"Q{q+1} {today.year}",
            "1a_standard_rated_supplies":round(standard_rated,2),
            "1b_vat_on_standard_rated":round(total_tax,2),
            "2_zero_rated_supplies":0,
            "3_exempt_supplies":0,
            "4_total_supplies":round(total_sales,2),
            "10_recoverable_vat":0,
            "net_vat_due":round(total_tax,2),
            "currency":"AED",
            "filing_deadline":"28th of month following quarter end"
        }})




@app.route("/suppliers")
@business_required
def suppliers():
    user = current_user(); business = current_business()
    try:
        supplier_list = Supplier.query.filter_by(
            business_id=business.id, is_active=True
        ).order_by(Supplier.total_purchases.desc()).all()
    except Exception as e:
        print("Suppliers error: " + str(e))
        supplier_list = []
    return render_template("suppliers.html", user=user, business=business,
                           suppliers=supplier_list, tax=business.tax_rules())




# ── Manual Journal Entry ──────────────────────────────────────────────────────

@app.route("/api/journal/manual", methods=["POST"])
@login_required
def api_manual_journal():
    """Professional manual journal entry with debit/credit validation"""
    user = current_user()
    business, err = api_business_guard()
    if err: return err
    data = request.get_json()
    lines = data.get("lines", [])
    memo = data.get("memo", "Manual Journal Entry").strip()
    ref = data.get("ref", "").strip()
    if not lines:
        return jsonify({"ok":False,"error":"No lines provided"})
    # Validate balance
    total_debit = sum(float(l.get("debit",0)) for l in lines)
    total_credit = sum(float(l.get("credit",0)) for l in lines)
    if abs(total_debit - total_credit) > 0.01:
        return jsonify({"ok":False,
                        "error":f"Journal does not balance. Debits: {total_debit:.2f}, Credits: {total_credit:.2f}. Difference: {abs(total_debit-total_credit):.2f}"})
    try:
        je = post_journal(business.id, user.id, memo, ref or "MANUAL", "MANUAL", lines)
        return jsonify({"ok":True,"journal_entry_id":je.id,
                        "message":f"Manual journal posted — {memo}",
                        "total_debit":total_debit,"total_credit":total_credit})
    except Exception as e:
        return jsonify({"ok":False,"error":str(e)})


@app.route("/api/journal/<int:je_id>/void", methods=["POST"])
@login_required
def api_journal_void(je_id):
    """Void a journal entry by creating a reversal — maintains audit trail"""
    user = current_user()
    business, err = api_business_guard()
    if err: return err
    je = JournalEntry.query.filter_by(id=je_id, business_id=business.id).first()
    if not je:
        return jsonify({"ok":False,"error":"Journal entry not found"})
    if je.is_void:
        return jsonify({"ok":False,"error":"Already voided"})
    # Check authority — only owner/accountant can void
    ub = UserBusiness.query.filter_by(user_id=user.id, business_id=business.id).first()
    if ub and ub.role not in ['owner','accountant']:
        return jsonify({"ok":False,"error":"Only owner or accountant can void journal entries"})
    # Create reversal entry
    orig_lines = JournalLine.query.filter_by(journal_entry_id=je_id).all()
    reversal_lines = [{"account_code":l.account.code if l.account else "6900",
                       "debit":float(l.credit),"credit":float(l.debit),
                       "description":"VOID: " + (l.description or "")} for l in orig_lines]
    try:
        post_journal(business.id, user.id, "VOID: " + je.description,
                    "VOID-" + str(je_id), "VOID", reversal_lines)
        je.is_void = True
        db.session.commit()
        return jsonify({"ok":True,"message":"Journal entry voided with reversal"})
    except Exception as e:
        return jsonify({"ok":False,"error":str(e)})


@app.route("/api/account/add", methods=["POST"])
@login_required
def api_account_add():
    """Add a custom account to Chart of Accounts"""
    business, err = api_business_guard()
    if err: return err
    data = request.get_json()
    code = data.get("code","").strip()
    name = data.get("name","").strip()
    acct_type = data.get("account_type","EXPENSE")
    if not code or not name:
        return jsonify({"ok":False,"error":"Code and name required"})
    existing = Account.query.filter_by(business_id=business.id, code=code).first()
    if existing:
        return jsonify({"ok":False,"error":f"Account code {code} already exists: {existing.name}"})
    acct = Account(business_id=business.id, code=code, name=name,
                   account_type=acct_type, is_active=True)
    db.session.add(acct)
    db.session.commit()
    return jsonify({"ok":True,"account_id":acct.id,"code":code,"name":name})


@app.route("/api/account/<int:acct_id>/edit", methods=["POST"])
@login_required
def api_account_edit(acct_id):
    """Edit a custom account"""
    business, err = api_business_guard()
    if err: return err
    acct = Account.query.filter_by(id=acct_id, business_id=business.id).first()
    if not acct: return jsonify({"ok":False,"error":"Account not found"})
    data = request.get_json()
    if data.get("name"): acct.name = data["name"]
    if data.get("account_type"): acct.account_type = data["account_type"]
    db.session.commit()
    return jsonify({"ok":True,"message":"Account updated"})


@app.route("/api/bill/<int:doc_id>/mark-paid", methods=["POST"])
@login_required
def api_bill_mark_paid(doc_id):
    """Mark a bill as paid — debits AP, credits Cash/Bank"""
    user = current_user()
    business, err = api_business_guard()
    if err: return err
    doc = Document.query.filter_by(id=doc_id, business_id=business.id).first()
    if not doc: return jsonify({"ok":False,"error":"Bill not found"})
    if doc.payment_status == "PAID":
        return jsonify({"ok":False,"error":"Already marked as paid"})
    data = request.get_json() or {}
    payment_method = data.get("payment_method","Cash")
    bank_code = "1010" if payment_method == "Bank" else "1000"
    total = float(doc.total_amount or 0)
    try:
        post_journal(business.id, user.id,
                    "Payment: " + (doc.vendor_name or "Supplier"),
                    "PAY-" + str(doc.id), "PAYMENT",
                    [{"account_code":"2000","debit":total,"credit":0,"description":"AP Settlement"},
                     {"account_code":bank_code,"debit":0,"credit":total,"description":"Payment"}])
        doc.payment_status = "PAID"
        doc.status = "PAID"
        db.session.commit()
        return jsonify({"ok":True,"message":"Bill marked as paid — Accounts Payable cleared"})
    except Exception as e:
        return jsonify({"ok":False,"error":str(e)})





# ── PDF Bank Statement — Server-side page splitting ────────────────────────────

@app.route("/api/bank/upload-statement-pdf", methods=["POST"])
@login_required
def api_bank_upload_statement_pdf():
    """Split PDF into pages, extract each separately, merge results"""
    user = current_user()
    business, err = api_business_guard()
    if err: return err
    if not ANTHROPIC_KEY:
        return jsonify({"ok":False,"error":"AI not configured"})

    data = request.get_json()
    file_b64 = data.get("file","")
    media_type = data.get("media_type","application/pdf")
    bank_account_id = data.get("bank_account_id")
    tax = business.tax_rules()
    currency = tax["currency"]
    region_name = tax["name"]

    try:
        import base64 as b64lib
        import io
        file_bytes = b64lib.b64decode(file_b64)

        # Try to split PDF with PyPDF2
        page_chunks = []
        try:
            import PyPDF2
            pdf_reader = PyPDF2.PdfReader(io.BytesIO(file_bytes))
            total_pages = len(pdf_reader.pages)
            chunk_size = 3  # 3 pages per chunk for reliability

            for start in range(0, total_pages, chunk_size):
                writer = PyPDF2.PdfWriter()
                end = min(start + chunk_size, total_pages)
                for i in range(start, end):
                    writer.add_page(pdf_reader.pages[i])
                buf = io.BytesIO()
                writer.write(buf)
                chunk_b64 = b64lib.b64encode(buf.getvalue()).decode()
                page_chunks.append({
                    "b64": chunk_b64,
                    "pages": str(start+1) + "-" + str(end),
                    "total": total_pages
                })
        except Exception as pdf_err:
            print("PDF split error — falling back to full file: " + str(pdf_err))
            page_chunks = [{"b64": file_b64, "pages": "all", "total": 1}]

        # Extract each chunk
        all_transactions = []
        stmt_meta = {}
        json_template = ('{"account_name":"","account_number":"","bank_name":"",'
                        '"statement_period":"","opening_balance":0.00,"closing_balance":0.00,'
                        '"currency":"' + currency + '",'
                        '"transactions":[{"date":"YYYY-MM-DD","description":"","reference":"",'
                        '"debit":0.00,"credit":0.00,"balance":0.00,"category":"Other"}]}')

        for idx, chunk in enumerate(page_chunks):
            page_note = "Pages " + chunk["pages"] + " of " + str(chunk["total"]) + ". "
            prompt = (
                "Extract ALL bank transactions from this " + region_name + " bank statement. "
                + page_note +
                "Be thorough — extract every single transaction row. "
                "Return ONLY valid JSON: " + json_template + " "
                "Rules: debit=money out, credit=money in. Use 0.00 not null. "
                "Date format YYYY-MM-DD. "
                "Categories: Sales Revenue, Salary Payment, Rent, Utilities, "
                "Supplier Payment, Tax Payment, Bank Charges, Transfer, Other."
            )
            content = {
                "type": "document",
                "source": {"type": "base64", "media_type": "application/pdf", "data": chunk["b64"]}
            }
            try:
                body = json.dumps({
                    "model": "claude-sonnet-4-6",
                    "max_tokens": 8000,
                    "messages": [{"role":"user","content":[content,{"type":"text","text":prompt}]}]
                }).encode()
                req = urllib.request.Request(
                    "https://api.anthropic.com/v1/messages", data=body,
                    headers={"Content-Type":"application/json","x-api-key":ANTHROPIC_KEY,
                             "anthropic-version":"2023-06-01"}
                )
                with urllib.request.urlopen(req, timeout=120) as resp:
                    result = json.loads(resp.read())
                    text = result["content"][0]["text"].strip()
                    start_idx = text.find("{")
                    end_idx = text.rfind("}") + 1
                    if start_idx >= 0:
                        chunk_data = json.loads(text[start_idx:end_idx])
                        if idx == 0:
                            stmt_meta = chunk_data
                        txns = chunk_data.get("transactions", [])
                        # Deduplicate by date+description+amount
                        for t in txns:
                            key = str(t.get("date","")) + str(t.get("description","")) + str(t.get("debit",0)) + str(t.get("credit",0))
                            if not any(str(e.get("date",""))+str(e.get("description",""))+str(e.get("debit",0))+str(e.get("credit",0)) == key for e in all_transactions):
                                all_transactions.append(t)
                        if chunk_data.get("closing_balance"):
                            stmt_meta["closing_balance"] = chunk_data["closing_balance"]
            except Exception as chunk_err:
                print("Chunk " + str(idx) + " error: " + str(chunk_err))
                continue

        stmt_meta["transactions"] = all_transactions
        txn_count = len(all_transactions)
        return jsonify({
            "ok": True,
            "extracted": stmt_meta,
            "bank_account_id": bank_account_id,
            "pages_processed": len(page_chunks),
            "message": str(txn_count) + " transactions extracted from " + str(len(page_chunks)) + " page chunks"
        })

    except Exception as e:
        return jsonify({"ok":False,"error":"Processing error: " + str(e)[:200]})



@app.route('/admin/migrate-models')
@login_required
@admin_required
def migrate_models():
    """One-time migration for new global compliance fields"""
    try:
        db.create_all()
        # Run ALTER TABLE for new columns that won't be created by create_all
        compliance_cols = [
            "ALTER TABLE documents ADD COLUMN IF NOT EXISTS legal_seller_name VARCHAR(200)",
            "ALTER TABLE documents ADD COLUMN IF NOT EXISTS seller_trn_vat_number VARCHAR(50)",
            "ALTER TABLE documents ADD COLUMN IF NOT EXISTS buyer_legal_name VARCHAR(200)",
            "ALTER TABLE documents ADD COLUMN IF NOT EXISTS buyer_trn_vat_number VARCHAR(50)",
            "ALTER TABLE documents ADD COLUMN IF NOT EXISTS irn VARCHAR(100)",
            "ALTER TABLE documents ADD COLUMN IF NOT EXISTS qr_code_data TEXT",
            "ALTER TABLE documents ADD COLUMN IF NOT EXISTS uuid VARCHAR(100)",
            "ALTER TABLE documents ADD COLUMN IF NOT EXISTS cryptographic_stamp TEXT",
            "ALTER TABLE documents ADD COLUMN IF NOT EXISTS nsfp VARCHAR(100)",
            "ALTER TABLE documents ADD COLUMN IF NOT EXISTS hs_code VARCHAR(20)",
            "ALTER TABLE documents ADD COLUMN IF NOT EXISTS emirate VARCHAR(50)",
            "ALTER TABLE documents ADD COLUMN IF NOT EXISTS transaction_type_code VARCHAR(20)",
            "ALTER TABLE documents ADD COLUMN IF NOT EXISTS supply_type VARCHAR(20) DEFAULT 'standard'",
            "ALTER TABLE documents ADD COLUMN IF NOT EXISTS clearance_status VARCHAR(20) DEFAULT 'PENDING'",
            "ALTER TABLE documents ADD COLUMN IF NOT EXISTS clearance_date TIMESTAMP",
            "ALTER TABLE documents ADD COLUMN IF NOT EXISTS clearance_reference VARCHAR(100)",
            "ALTER TABLE documents ADD COLUMN IF NOT EXISTS total_excl_tax_local NUMERIC(12,2)",
            "ALTER TABLE documents ADD COLUMN IF NOT EXISTS total_vat_local NUMERIC(12,2)",
            "ALTER TABLE documents ADD COLUMN IF NOT EXISTS total_incl_tax_local NUMERIC(12,2)",
            "ALTER TABLE documents ADD COLUMN IF NOT EXISTS line_items TEXT DEFAULT '[]'",
            "ALTER TABLE invoices ADD COLUMN IF NOT EXISTS legal_seller_name VARCHAR(200)",
            "ALTER TABLE invoices ADD COLUMN IF NOT EXISTS seller_trn_vat_number VARCHAR(50)",
            "ALTER TABLE invoices ADD COLUMN IF NOT EXISTS buyer_legal_name VARCHAR(200)",
            "ALTER TABLE invoices ADD COLUMN IF NOT EXISTS buyer_trn_vat_number VARCHAR(50)",
            "ALTER TABLE invoices ADD COLUMN IF NOT EXISTS irn VARCHAR(100)",
            "ALTER TABLE invoices ADD COLUMN IF NOT EXISTS qr_code_data TEXT",
            "ALTER TABLE invoices ADD COLUMN IF NOT EXISTS uuid VARCHAR(100)",
            "ALTER TABLE invoices ADD COLUMN IF NOT EXISTS cryptographic_stamp TEXT",
            "ALTER TABLE invoices ADD COLUMN IF NOT EXISTS nsfp VARCHAR(100)",
            "ALTER TABLE invoices ADD COLUMN IF NOT EXISTS hs_code VARCHAR(20)",
            "ALTER TABLE invoices ADD COLUMN IF NOT EXISTS emirate VARCHAR(50)",
            "ALTER TABLE invoices ADD COLUMN IF NOT EXISTS transaction_type_code VARCHAR(20)",
            "ALTER TABLE invoices ADD COLUMN IF NOT EXISTS supply_type VARCHAR(20) DEFAULT 'standard'",
            "ALTER TABLE invoices ADD COLUMN IF NOT EXISTS clearance_status VARCHAR(20) DEFAULT 'PENDING'",
            "ALTER TABLE invoices ADD COLUMN IF NOT EXISTS clearance_date TIMESTAMP",
            "ALTER TABLE invoices ADD COLUMN IF NOT EXISTS clearance_reference VARCHAR(100)",
            "ALTER TABLE invoices ADD COLUMN IF NOT EXISTS total_excl_tax_local NUMERIC(12,2)",
            "ALTER TABLE invoices ADD COLUMN IF NOT EXISTS total_vat_local NUMERIC(12,2)",
            "ALTER TABLE invoices ADD COLUMN IF NOT EXISTS total_incl_tax_local NUMERIC(12,2)",
            "ALTER TABLE invoices ADD COLUMN IF NOT EXISTS line_items TEXT DEFAULT '[]'",
        ]
        results = []
        for sql in compliance_cols:
            try:
                db.session.execute(db.text(sql))
                results.append("OK: " + sql[:60])
            except Exception as e:
                results.append("SKIP: " + str(e)[:60])
        db.session.commit()
        result_text = "Migration complete!\n\n" + "\n".join(results)
        return "<pre>" + result_text + "</pre>"
    except Exception as e:
        return "Migration error: " + str(e)



# ── Inventory & Warehouse Management APIs ─────────────────────────────────────

@app.route("/api/stock/transfer", methods=["POST"])
@login_required
def api_stock_transfer():
    """Transfer stock between locations/warehouses"""
    user = current_user()
    business, err = api_business_guard()
    if err: return err
    data = request.get_json()
    product_id = data.get("product_id")
    from_loc = int(data.get("from_location_id", 0))
    to_loc = int(data.get("to_location_id", 0))
    qty = float(data.get("quantity", 0))
    if not product_id or not from_loc or not to_loc or qty <= 0:
        return jsonify({"ok":False,"error":"Product, locations and quantity required"})
    if from_loc == to_loc:
        return jsonify({"ok":False,"error":"Source and destination cannot be the same"})
    # Check source stock
    from_pl = ProductLocation.query.filter_by(product_id=product_id, location_id=from_loc).first()
    if not from_pl or float(from_pl.stock_quantity) < qty:
        avail = float(from_pl.stock_quantity) if from_pl else 0
        return jsonify({"ok":False,"error":"Insufficient stock. Available: " + str(avail)})
    # Deduct from source
    from_pl.stock_quantity = float(from_pl.stock_quantity) - qty
    # Add to destination
    to_pl = ProductLocation.query.filter_by(product_id=product_id, location_id=to_loc).first()
    if not to_pl:
        to_pl = ProductLocation(product_id=product_id, location_id=to_loc, stock_quantity=0)
        db.session.add(to_pl)
    to_pl.stock_quantity = float(to_pl.stock_quantity) + qty
    # Record transfer
    transfer = StockTransfer(
        business_id=business.id, product_id=product_id,
        from_location_id=from_loc, to_location_id=to_loc,
        quantity=qty, reference=data.get("reference",""),
        notes=data.get("notes",""), created_by=user.id, status="COMPLETED"
    )
    db.session.add(transfer)
    db.session.commit()
    return jsonify({"ok":True,"message":"Stock transferred successfully","quantity":qty})


@app.route("/api/stock/adjust", methods=["POST"])
@login_required
def api_stock_adjust():
    """Manual stock adjustment — with reason"""
    user = current_user()
    business, err = api_business_guard()
    if err: return err
    data = request.get_json()
    product_id = data.get("product_id")
    location_id = data.get("location_id")
    new_qty = float(data.get("new_quantity", 0))
    reason = data.get("reason", "Manual adjustment")
    product = Product.query.filter_by(id=product_id, business_id=business.id).first()
    if not product: return jsonify({"ok":False,"error":"Product not found"})
    if location_id:
        pl = ProductLocation.query.filter_by(product_id=product_id, location_id=location_id).first()
        if not pl:
            pl = ProductLocation(product_id=product_id, location_id=location_id, stock_quantity=0)
            db.session.add(pl)
        old_qty = float(pl.stock_quantity)
        pl.stock_quantity = new_qty
    else:
        old_qty = float(product.stock_level)
        product.stock_level = new_qty
    # Post adjustment to journal if significant
    diff = new_qty - old_qty
    if abs(diff) > 0:
        try:
            adj_val = abs(diff) * float(product.unit_cost or 0)
            if adj_val > 0:
                if diff > 0:
                    lines = [{"account_code":"1200","debit":adj_val,"credit":0},
                             {"account_code":"6900","debit":0,"credit":adj_val}]
                else:
                    lines = [{"account_code":"6900","debit":adj_val,"credit":0},
                             {"account_code":"1200","debit":0,"credit":adj_val}]
                post_journal(business.id, user.id, "Stock Adjustment: " + product.name,
                            "ADJ-" + str(product_id), "ADJUSTMENT", lines)
        except: pass
    db.session.commit()
    return jsonify({"ok":True,"message":"Stock adjusted. Old: " + str(old_qty) + " → New: " + str(new_qty)})


@app.route("/api/purchase-order/create", methods=["POST"])
@login_required
def api_po_create():
    """Create a purchase order"""
    user = current_user()
    business, err = api_business_guard()
    if err: return err
    data = request.get_json()
    import random
    po_num = "PO-" + str(datetime.utcnow().year) + "-" + str(random.randint(1000,9999))
    items = data.get("items", [])
    subtotal = sum(float(i.get("qty",0)) * float(i.get("unit_cost",0)) for i in items)
    po = PurchaseOrder(
        business_id=business.id,
        supplier_id=data.get("supplier_id"),
        po_number=po_num,
        warehouse_id=data.get("warehouse_id"),
        currency=business.base_currency,
        subtotal=subtotal, total_amount=subtotal,
        items=json.dumps(items),
        notes=data.get("notes",""), status="DRAFT"
    )
    db.session.add(po)
    db.session.commit()
    return jsonify({"ok":True,"po_id":po.id,"po_number":po_num,"total":subtotal})


@app.route("/api/purchase-order/<int:po_id>/receive", methods=["POST"])
@login_required
def api_po_receive(po_id):
    """Mark PO as received — update inventory"""
    user = current_user()
    business, err = api_business_guard()
    if err: return err
    po = PurchaseOrder.query.filter_by(id=po_id, business_id=business.id).first()
    if not po: return jsonify({"ok":False,"error":"PO not found"})
    try:
        items = json.loads(po.items or "[]")
        for item in items:
            product = Product.query.filter_by(id=item.get("product_id"), business_id=business.id).first()
            if product:
                qty = float(item.get("qty", 0))
                product.stock_level = float(product.stock_level or 0) + qty
                if po.warehouse_id:
                    pl = ProductLocation.query.filter_by(product_id=product.id, location_id=po.warehouse_id).first()
                    if not pl:
                        pl = ProductLocation(product_id=product.id, location_id=po.warehouse_id, stock_quantity=0)
                        db.session.add(pl)
                    pl.stock_quantity = float(pl.stock_quantity or 0) + qty
        po.status = "RECEIVED"
        po.received_date = datetime.utcnow().date()
        # Post to journal
        if po.total_amount > 0:
            post_journal(business.id, user.id, "PO Received: " + po.po_number,
                        po.po_number, "PURCHASE",
                        [{"account_code":"1200","debit":float(po.total_amount),"credit":0},
                         {"account_code":"2000","debit":0,"credit":float(po.total_amount)}])
        db.session.commit()
        return jsonify({"ok":True,"message":"PO received and inventory updated"})
    except Exception as e:
        db.session.rollback()
        return jsonify({"ok":False,"error":str(e)})


# ── HR Management APIs ────────────────────────────────────────────────────────

@app.route("/api/employee/add", methods=["POST"])
@login_required
def api_employee_add():
    user = current_user()
    business, err = api_business_guard()
    if err: return err
    data = request.get_json()
    name = (data.get("full_name") or "").strip()
    if not name: return jsonify({"ok":False,"error":"Employee name required"})
    country = data.get("country_of_work", business.region or "MV")
    emp_type = data.get("employment_type", "local")
    salary = float(data.get("monthly_salary", 0))
    rules = get_employment_rules(country)
    # Auto-calculate pension
    pension_emp = round(salary * rules.get("pension_employee_pct", 0) / 100, 2)
    pension_er = round(salary * rules.get("pension_employer_pct", 0) / 100, 2)
    try:
        e = Employee(business_id=business.id, full_name=name)
        e.employee_id = data.get("employee_id", "EMP-" + str(Employee.query.filter_by(business_id=business.id).count() + 1).zfill(3))
        e.position = data.get("position","")
        e.department = data.get("department","")
        e.nationality = data.get("nationality","")
        e.employment_type = emp_type
        e.contract_type = data.get("contract_type","permanent")
        e.country_of_work = country
        e.phone = data.get("phone","")
        e.email = data.get("email","")
        e.monthly_salary = salary
        e.allowances = float(data.get("allowances",0))
        e.housing_allowance = float(data.get("housing_allowance",0))
        e.transport_allowance = float(data.get("transport_allowance",0))
        e.pension_employee = pension_emp
        e.pension_employer = pension_er
        e.currency = business.base_currency
        # Parse dates
        for field, key in [("start_date","start_date"),("visa_expiry","visa_expiry"),
                           ("work_permit_expiry","work_permit_expiry"),("passport_expiry","passport_expiry"),
                           ("medical_expiry","medical_expiry"),("insurance_expiry","insurance_expiry")]:
            val = data.get(key)
            if val:
                try: setattr(e, field, datetime.strptime(val, "%Y-%m-%d").date())
                except: pass
        e.passport_number = data.get("passport_number","")
        e.visa_number = data.get("visa_number","")
        e.work_permit_number = data.get("work_permit_number","")
        e.quota_slot_number = data.get("quota_slot_number","")
        e.quota_fee_paid = float(data.get("quota_fee_paid",0))
        e.security_deposit = float(data.get("security_deposit",0))
        e.insurance_provider = data.get("insurance_provider","")
        e.insurance_cost = float(data.get("insurance_cost",0))
        e.bank_name = data.get("bank_name","")
        e.bank_account = data.get("bank_account","")
        e.notes = data.get("notes","")
        db.session.add(e)
        db.session.commit()
        costs = calculate_employee_costs(e, country)
        return jsonify({"ok":True,"employee_id":e.id,"name":e.full_name,
                       "true_monthly_cost":costs["true_monthly_cost"],
                       "net_salary":costs["net_salary"]})
    except Exception as ex:
        db.session.rollback()
        return jsonify({"ok":False,"error":str(ex)})


@app.route("/api/employee/<int:emp_id>/costs")
@login_required
def api_employee_costs(emp_id):
    """Get true cost breakdown for an employee"""
    business, err = api_business_guard()
    if err: return err
    e = Employee.query.filter_by(id=emp_id, business_id=business.id).first()
    if not e: return jsonify({"ok":False,"error":"Not found"})
    costs = calculate_employee_costs(e, e.country_of_work or business.region or "MV")
    return jsonify({"ok":True,"employee":e.full_name,"costs":costs,
                   "alerts":e.compliance_alerts()})


@app.route("/api/hr/compliance-alerts")
@login_required
def api_hr_compliance_alerts():
    """Get all compliance alerts across all employees"""
    business, err = api_business_guard()
    if err: return err
    try:
        employees = Employee.query.filter_by(business_id=business.id, is_active=True).all()
    except Exception:
        employees = []
    all_alerts = []
    for e in employees:
        alerts = e.compliance_alerts()
        for a in alerts:
            a["employee_id"] = e.id
            a["employee_name"] = e.full_name
            a["position"] = e.position
            all_alerts.append(a)
    # Sort by urgency
    all_alerts.sort(key=lambda x: x.get("days", 999))
    return jsonify({"ok":True,"alerts":all_alerts,"count":len(all_alerts)})


@app.route("/api/hr/payroll-run", methods=["POST"])
@login_required
def api_payroll_run():
    """Process payroll for all active employees — post to journal"""
    user = current_user()
    business, err = api_business_guard()
    if err: return err
    data = request.get_json()
    month = data.get("month", datetime.utcnow().strftime("%Y-%m"))
    try:
        employees = Employee.query.filter_by(business_id=business.id, is_active=True).all()
    except Exception:
        employees = []
    if not employees: return jsonify({"ok":False,"error":"No active employees"})
    total_gross = 0
    total_pension_er = 0
    total_net = 0
    posted = 0
    for e in employees:
        costs = calculate_employee_costs(e, e.country_of_work or business.region or "MV")
        gross = costs["base_salary"] + costs["allowances"]
        net = costs["net_salary"]
        pension_er = costs["pension_employer"]
        total_gross += gross
        total_pension_er += pension_er
        total_net += net
        try:
            post_journal(business.id, user.id,
                "Payroll: " + e.full_name + " (" + month + ")",
                "PAY-" + month + "-" + str(e.id), "PAYROLL",
                [{"account_code":"5100","debit":gross,"credit":0,"description":"Gross salary"},
                 {"account_code":"2210","debit":pension_er,"credit":0,"description":"Pension employer"},
                 {"account_code":"2000","debit":0,"credit":gross + pension_er,"description":"Net payable"}])
            posted += 1
        except: pass
    # Save payroll run record
    try:
        pr = PayrollRun(business_id=business.id, month=month,
                       total_gross=round(total_gross,2),
                       total_employer_contrib=round(total_pension_er,2),
                       total_net=round(total_net,2),
                       employees_processed=posted,
                       created_by=user.id, status="COMPLETED")
        db.session.add(pr)
    except: pass
    db.session.commit()
    return jsonify({"ok":True,"month":month,"employees_processed":posted,
                   "total_gross":round(total_gross,2),
                   "total_pension_employer":round(total_pension_er,2),
                   "total_net_payable":round(total_net,2),
                   "message":"Payroll for " + month + " completed — " + str(posted) + " employees processed"})




@app.route("/api/supplier/add", methods=["POST"])
@login_required
def api_supplier_add():
    business, err = api_business_guard()
    if err: return err
    data = request.get_json()
    name = (data.get("name") or "").strip()
    if not name: return jsonify({"ok":False,"error":"Supplier name required"})
    existing = Supplier.query.filter_by(business_id=business.id, name=name).first()
    if existing: return jsonify({"ok":False,"error":"Supplier already exists","supplier_id":existing.id})
    try:
        s = Supplier(business_id=business.id, name=name,
                     tax_id=data.get("tax_id",""),
                     phone=data.get("phone",""),
                     email=data.get("email",""),
                     address=data.get("address",""),
                     currency=data.get("currency", business.base_currency),
                     payment_terms=data.get("payment_terms","Net 30"),
                     notes=data.get("notes",""))
        db.session.add(s)
        db.session.commit()
        return jsonify({"ok":True,"supplier_id":s.id,"name":s.name})
    except Exception as e:
        db.session.rollback()
        return jsonify({"ok":False,"error":str(e)})


@app.route("/api/supplier/<int:sid>/delete", methods=["POST"])
@login_required
def api_supplier_delete(sid):
    business, err = api_business_guard()
    if err: return err
    s = Supplier.query.filter_by(id=sid, business_id=business.id).first()
    if not s: return jsonify({"ok":False,"error":"Not found"})
    if s.has_transactions:
        return jsonify({"ok":False,"error":"Cannot delete — supplier has transactions. Archive instead."})
    s.is_active = False
    db.session.commit()
    return jsonify({"ok":True})




# ── Payment Module ────────────────────────────────────────────────────────────

@app.route("/payments")
@business_required
def payments():
    user = current_user(); business = current_business()
    # Unpaid bills (AP)
    unpaid_bills = Document.query.filter(
        Document.business_id==business.id,
        Document.doc_type.in_(["BILL","EXPENSE"]),
        Document.payment_status.in_(["UNPAID","PARTIAL","POSTED_UNPAID"])
    ).order_by(Document.invoice_date).all()
    # Unpaid invoices (AR)
    unpaid_invoices = Invoice.query.filter(
        Invoice.business_id==business.id,
        Invoice.status.in_(["SENT","PARTIAL"])
    ).order_by(Invoice.invoice_date).all()
    # Recent payments
    recent_payments = Payment.query.filter_by(
        business_id=business.id
    ).order_by(Payment.payment_date.desc()).limit(30).all()
    # Bank accounts for payment method
    bank_accounts = BankAccount.query.filter_by(
        business_id=business.id, is_active=True).all()
    # Totals
    total_ap = sum(float(b.total_amount or 0) for b in unpaid_bills)
    total_ar = sum(float(i.amount_due()) for i in unpaid_invoices)
    return render_template("payments.html", user=user, business=business,
                           tax=business.tax_rules(),
                           unpaid_bills=unpaid_bills,
                           unpaid_invoices=unpaid_invoices,
                           recent_payments=recent_payments,
                           bank_accounts=bank_accounts,
                           total_ap=total_ap, total_ar=total_ar)


@app.route("/api/payment/pay-bills", methods=["POST"])
@login_required
def api_pay_bills():
    """Pay one or multiple bills — bulk AP payment"""
    user = current_user()
    business, err = api_business_guard()
    if err: return err
    data = request.get_json()
    doc_ids = data.get("document_ids", [])
    payment_method = data.get("payment_method", "Bank Transfer")
    bank_account_id = data.get("bank_account_id")
    payment_date_str = data.get("payment_date")
    reference = data.get("reference", "")
    notes = data.get("notes", "")

    if not doc_ids:
        return jsonify({"ok":False,"error":"No bills selected"})

    try:
        payment_date = datetime.strptime(payment_date_str, "%Y-%m-%d").date() if payment_date_str else date.today()
    except:
        payment_date = date.today()

    # Get and validate all selected bills
    docs = []
    total_amount = 0
    for did in doc_ids:
        doc = Document.query.filter_by(id=did, business_id=business.id).first()
        if doc and doc.payment_status not in ["PAID"]:
            docs.append(doc)
            total_amount += float(doc.total_amount or 0)

    if not docs:
        return jsonify({"ok":False,"error":"No valid unpaid bills found"})

    # Determine bank/cash GL code
    bank_code = "1010" if payment_method in ["Bank Transfer","Card"] else "1000"
    if bank_account_id:
        bank_code = "1010"

    try:
        # Create payment record
        payment = Payment(
            business_id=business.id,
            payment_type="OUTGOING",
            payment_method=payment_method,
            bank_account_id=bank_account_id,
            payment_date=payment_date,
            amount=total_amount,
            currency=business.base_currency,
            reference=reference,
            notes=notes,
            created_by=user.id
        )
        db.session.add(payment)
        db.session.flush()

        # Post journal: DR Accounts Payable, CR Bank/Cash
        vendor_names = ", ".join(set(d.vendor_name or "Supplier" for d in docs))
        lines = [
            {"account_code":"2000","debit":total_amount,"credit":0,
             "description":"AP Payment: " + vendor_names},
            {"account_code":bank_code,"debit":0,"credit":total_amount,
             "description":payment_method + " payment ref: " + (reference or "—")}
        ]
        je = post_journal(business.id, user.id,
                         "Payment: " + vendor_names,
                         reference or "PAY-" + str(payment.id),
                         "PAYMENT", lines)
        payment.journal_entry_id = je.id

        # Update bank account balance
        if bank_account_id:
            ba = BankAccount.query.get(bank_account_id)
            if ba:
                ba.current_balance = float(ba.current_balance or 0) - total_amount

        # Mark each bill as paid and create allocations
        for doc in docs:
            doc.payment_status = "PAID"
            doc.status = "PAID"
            alloc = PaymentAllocation(
                payment_id=payment.id,
                document_id=doc.id,
                amount_allocated=float(doc.total_amount or 0)
            )
            db.session.add(alloc)

        # Update supplier totals if linked
        if docs:
            vendor_name = docs[0].vendor_name
            if vendor_name:
                supplier = Supplier.query.filter_by(
                    business_id=business.id, name=vendor_name).first()
                if supplier:
                    supplier.total_purchases = float(supplier.total_purchases or 0) + total_amount
                    supplier.has_transactions = True

        db.session.commit()
        return jsonify({
            "ok":True,
            "payment_id":payment.id,
            "bills_paid":len(docs),
            "total_paid":total_amount,
            "currency":business.base_currency,
            "message":str(len(docs)) + " bill(s) paid — " + business.base_currency + " " + str(round(total_amount,2))
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({"ok":False,"error":str(e)})


@app.route("/api/payment/receive", methods=["POST"])
@login_required
def api_payment_receive():
    """Record payment received from customer — clears AR"""
    user = current_user()
    business, err = api_business_guard()
    if err: return err
    data = request.get_json()
    invoice_ids = data.get("invoice_ids", [])
    amount_received = float(data.get("amount_received", 0))
    payment_method = data.get("payment_method", "Bank Transfer")
    bank_account_id = data.get("bank_account_id")
    payment_date_str = data.get("payment_date")
    reference = data.get("reference", "")
    customer_id = data.get("customer_id")

    if not invoice_ids and not amount_received:
        return jsonify({"ok":False,"error":"Select invoices or enter amount received"})

    try:
        payment_date = datetime.strptime(payment_date_str, "%Y-%m-%d").date() if payment_date_str else date.today()
    except:
        payment_date = date.today()

    bank_code = "1010" if payment_method in ["Bank Transfer","Card"] else "1000"

    try:
        # Get invoices
        invoices = []
        total_invoiced = 0
        for iid in invoice_ids:
            inv = Invoice.query.filter_by(id=iid, business_id=business.id).first()
            if inv and inv.status not in ["PAID","CANCELLED"]:
                invoices.append(inv)
                total_invoiced += inv.amount_due()

        actual_amount = amount_received if amount_received > 0 else total_invoiced

        # Create payment record
        payment = Payment(
            business_id=business.id,
            payment_type="INCOMING",
            payment_method=payment_method,
            bank_account_id=bank_account_id,
            payment_date=payment_date,
            amount=actual_amount,
            currency=business.base_currency,
            reference=reference,
            customer_id=customer_id,
            created_by=user.id
        )
        db.session.add(payment)
        db.session.flush()

        # Post journal: DR Bank/Cash, CR Accounts Receivable
        lines = [
            {"account_code":bank_code,"debit":actual_amount,"credit":0,
             "description":"Payment received: " + payment_method},
            {"account_code":"1100","debit":0,"credit":actual_amount,
             "description":"AR cleared — " + (reference or "—")}
        ]
        je = post_journal(business.id, user.id,
                         "Payment received",
                         reference or "RECV-" + str(payment.id),
                         "RECEIPT", lines)
        payment.journal_entry_id = je.id

        # Update bank balance
        if bank_account_id:
            ba = BankAccount.query.get(bank_account_id)
            if ba:
                ba.current_balance = float(ba.current_balance or 0) + actual_amount

        # Allocate to invoices and update status
        remaining = actual_amount
        for inv in invoices:
            due = inv.amount_due()
            allocated = min(due, remaining)
            inv.amount_paid = float(inv.amount_paid or 0) + allocated
            if inv.amount_due() <= 0.01:
                inv.status = "PAID"
            else:
                inv.status = "PARTIAL"
            remaining -= allocated
            db.session.add(PaymentAllocation(
                payment_id=payment.id,
                invoice_id=inv.id,
                amount_allocated=allocated
            ))
            # Update customer outstanding
            if inv.customer_id:
                c = Customer.query.get(inv.customer_id)
                if c:
                    c.outstanding_balance = max(0, float(c.outstanding_balance or 0) - allocated)

        db.session.commit()
        return jsonify({
            "ok":True,
            "payment_id":payment.id,
            "amount_received":actual_amount,
            "invoices_updated":len(invoices),
            "currency":business.base_currency,
            "message":"Payment of " + business.base_currency + " " + str(round(actual_amount,2)) + " received and recorded"
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({"ok":False,"error":str(e)})


@app.route("/api/payment/<int:pid>/cancel", methods=["POST"])
@login_required
def api_payment_cancel(pid):
    """Cancel/reverse a payment — creates reversal journal"""
    user = current_user()
    business, err = api_business_guard()
    if err: return err
    payment = Payment.query.filter_by(id=pid, business_id=business.id).first()
    if not payment:
        return jsonify({"ok":False,"error":"Payment not found"})
    try:
        # Reverse the journal
        if payment.journal_entry_id:
            orig = JournalEntry.query.get(payment.journal_entry_id)
            if orig and not orig.is_void:
                orig_lines = JournalLine.query.filter_by(journal_entry_id=orig.id).all()
                reversal = [{"account_code":l.account.code,"debit":float(l.credit),"credit":float(l.debit),
                            "description":"REVERSAL: " + (l.description or "")} for l in orig_lines if l.account]
                post_journal(business.id, user.id, "REVERSAL: " + orig.description,
                            "REV-" + str(pid), "REVERSAL", reversal)
                orig.is_void = True
        # Reopen allocated documents
        allocs = PaymentAllocation.query.filter_by(payment_id=pid).all()
        for alloc in allocs:
            if alloc.document_id:
                doc = Document.query.get(alloc.document_id)
                if doc: doc.payment_status = "UNPAID"
            if alloc.invoice_id:
                inv = Invoice.query.get(alloc.invoice_id)
                if inv:
                    inv.amount_paid = max(0, float(inv.amount_paid or 0) - float(alloc.amount_allocated))
                    inv.status = "SENT"
        db.session.commit()
        return jsonify({"ok":True,"message":"Payment reversed successfully"})
    except Exception as e:
        db.session.rollback()
        return jsonify({"ok":False,"error":str(e)})




@app.route("/hr")
@business_required
def hr_dashboard():
    user = current_user(); business = current_business()
    try:
        employees = Employee.query.filter_by(business_id=business.id, is_active=True).all()
    except:
        employees = []
    # Compliance alerts
    all_alerts = []
    for e in employees:
        for a in e.compliance_alerts():
            a["employee_name"] = e.full_name
            a["position"] = e.position or ""
            all_alerts.append(a)
    all_alerts.sort(key=lambda x: x.get("days", 999))
    # Payroll summary
    total_salary = sum(float(e.monthly_salary or 0) for e in employees)
    total_allowances = sum(float(e.allowances or 0) + float(e.housing_allowance or 0) + float(e.transport_allowance or 0) for e in employees)
    total_pension_er = sum(float(e.pension_employer or 0) for e in employees)
    total_cost = total_salary + total_allowances + total_pension_er
    local_count = sum(1 for e in employees if e.employment_type == 'local')
    foreign_count = sum(1 for e in employees if e.employment_type == 'foreign')
    # Expiring docs in next 30 days
    urgent_alerts = [a for a in all_alerts if a.get("days", 999) <= 30]
    return render_template("hr_dashboard.html", user=user, business=business,
                           tax=business.tax_rules(), employees=employees,
                           all_alerts=all_alerts, urgent_alerts=urgent_alerts,
                           total_salary=total_salary, total_allowances=total_allowances,
                           total_pension_er=total_pension_er, total_cost=total_cost,
                           local_count=local_count, foreign_count=foreign_count)


@app.route("/inventory/dashboard")
@business_required
def inventory_dashboard():
    user = current_user(); business = current_business()
    products = Product.query.filter_by(business_id=business.id).filter(
        db.or_(Product.is_active==True, Product.is_active==None)
    ).all()
    locations = Location.query.filter_by(business_id=business.id, is_active=True).all()
    low_stock = [p for p in products if float(p.stock_level or 0) <= float(p.reorder_level or 10)]
    total_value = sum(float(p.stock_level or 0) * float(p.unit_cost or 0) for p in products)
    total_retail = sum(float(p.stock_level or 0) * float(p.unit_price or 0) for p in products)
    # Recent transfers
    try:
        recent_transfers = StockTransfer.query.filter_by(business_id=business.id).order_by(
            StockTransfer.created_at.desc()).limit(10).all()
    except:
        recent_transfers = []
    # Recent POs
    try:
        recent_pos = PurchaseOrder.query.filter_by(business_id=business.id).order_by(
            PurchaseOrder.created_at.desc()).limit(5).all()
    except:
        recent_pos = []
    return render_template("inventory_dashboard.html", user=user, business=business,
                           tax=business.tax_rules(), products=products, locations=locations,
                           low_stock=low_stock, total_value=total_value, total_retail=total_retail,
                           recent_transfers=recent_transfers, recent_pos=recent_pos)



@app.route("/api/bank/upload-csv", methods=["POST"])
@login_required
def api_bank_upload_csv():
    """Upload bank statement as CSV — no AI needed, direct parsing"""
    user = current_user()
    business, err = api_business_guard()
    if err: return err
    data = request.get_json()
    csv_content = data.get("csv_content", "")
    bank_account_id = data.get("bank_account_id")

    if not csv_content:
        return jsonify({"ok":False,"error":"No CSV content provided"})

    try:
        import csv, io
        reader = csv.DictReader(io.StringIO(csv_content))
        headers = reader.fieldnames or []

        # Auto-detect column mappings for common bank formats
        # BML, MIB, HSBC, and generic CSV formats
        def find_col(possible_names, headers):
            headers_lower = [h.lower().strip() for h in headers]
            for name in possible_names:
                for i, h in enumerate(headers_lower):
                    if name in h:
                        return headers[i]
            return None

        date_col = find_col(['date','txn date','transaction date','value date','posting date'], headers)
        desc_col = find_col(['description','narration','particulars','details','transaction','memo','reference','remarks'], headers)
        debit_col = find_col(['debit','withdrawal','dr','amount out','payments out','debit amount'], headers)
        credit_col = find_col(['credit','deposit','cr','amount in','payments in','credit amount'], headers)
        balance_col = find_col(['balance','running balance','closing balance'], headers)
        amount_col = find_col(['amount'], headers)  # Some banks use single amount column

        if not date_col:
            return jsonify({"ok":False,"error":"Could not find date column. Headers found: " + ", ".join(headers[:10])})

        transactions = []
        for row in reader:
            try:
                # Parse date
                raw_date = (row.get(date_col) or "").strip()
                txn_date = None
                for fmt in ['%d/%m/%Y','%Y-%m-%d','%m/%d/%Y','%d-%m-%Y','%d %b %Y','%d-%b-%Y','%d %B %Y']:
                    try:
                        txn_date = datetime.strptime(raw_date, fmt).strftime('%Y-%m-%d')
                        break
                    except: pass
                if not txn_date: continue

                desc = (row.get(desc_col) or "").strip() if desc_col else ""
                if not desc: continue

                # Parse amounts
                def parse_amount(val):
                    if not val: return 0.0
                    val = str(val).replace(',','').replace(' ','').strip()
                    if val in ['','-','—']: return 0.0
                    try: return abs(float(val))
                    except: return 0.0

                debit = parse_amount(row.get(debit_col)) if debit_col else 0
                credit = parse_amount(row.get(credit_col)) if credit_col else 0
                balance = parse_amount(row.get(balance_col)) if balance_col else 0

                # Handle single amount column
                if amount_col and not debit_col and not credit_col:
                    amt_raw = str(row.get(amount_col) or "").replace(',','').strip()
                    try:
                        amt = float(amt_raw)
                        if amt < 0: debit = abs(amt)
                        else: credit = amt
                    except: pass

                if debit == 0 and credit == 0: continue

                # Auto-categorize
                desc_lower = desc.lower()
                category = "Other"
                if any(w in desc_lower for w in ['salary','payroll','wages','allowance']): category = "Salary Payment"
                elif any(w in desc_lower for w in ['rent','lease']): category = "Rent"
                elif any(w in desc_lower for w in ['electric','water','utility','utilities','mwsc','stelco']): category = "Utilities"
                elif any(w in desc_lower for w in ['bank charge','service charge','fee','commission']): category = "Bank Charges"
                elif any(w in desc_lower for w in ['tax','gst','vat','mira']): category = "Tax Payment"
                elif any(w in desc_lower for w in ['transfer','trf','trx']): category = "Transfer"
                elif credit > 0 and any(w in desc_lower for w in ['sale','pos','payment received','receipt']): category = "Sales Revenue"

                transactions.append({
                    "date": txn_date,
                    "description": desc,
                    "reference": "",
                    "debit": debit,
                    "credit": credit,
                    "balance": balance,
                    "category": category
                })
            except Exception as row_err:
                continue

        if not transactions:
            return jsonify({"ok":False,"error":"No valid transactions found in CSV. Check the file format."})

        return jsonify({
            "ok": True,
            "extracted": {
                "bank_name": "Imported from CSV",
                "account_name": "",
                "account_number": "",
                "statement_period": "",
                "opening_balance": 0,
                "closing_balance": transactions[-1]["balance"] if transactions else 0,
                "currency": business.base_currency,
                "transactions": transactions
            },
            "bank_account_id": bank_account_id,
            "headers_detected": headers[:15],
            "message": str(len(transactions)) + " transactions parsed from CSV"
        })

    except Exception as e:
        return jsonify({"ok":False,"error":"CSV parsing error: " + str(e)[:200]})


# ── Data Import from QB/Odoo/Xero ─────────────────────────────────────────────

@app.route("/api/import/customers-csv", methods=["POST"])
@login_required
def api_import_customers_csv():
    """Import customers from QB/Xero/Odoo CSV export"""
    business, err = api_business_guard()
    if err: return err
    data = request.get_json()
    csv_content = data.get("csv_content", "")
    if not csv_content:
        return jsonify({"ok":False,"error":"No CSV content"})
    try:
        import csv, io
        reader = csv.DictReader(io.StringIO(csv_content))
        headers = reader.fieldnames or []
        def find_col(names, headers):
            hl = [h.lower().strip() for h in headers]
            for n in names:
                for i,h in enumerate(hl):
                    if n in h: return headers[i]
            return None
        name_col = find_col(['name','customer name','company','full name'], headers)
        email_col = find_col(['email','e-mail','email address'], headers)
        phone_col = find_col(['phone','telephone','mobile','contact'], headers)
        balance_col = find_col(['balance','outstanding','amount due','open balance'], headers)
        if not name_col:
            return jsonify({"ok":False,"error":"Could not find name column. Headers: " + ", ".join(headers[:10])})
        imported = 0; skipped = 0
        for row in reader:
            name = (row.get(name_col) or "").strip()
            if not name: continue
            existing = Customer.query.filter_by(business_id=business.id, name=name).first()
            if existing: skipped += 1; continue
            c = Customer(business_id=business.id, name=name,
                        email=(row.get(email_col) or "").strip() if email_col else "",
                        phone=(row.get(phone_col) or "").strip() if phone_col else "",
                        outstanding_balance=abs(float(str(row.get(balance_col) or 0).replace(',',''))) if balance_col else 0)
            db.session.add(c); imported += 1
        db.session.commit()
        return jsonify({"ok":True,"imported":imported,"skipped":skipped,
                       "message":str(imported) + " customers imported, " + str(skipped) + " skipped (already exist)"})
    except Exception as e:
        db.session.rollback()
        return jsonify({"ok":False,"error":str(e)})


@app.route("/api/import/suppliers-csv", methods=["POST"])
@login_required
def api_import_suppliers_csv():
    """Import suppliers/vendors from QB/Xero/Odoo CSV export"""
    business, err = api_business_guard()
    if err: return err
    data = request.get_json()
    csv_content = data.get("csv_content", "")
    try:
        import csv, io
        reader = csv.DictReader(io.StringIO(csv_content))
        headers = reader.fieldnames or []
        def find_col(names, headers):
            hl = [h.lower().strip() for h in headers]
            for n in names:
                for i,h in enumerate(hl):
                    if n in h: return headers[i]
            return None
        name_col = find_col(['name','vendor name','supplier name','company'], headers)
        email_col = find_col(['email','e-mail'], headers)
        phone_col = find_col(['phone','telephone','mobile'], headers)
        if not name_col:
            return jsonify({"ok":False,"error":"Could not find name column"})
        imported = 0; skipped = 0
        for row in reader:
            name = (row.get(name_col) or "").strip()
            if not name: continue
            existing = Supplier.query.filter_by(business_id=business.id, name=name).first()
            if existing: skipped += 1; continue
            s = Supplier(business_id=business.id, name=name,
                        email=(row.get(email_col) or "").strip() if email_col else "",
                        phone=(row.get(phone_col) or "").strip() if phone_col else "")
            db.session.add(s); imported += 1
        db.session.commit()
        return jsonify({"ok":True,"imported":imported,"skipped":skipped})
    except Exception as e:
        db.session.rollback()
        return jsonify({"ok":False,"error":str(e)})


@app.route("/import")
@business_required
def data_import():
    user = current_user(); business = current_business()
    return render_template("import.html", user=user, business=business, tax=business.tax_rules())




# ── Professional Financial Reports ───────────────────────────────────────────

@app.route("/reports/pl")
@business_required
def report_pl():
    """Profit & Loss Statement — QB/Xero format"""
    user = current_user(); business = current_business()
    tax = business.tax_rules()
    # Period selection
    period = request.args.get("period","month")
    from datetime import date
    today = date.today()
    if period == "month":
        start = date(today.year, today.month, 1)
        end = today
        period_label = today.strftime("%B %Y")
    elif period == "quarter":
        q = (today.month - 1) // 3
        start = date(today.year, q*3+1, 1)
        end = today
        period_label = f"Q{q+1} {today.year}"
    elif period == "year":
        start = date(today.year, 1, 1)
        end = today
        period_label = str(today.year)
    elif period == "custom":
        try:
            start = datetime.strptime(request.args.get("start",""), "%Y-%m-%d").date()
            end = datetime.strptime(request.args.get("end",""), "%Y-%m-%d").date()
            period_label = start.strftime("%d %b %Y") + " to " + end.strftime("%d %b %Y")
        except:
            start = date(today.year, 1, 1); end = today
            period_label = str(today.year)
    else:
        start = date(today.year, today.month, 1); end = today
        period_label = today.strftime("%B %Y")

    # Get revenue accounts with balances for period
    revenue_accounts = Account.query.filter_by(
        business_id=business.id, account_type="REVENUE", is_active=True
    ).order_by(Account.code).all()

    expense_accounts = Account.query.filter_by(
        business_id=business.id, account_type="EXPENSE", is_active=True
    ).order_by(Account.code).all()

    # Calculate balances for period from journal lines
    def account_period_balance(acct_id, start, end):
        lines = db.session.query(
            db.func.sum(JournalLine.credit - JournalLine.debit)
        ).join(JournalEntry).filter(
            JournalLine.account_id == acct_id,
            JournalEntry.business_id == business.id,
            db.func.date(JournalEntry.date) >= start,
            db.func.date(JournalEntry.date) <= end
        ).scalar() or 0
        return float(lines)

    revenue_items = []
    total_revenue = 0
    for acct in revenue_accounts:
        bal = account_period_balance(acct.id, start, end)
        if bal != 0:
            revenue_items.append({"code":acct.code,"name":acct.name,"amount":bal})
            total_revenue += bal

    expense_items = []
    total_expenses = 0
    for acct in expense_accounts:
        bal = -account_period_balance(acct.id, start, end)
        if bal != 0:
            expense_items.append({"code":acct.code,"name":acct.name,"amount":bal})
            total_expenses += bal

    # Group expenses by category
    cogs_items = [e for e in expense_items if e["code"].startswith("5") and int(e["code"][:4]) <= 5099]
    opex_items = [e for e in expense_items if e not in cogs_items]
    total_cogs = sum(e["amount"] for e in cogs_items)
    total_opex = sum(e["amount"] for e in opex_items)
    gross_profit = total_revenue - total_cogs
    net_profit = total_revenue - total_expenses

    return render_template("report_pl.html",
        user=user, business=business, tax=tax,
        period=period, period_label=period_label,
        start=start, end=end, today=today,
        revenue_items=revenue_items, total_revenue=total_revenue,
        cogs_items=cogs_items, total_cogs=total_cogs,
        opex_items=opex_items, total_opex=total_opex,
        gross_profit=gross_profit, net_profit=net_profit)


@app.route("/reports/balance-sheet")
@business_required
def report_balance_sheet():
    """Balance Sheet — as of date"""
    user = current_user(); business = current_business()
    tax = business.tax_rules()
    from datetime import date
    as_of_str = request.args.get("as_of","")
    try:
        as_of = datetime.strptime(as_of_str, "%Y-%m-%d").date()
    except:
        as_of = date.today()

    def acct_balance_as_of(acct):
        lines = db.session.query(
            db.func.sum(JournalLine.debit - JournalLine.credit)
        ).join(JournalEntry).filter(
            JournalLine.account_id == acct.id,
            JournalEntry.business_id == business.id,
            db.func.date(JournalEntry.date) <= as_of
        ).scalar() or 0
        bal = float(acct.opening_balance or 0)
        if acct.account_type in ["ASSET","EXPENSE"]:
            return bal + float(lines)
        else:
            return bal - float(lines)

    assets = Account.query.filter_by(business_id=business.id, account_type="ASSET", is_active=True).order_by(Account.code).all()
    liabilities = Account.query.filter_by(business_id=business.id, account_type="LIABILITY", is_active=True).order_by(Account.code).all()
    equity = Account.query.filter_by(business_id=business.id, account_type="EQUITY", is_active=True).order_by(Account.code).all()

    asset_items = [{"code":a.code,"name":a.name,"amount":acct_balance_as_of(a)} for a in assets]
    liability_items = [{"code":a.code,"name":a.name,"amount":acct_balance_as_of(a)} for a in liabilities]
    equity_items = [{"code":a.code,"name":a.name,"amount":acct_balance_as_of(a)} for a in equity]

    # P&L for current year feeds into retained earnings
    year_start = date(as_of.year, 1, 1)
    revenue = db.session.query(db.func.sum(JournalLine.credit - JournalLine.debit)).join(JournalEntry).join(Account).filter(
        Account.business_id==business.id, Account.account_type=="REVENUE",
        db.func.date(JournalEntry.date) >= year_start,
        db.func.date(JournalEntry.date) <= as_of
    ).scalar() or 0
    expenses = db.session.query(db.func.sum(JournalLine.debit - JournalLine.credit)).join(JournalEntry).join(Account).filter(
        Account.business_id==business.id, Account.account_type=="EXPENSE",
        db.func.date(JournalEntry.date) >= year_start,
        db.func.date(JournalEntry.date) <= as_of
    ).scalar() or 0
    current_year_profit = float(revenue) - float(expenses)

    total_assets = sum(i["amount"] for i in asset_items)
    total_liabilities = sum(i["amount"] for i in liability_items)
    total_equity = sum(i["amount"] for i in equity_items) + current_year_profit

    return render_template("report_balance_sheet.html",
        user=user, business=business, tax=tax, as_of=as_of,
        asset_items=asset_items, total_assets=total_assets,
        liability_items=liability_items, total_liabilities=total_liabilities,
        equity_items=equity_items, total_equity=total_equity,
        current_year_profit=current_year_profit)


@app.route("/reports/statement-of-accounts/<int:customer_id>")
@business_required
def report_statement_of_accounts(customer_id):
    """Customer Statement of Account"""
    user = current_user(); business = current_business()
    customer = Customer.query.filter_by(id=customer_id, business_id=business.id).first()
    if not customer: return redirect(url_for("customers"))
    invoices = Invoice.query.filter_by(
        business_id=business.id, customer_id=customer_id
    ).order_by(Invoice.invoice_date).all()
    # Build statement lines
    lines = []
    running_balance = 0
    for inv in invoices:
        running_balance += float(inv.total_amount or 0)
        lines.append({
            "date": inv.invoice_date,
            "type": "Invoice",
            "reference": inv.invoice_number,
            "debit": float(inv.total_amount or 0),
            "credit": 0,
            "balance": running_balance,
            "status": inv.status
        })
        if float(inv.amount_paid or 0) > 0:
            running_balance -= float(inv.amount_paid)
            lines.append({
                "date": inv.invoice_date,
                "type": "Payment",
                "reference": "PMT-" + inv.invoice_number,
                "debit": 0,
                "credit": float(inv.amount_paid),
                "balance": running_balance,
                "status": "PAID"
            })
    return render_template("report_statement.html",
        user=user, business=business, tax=business.tax_rules(),
        customer=customer, lines=lines,
        total_invoiced=sum(l["debit"] for l in lines),
        total_paid=sum(l["credit"] for l in lines),
        outstanding=running_balance)


@app.route("/reports/cash-flow")
@business_required  
def report_cash_flow():
    """Cash Flow Statement"""
    user = current_user(); business = current_business()
    tax = business.tax_rules()
    from datetime import date
    period = request.args.get("period","month")
    today = date.today()
    if period == "month":
        start = date(today.year, today.month, 1); end = today
        period_label = today.strftime("%B %Y")
    elif period == "quarter":
        q = (today.month-1)//3
        start = date(today.year, q*3+1, 1); end = today
        period_label = f"Q{q+1} {today.year}"
    else:
        start = date(today.year, 1, 1); end = today
        period_label = str(today.year)

    # Operating activities from ledger entries
    operating_in = float(db.session.query(db.func.sum(LedgerEntry.amount)).filter(
        LedgerEntry.business_id==business.id, LedgerEntry.entry_type=="REVENUE",
        LedgerEntry.timestamp >= datetime.combine(start, datetime.min.time()),
        LedgerEntry.timestamp <= datetime.combine(end, datetime.max.time())
    ).scalar() or 0)

    operating_out = float(db.session.query(db.func.sum(LedgerEntry.amount)).filter(
        LedgerEntry.business_id==business.id, LedgerEntry.entry_type=="EXPENSE",
        LedgerEntry.timestamp >= datetime.combine(start, datetime.min.time()),
        LedgerEntry.timestamp <= datetime.combine(end, datetime.max.time())
    ).scalar() or 0)

    # Bank transactions for financing
    bank_credits = float(db.session.query(db.func.sum(BankTransaction.credit)).filter(
        BankTransaction.business_id==business.id,
        BankTransaction.txn_date >= start,
        BankTransaction.txn_date <= end,
        BankTransaction.category == "Transfer"
    ).scalar() or 0)

    bank_debits = float(db.session.query(db.func.sum(BankTransaction.debit)).filter(
        BankTransaction.business_id==business.id,
        BankTransaction.txn_date >= start,
        BankTransaction.txn_date <= end,
        BankTransaction.category == "Transfer"
    ).scalar() or 0)

    net_operating = operating_in - operating_out
    net_financing = bank_credits - bank_debits
    net_cash_change = net_operating + net_financing

    return render_template("report_cash_flow.html",
        user=user, business=business, tax=tax,
        period=period, period_label=period_label, start=start, end=end,
        operating_in=operating_in, operating_out=operating_out,
        net_operating=net_operating,
        bank_credits=bank_credits, bank_debits=bank_debits,
        net_financing=net_financing, net_cash_change=net_cash_change)



@app.route("/hr/employee/<int:emp_id>")
@business_required
def employee_detail(emp_id):
    user = current_user(); business = current_business()
    employee = Employee.query.filter_by(id=emp_id, business_id=business.id).first()
    if not employee: return redirect(url_for("hr_dashboard"))
    costs = calculate_employee_costs(employee, employee.country_of_work or business.region or "MV")
    return render_template("employee_detail.html", user=user, business=business,
                           employee=employee, costs=costs, tax=business.tax_rules(),
                           today_date=date.today())


@app.route("/hr/employee/<int:emp_id>/edit", methods=["GET","POST"])
@business_required
def employee_edit(emp_id):
    user = current_user(); business = current_business()
    employee = Employee.query.filter_by(id=emp_id, business_id=business.id).first()
    if not employee: return redirect(url_for("hr_dashboard"))
    if request.method == "POST":
        data = request.form
        for field in ["full_name","position","department","nationality","phone","email",
                     "notes","employee_id","quota_slot_number","insurance_provider",
                     "visa_number","work_permit_number","passport_number","bank_name","bank_account"]:
            if field in data: setattr(employee, field, data[field])
        for date_field in ["start_date","end_date","visa_expiry","work_permit_expiry",
                          "medical_expiry","insurance_expiry","passport_expiry"]:
            val = data.get(date_field)
            if val:
                try: setattr(employee, date_field, datetime.strptime(val, "%Y-%m-%d").date())
                except: pass
        for num_field in ["monthly_salary","allowances","housing_allowance","transport_allowance",
                         "quota_fee_paid","security_deposit","insurance_cost"]:
            val = data.get(num_field)
            if val:
                try: setattr(employee, num_field, float(val))
                except: pass
        if data.get("employment_type"): employee.employment_type = data["employment_type"]
        if data.get("contract_type"): employee.contract_type = data["contract_type"]
        db.session.commit()
        flash(employee.full_name + " updated successfully", "success")
        return redirect(url_for("employee_detail", emp_id=emp_id))
    return render_template("employee_edit.html", user=user, business=business,
                           employee=employee, tax=business.tax_rules())


@app.route("/hr/payroll")
@business_required
def payroll_dashboard():
    user = current_user(); business = current_business()
    try:
        employees = Employee.query.filter_by(business_id=business.id, is_active=True).all()
    except: employees = []
    total_monthly_cost = sum(e.total_cost() for e in employees)
    try:
        payroll_history = PayrollRun.query.filter_by(
            business_id=business.id).order_by(PayrollRun.created_at.desc()).all()
    except: payroll_history = []
    return render_template("payroll_dashboard.html", user=user, business=business,
                           employees=employees, total_monthly_cost=total_monthly_cost,
                           payroll_history=payroll_history, tax=business.tax_rules())



@app.route('/admin')
@login_required
@admin_required
def admin():
    user = current_user()
    users = User.query.order_by(User.created_at.desc()).all()
    businesses = Business.query.all()
    total_docs = Document.query.count()
    stats = {'total_users':len(users),'total_businesses':len(businesses),'total_docs':total_docs,
             'free_users':sum(1 for u in users if u.plan=='free'),
             'pro_users':sum(1 for u in users if u.plan=='pro'),
             'business_users':sum(1 for u in users if u.plan=='business')}
    return render_template('admin.html', user=user, users=users, stats=stats, plans=PLANS)

# ── Business Management ───────────────────────────────────────────────────────
@app.route('/business/add', methods=['GET','POST'])
@login_required
def add_business():
    user = current_user()
    if request.method == 'POST':
        bname = request.form.get('business_name','').strip()
        region = request.form.get('region','MV')
        btype = request.form.get('business_type','sole_proprietor')
        if not bname:
            flash('Business name is required','error')
            return render_template('add_business.html', regions=TAX_RULES, business_types=BUSINESS_TYPES, user=user)
        existing_count = UserBusiness.query.filter_by(user_id=user.id).count()
        # Soft limit during beta — show info but don't block
        tax = TAX_RULES.get(region, TAX_RULES['MV'])
        bt  = BUSINESS_TYPES.get(btype, BUSINESS_TYPES['sole_proprietor'])
        industry = request.form.get('industry_type', 'general')
        ind = INDUSTRY_TYPES.get(industry, INDUSTRY_TYPES['general'])
        business = Business(name=bname, region=region, base_currency=tax['currency'],
                            business_type=btype, has_full_accounting=bt['accounting']=='full',
                            has_pos=True, industry_type=industry,
                            has_service_charge=ind['service_charge'],
                            has_expiry_tracking=ind['expiry_tracking'])
        db.session.add(business)
        db.session.flush()
        db.session.add(UserBusiness(user_id=user.id, business_id=business.id, role='owner'))
        db.session.commit()
        create_default_coa(business.id, industry)
        session['business_id'] = business.id
        session['business_name'] = bname
        flash(f'{bname} workspace created!','success')
        return redirect(url_for('dashboard'))
    return render_template('add_business.html', regions=TAX_RULES, business_types=BUSINESS_TYPES, user=user)

@app.route('/business/switch/<int:business_id>')
@login_required
def switch_business(business_id):
    user = current_user()
    ub = UserBusiness.query.filter_by(user_id=user.id, business_id=business_id).first()
    if not ub:
        # Legacy: check direct business ownership
        b = Business.query.get(business_id)
        if b and (b.id == user.business_id):
            ub_new = UserBusiness(user_id=user.id, business_id=business_id, role='owner')
            db.session.add(ub_new)
            try: db.session.commit()
            except: db.session.rollback()
            ub = ub_new
    if ub:
        session.permanent = True
        session['business_id'] = int(business_id)
        session['business_name'] = ub.business.name
        session.modified = True
        flash('Switched to ' + ub.business.name, 'success')
    else:
        flash('Access denied to this business', 'error')
    return redirect(url_for('dashboard'))

# ── API: Upload & AI ──────────────────────────────────────────────────────────
@app.route('/api/upload', methods=['POST'])
@login_required
def api_upload():
    user = current_user()
    business, err = api_business_guard()
    if err: return err
    if not user.can_upload():
        return jsonify({'ok':False,'error':'Upload limit reached. Upgrade your plan.','upgrade':True})
    if not ANTHROPIC_KEY:
        return jsonify({'ok':False,'error':'AI engine not configured'})
    data = request.get_json()
    try:
        extracted = extract_with_ai(data.get('file',''), data.get('media_type','image/jpeg'), business.region)
        user.increment_uploads()
        inv_date = due_date = None
        try:
            if extracted.get('invoice_date'): inv_date = datetime.strptime(extracted['invoice_date'],'%Y-%m-%d').date()
            if extracted.get('due_date'): due_date = datetime.strptime(extracted['due_date'],'%Y-%m-%d').date()
        except: pass
        doc = Document(business_id=business.id, user_id=user.id,
                       doc_type=extracted.get('doc_type','BILL'),
                       vendor_name=extracted.get('vendor_name',''),
                       vendor_tax_id=extracted.get('vendor_tax_id'),
                       invoice_number=extracted.get('invoice_number',''),
                       invoice_date=inv_date, due_date=due_date,
                       currency=extracted.get('currency', business.base_currency),
                       subtotal=float(extracted.get('subtotal') or 0),
                       tax_amount=float(extracted.get('tax_amount') or 0),
                       total_amount=float(extracted.get('total_amount') or 0),
                       compliance_data=json.dumps(extracted.get('compliance_data',{})),
                       raw_ai_data=json.dumps(extracted), status='PROCESSED')
        db.session.add(doc)
        db.session.flush()
        total = float(extracted.get('total_amount') or 0)
        tax_amt = float(extracted.get('tax_amount') or 0)
        cat_map = {'Office Supplies':'5400','Utilities':'5300','Travel':'5700','Meals':'5800',
                   'Professional Services':'5600','Inventory Purchase':'1200','Payroll':'5100',
                   'Tax Payment':'6200','Other':'6900'}
        expense_code = cat_map.get(extracted.get('category','Other'),'6900')
        try:
            lines = [{'account_code':expense_code,'debit':total-tax_amt,'credit':0,'description':extracted.get('vendor_name','')},
                     {'account_code':'2000','debit':0,'credit':total,'description':extracted.get('vendor_name','')}]
            if tax_amt > 0: lines.insert(1,{'account_code':'2210','debit':tax_amt,'credit':0,'description':'Tax on purchase'})
            post_journal(business.id, user.id, f"{extracted.get('doc_type','BILL')} — {extracted.get('vendor_name','')}",
                        extracted.get('invoice_number',f'DOC-{doc.id}'), 'PURCHASE', lines, doc.id)
        except Exception as je: print(f'Journal error: {je}')
        db.session.add(LedgerEntry(business_id=business.id, document_id=doc.id, entry_type='EXPENSE',
                                   amount=total, tax_amount=tax_amt, currency=extracted.get('currency',business.base_currency),
                                   description=f"{extracted.get('doc_type','BILL')} — {extracted.get('vendor_name','')}",
                                   category=extracted.get('category','Other')))
        # Auto-post BILLS to Accounts Payable (2100) — not Revenue
        # Scanned bills are LIABILITIES until paid, never Revenue
        if doc.doc_type in ['BILL', 'RECEIPT', 'EXPENSE']:
            try:
                # Determine expense account from category
                cat_map = {'Office Supplies':'5400','Utilities':'5300','Travel':'5700',
                           'Meals':'5800','Professional Services':'5600',
                           'Inventory Purchase':'1200','Payroll':'5100',
                           'Tax Payment':'6200','Other':'6900'}
                expense_code = cat_map.get(extracted.get('category','Other'),'6900')
                expense_acct = get_account(business.id, expense_code) or get_account(business.id, '6900')
                ap_acct = get_account(business.id, '2000')  # Accounts Payable
                if expense_acct and ap_acct:
                    doc.posted_to_account_id = expense_acct.id
                    doc.posted_to_account_name = expense_acct.name
                doc.payment_status = 'UNPAID'
                doc.status = 'POSTED_UNPAID'
            except Exception as e:
                print("AP posting note: " + str(e))
                doc.status = 'PROCESSED'
        else:
            doc.status = 'PROCESSED'
        doc.ledger_posted = True
        db.session.commit()
        return jsonify({'ok':True,'document_id':doc.id,'extracted':extracted,
                        'uploads_remaining':user.uploads_remaining(),
                        'has_inventory':business.has_inventory,
                        'message':f"Document processed. {extracted.get('confidence','').upper()} confidence."})
    except Exception as e:
        return jsonify({'ok':False,'error':str(e)})

@app.route('/api/ai/chat', methods=['POST'])
@login_required
def api_ai_chat():
    user = current_user()
    business, err = api_business_guard()
    if err: return err
    data = request.get_json()
    message = data.get('message','').strip()
    if not message: return jsonify({'ok':False,'error':'Empty message'})
    if not ANTHROPIC_KEY: return jsonify({'ok':False,'error':'AI not configured'})
    tax = business.tax_rules()
    total_revenue = float(db.session.query(db.func.sum(LedgerEntry.amount)).filter_by(business_id=business.id,entry_type='REVENUE').scalar() or 0)
    total_expenses = float(db.session.query(db.func.sum(LedgerEntry.amount)).filter_by(business_id=business.id,entry_type='EXPENSE').scalar() or 0)
    total_customers = Customer.query.filter_by(business_id=business.id).count()
    try:
        employees = Employee.query.filter_by(business_id=business.id, is_active=True).all()
    except Exception:
        employees = []
    monthly_payroll = sum(float(e.monthly_salary or 0) + float(e.allowances or 0) for e in employees)
    threshold = check_threshold(business)
    threshold_str = f"Rolling 12-month revenue: {tax['currency']} {total_revenue:.2f} = {threshold['percentage'] if threshold else 0}% of {tax['authority']} threshold." if threshold else ""
    system = f"""You are LEDGR AI Accountant — friendly expert financial advisor for {business.name}.
BUSINESS DATA:
- Type: {business.btype()['name']} | Region: {tax['name']} | Currency: {tax['currency']}
- Tax: {tax['tax_name']} {tax['tax_rate']*100:.0f}% | Authority: {tax['authority']}
- Tax Registered: {'Yes — ' + (business.tax_registration_number or 'Number not set') if business.is_tax_registered else 'No — below threshold'}
- Revenue: {tax['currency']} {total_revenue:.2f} | Expenses: {tax['currency']} {total_expenses:.2f} | Net: {tax['currency']} {total_revenue-total_expenses:.2f}
- Customers: {total_customers} | Employees: {len(employees)} | Monthly Payroll: {tax['currency']} {monthly_payroll:.2f}
- {threshold_str}
YOUR ROLE: Answer financial questions in simple friendly language. Flag issues proactively. Give actionable advice specific to {tax['name']} regulations. Keep responses concise. Use {tax['currency']} for amounts. Always recommend consulting a licensed accountant for major decisions."""
    history = AIConversation.query.filter_by(business_id=business.id).order_by(AIConversation.created_at.asc()).limit(10).all()
    messages = [{'role':h.role,'content':h.message} for h in history]
    messages.append({'role':'user','content':message})
    db.session.add(AIConversation(business_id=business.id, user_id=user.id, role='user', message=message))
    try:
        body = json.dumps({'model':'claude-sonnet-4-6','max_tokens':1024,'system':system,'messages':messages}).encode()
        req = urllib.request.Request('https://api.anthropic.com/v1/messages', data=body,
                                     headers={'Content-Type':'application/json','x-api-key':ANTHROPIC_KEY,'anthropic-version':'2023-06-01'})
        with urllib.request.urlopen(req, timeout=60) as resp:
            result = json.loads(resp.read())
            reply = result['content'][0]['text']
        db.session.add(AIConversation(business_id=business.id, user_id=user.id, role='assistant', message=reply))
        db.session.commit()
        return jsonify({'ok':True,'reply':reply})
    except urllib.error.HTTPError as e:
        db.session.rollback()
        return jsonify({'ok':False,'error':f'AI error {e.code}: {e.read().decode()}'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'ok':False,'error':str(e)})

# ── API: POS ──────────────────────────────────────────────────────────────────

@app.route("/pos")
@business_required
def pos():
    user = current_user(); business = current_business()
    if not business.has_pos:
        flash("Point of Sale is not enabled. Enable it in Settings.", "error")
        return redirect(url_for("settings"))
    # Get selected location
    loc_id = request.args.get("location_id", type=int)
    locations_list = Location.query.filter_by(business_id=business.id, is_active=True).all()
    current_location = None
    if loc_id:
        current_location = Location.query.filter_by(id=loc_id, business_id=business.id).first()
    if not current_location and locations_list:
        current_location = locations_list[0]
    # Today sales
    today_sales = POSSale.query.filter(
        POSSale.business_id==business.id,
        db.func.date(POSSale.timestamp)==datetime.utcnow().date()
    ).order_by(POSSale.timestamp.desc()).all()
    today_total = sum(float(s.amount) for s in today_sales)
    today_tax = sum(float(s.tax_amount or 0) for s in today_sales)
    # Products with location stock
    products = []
    if business.has_inventory:
        products = Product.query.filter_by(business_id=business.id).filter(
            db.or_(Product.is_active == True, Product.is_active == None)
        ).order_by(Product.name).all()
        if business.has_multi_location and current_location:
            loc_stock = {pl.product_id: float(pl.stock_quantity)
                        for pl in ProductLocation.query.filter_by(location_id=current_location.id).all()}
            for p in products:
                p.display_stock = loc_stock.get(p.id, 0)
        else:
            for p in products:
                p.display_stock = float(p.stock_level or 0)
    customers_list = Customer.query.filter_by(business_id=business.id).order_by(Customer.name).limit(100).all()
    return render_template("pos.html", user=user, business=business, tax=business.tax_rules(),
                           today_sales=today_sales, today_total=today_total, today_tax=today_tax,
                           products=products, customers=customers_list,
                           locations=locations_list, current_location=current_location)



@app.route('/api/pos/sale', methods=['POST'])
@login_required
def api_pos_sale():
    user = current_user()
    business, err = api_business_guard()
    if err: return err
    data = request.get_json()
    amount = float(data.get('amount',0))
    if amount <= 0: return jsonify({'ok':False,'error':'Amount must be greater than zero'})
    payment = data.get('payment_method','Cash')
    is_credit = payment == 'Credit'
    customer_id = data.get('customer_id')
    if is_credit and not customer_id: return jsonify({'ok':False,'error':'Select a customer for credit/tab sales'})
    tax_amount = 0
    net_amount = amount
    if business.is_tax_registered:
        tax_rate = business.tax_rules()['tax_rate']
        if data.get('tax_inclusive', True):
            amt = Decimal(str(amount))
            rate = Decimal(str(tax_rate))
            tax_amount = float((amt - (amt / (1 + rate))).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP))
            net_amount = round(amount - tax_amount, 2)
    sale = POSSale(business_id=business.id, user_id=user.id, customer_id=customer_id,
                   amount=amount, tax_amount=tax_amount, currency=business.base_currency,
                   payment_method=payment, note=data.get('note',''), category=data.get('category','Sale'),
                   is_credit=is_credit)
    db.session.add(sale)
    db.session.flush()
    if customer_id:
        c = Customer.query.get(customer_id)
        if c:
            c.total_spent = float(c.total_spent or 0) + amount
            c.visit_count = (c.visit_count or 0) + 1
            c.last_visit = datetime.utcnow()
            if is_credit: c.outstanding_balance = float(c.outstanding_balance or 0) + amount
    cash_code = '1110' if is_credit else ('1000' if payment == 'Cash' else '1010')
    try:
        lines = [{'account_code':cash_code,'debit':amount,'credit':0,'description':data.get('note','POS Sale')},
                 {'account_code':'4000','debit':0,'credit':net_amount,'description':'Sales Revenue'}]
        if tax_amount > 0: lines.append({'account_code':'2210','debit':0,'credit':tax_amount,'description':'Tax collected'})
        je = post_journal(business.id, user.id, f"POS Sale — {data.get('note','')}",
                         f'POS-{sale.id}', 'SALE', lines)
        sale.journal_entry_id = je.id
    except Exception as e: print(f'POS journal error: {e}')
    db.session.add(LedgerEntry(business_id=business.id, entry_type='REVENUE', amount=amount,
                               tax_amount=tax_amount, currency=business.base_currency,
                               description=f"POS Sale — {data.get('note','')}", category=data.get('category','Sale')))
    db.session.commit()
    threshold = check_threshold(business)
    return jsonify({'ok':True,'sale_id':sale.id,'amount':amount,'tax_amount':tax_amount,
                    'net_amount':net_amount,'currency':business.base_currency,
                    'is_tax_registered':business.is_tax_registered,'threshold_warning':threshold})

@app.route('/api/pos/receipt', methods=['POST'])
@login_required
def api_pos_receipt():
    user = current_user(); business = current_business()
    data = request.get_json()
    amount = float(data.get('amount',0))
    tax_amt = float(data.get('tax_amount',0))
    note = data.get('note','Sale')
    payment = data.get('payment_method','Cash')
    customer_name = data.get('customer_name','')
    now = datetime.utcnow().strftime('%d %b %Y %H:%M')
    lines = []
    if customer_name: lines.append(f'Customer: {customer_name}')
    lines.append(f'Item: {note}')
    lines.append(f'Payment: {payment}')
    if tax_amt > 0:
        lines.append(f'Subtotal: {business.base_currency} {amount-tax_amt:.2f}')
        lines.append(f'Tax: {business.base_currency} {tax_amt:.2f}')
    receipt = f"*{business.name}*\n{'━'*20}\n📋 RECEIPT\nDate: {now}\n{'━'*20}\n" + '\n'.join(lines) + f"\n{'━'*20}\n*TOTAL: {business.base_currency} {amount:.2f}*\n{'━'*20}\nThank you! 🙏\nPowered by LEDGR"
    wa_url = 'https://wa.me/?text=' + urllib.parse.quote(receipt)
    return jsonify({'ok':True,'receipt':receipt,'wa_url':wa_url})

# ── API: Customers ────────────────────────────────────────────────────────────
@app.route('/api/customer/add', methods=['POST'])
@login_required
def api_customer_add():
    user = current_user()
    business, err = api_business_guard()
    if err: return err
    data = request.get_json()
    name = (data.get('name') or '').strip()
    if not name: return jsonify({'ok':False,'error':'Name is required'})
    if data.get('phone'):
        existing = Customer.query.filter_by(business_id=business.id, phone=data.get('phone')).first()
        if existing: return jsonify({'ok':False,'error':'Customer with this phone already exists','customer_id':existing.id,'name':existing.name})
    try:
        c = Customer(business_id=business.id, name=name)
        c.phone = data.get('phone','')
        c.email = data.get('email','')
        c.address = data.get('address','')
        c.city = data.get('city','')
        c.country = data.get('country','MV')
        c.notes = data.get('notes','')
        c.is_vip = data.get('is_vip', False)
        c.customer_type = data.get('customer_type','individual')
        c.tax_id = data.get('tax_id','')
        c.registration_number = data.get('registration_number','')
        c.is_tax_registered = bool(data.get('tax_id',''))
        db.session.add(c)
        db.session.commit()
        return jsonify({'ok':True,'customer_id':c.id,'name':c.name})
    except Exception as e:
        db.session.rollback()
        return jsonify({'ok':False,'error':str(e)})

@app.route('/api/customer/search')
@login_required
def api_customer_search():
    business = current_business()
    q = request.args.get('q','').strip().lower()
    if not q or len(q) < 2: return jsonify([])
    results = Customer.query.filter(Customer.business_id==business.id,
        db.or_(db.func.lower(Customer.name).contains(q), Customer.phone.contains(q))).limit(8).all()
    return jsonify([{'id':c.id,'name':c.name,'phone':c.phone or '','total_spent':float(c.total_spent or 0),
                     'visit_count':c.visit_count or 0,'is_vip':c.is_vip,
                     'outstanding_balance':float(c.outstanding_balance or 0),'currency':business.base_currency} for c in results])

@app.route('/api/customer/<int:cid>')
@login_required
def api_customer_detail(cid):
    business = current_business()
    c = Customer.query.filter_by(id=cid, business_id=business.id).first()
    if not c: return jsonify({'ok':False,'error':'Not found'})
    sales = POSSale.query.filter_by(customer_id=cid).order_by(POSSale.timestamp.desc()).limit(10).all()
    return jsonify({'ok':True,'id':c.id,'name':c.name,'phone':c.phone,'email':c.email,
                    'notes':c.notes,'address':c.address or '','city':c.city or '',
                    'country':c.country or 'MV','tax_id':c.tax_id or '',
                    'registration_number':c.registration_number or '',
                    'customer_type':c.customer_type or 'individual',
                    'is_vip':c.is_vip,'total_spent':float(c.total_spent or 0),
                    'visit_count':c.visit_count or 0,
                    'outstanding_balance':float(c.outstanding_balance or 0),
                    'credit_limit':float(getattr(c,'credit_limit',0) or 0),
                    'last_visit':c.last_visit.strftime('%d %b %Y %H:%M') if c.last_visit else None,
                    'currency':business.base_currency,
                    'recent_sales':[{'amount':float(s.amount),'date':s.timestamp.strftime('%d %b %Y'),'method':s.payment_method,'note':s.note} for s in sales]})

# ── API: Inventory ────────────────────────────────────────────────────────────
@app.route('/api/inventory/update', methods=['POST'])
@login_required
def api_inventory_update():
    user = current_user(); business = current_business()
    data = request.get_json()
    pid = data.get('product_id')
    if pid:
        p = Product.query.filter_by(id=pid, business_id=business.id).first()
        if p:
            for k in ['stock_level','unit_price','unit_cost','reorder_level']:
                if k in data: setattr(p, k, data[k])
            db.session.commit()
            return jsonify({'ok':True,'message':'Updated'})
    else:
        p = Product(business_id=business.id, sku=data.get('sku',''), name=data.get('name',''),
                    category=data.get('category',''), stock_level=int(data.get('stock_level',0)),
                    reorder_level=int(data.get('reorder_level',10)),
                    unit_cost=float(data.get('unit_cost',0)), unit_price=float(data.get('unit_price',0)),
                    currency=business.base_currency)
        db.session.add(p)
        db.session.commit()
        return jsonify({'ok':True,'product_id':p.id,'message':'Product added'})
    return jsonify({'ok':False,'error':'Product not found'})

@app.route('/api/inventory/from-upload', methods=['POST'])
@login_required
def api_inventory_from_upload():
    user = current_user(); business = current_business()
    if not business.has_inventory: return jsonify({'ok':False,'error':'Inventory tracking not enabled'})
    data = request.get_json()
    items = data.get('items',[])
    document_id = data.get('document_id')
    results = []
    for item in items:
        if not item.get('include',True): continue
        name = item.get('description','').strip()
        qty = int(item.get('quantity') or 1)
        cost = float(item.get('unit_price') or 0)
        if not name: continue
        existing = Product.query.filter(Product.business_id==business.id,
            db.func.lower(Product.name).contains(name.lower()[:20])).first()
        if existing:
            old = existing.stock_level
            existing.stock_level = (existing.stock_level or 0) + qty
            if cost > 0: existing.unit_cost = cost
            db.session.commit()
            results.append({'product':existing.name,'action':'updated','old_stock':old,'new_stock':existing.stock_level})
        else:
            p = Product(business_id=business.id, name=name, stock_level=qty, unit_cost=cost,
                        unit_price=round(cost*1.3,2), currency=business.base_currency, reorder_level=max(5,qty//2))
            db.session.add(p); db.session.commit()
            results.append({'product':name,'action':'created','old_stock':0,'new_stock':qty})
    if results and document_id:
        doc = Document.query.get(document_id)
        if doc:
            total = float(doc.total_amount or 0); tax_a = float(doc.tax_amount or 0)
            try:
                lines = [{'account_code':'1200','debit':total-tax_a,'credit':0,'description':'Inventory received'},
                         {'account_code':'2000','debit':0,'credit':total,'description':doc.vendor_name or 'Supplier'}]
                if tax_a > 0: lines.insert(1,{'account_code':'2210','debit':tax_a,'credit':0,'description':'Tax'})
                post_journal(business.id, user.id, f'Inventory Purchase — {doc.vendor_name or ""}',
                            doc.invoice_number or f'INV-{doc.id}', 'INVENTORY_PURCHASE', lines, document_id)
            except Exception as e: print(f'Inventory journal error: {e}')
    return jsonify({'ok':True,'results':results,'updated':len(results)})

# ── API: Employees ────────────────────────────────────────────────────────────
@app.route('/api/invoice/create', methods=['POST'])
@login_required
def api_invoice_create():
    user = current_user(); business = current_business()
    data = request.get_json()
    items = data.get('items',[])
    subtotal = sum(float(i.get('total',0)) for i in items)
    tax_rate = business.tax_rules()['tax_rate'] if business.is_tax_registered else 0
    tax_amt = round(subtotal * tax_rate, 2)
    total = subtotal + tax_amt
    # Generate invoice number
    count = Invoice.query.filter_by(business_id=business.id).count() + 1
    inv_num = f"INV-{datetime.utcnow().year}-{count:04d}"
    inv = Invoice(business_id=business.id, customer_id=data.get('customer_id'),
                  invoice_number=inv_num, subtotal=subtotal, tax_amount=tax_amt,
                  total_amount=total, currency=business.base_currency,
                  notes=data.get('notes',''), items=json.dumps(items),
                  due_date=datetime.strptime(data['due_date'],'%Y-%m-%d').date() if data.get('due_date') else None,
                  status='SENT')
    db.session.add(inv)
    db.session.flush()
    # Post to AR if customer
    if data.get('customer_id'):
        try:
            post_journal(business.id, user.id, f'Invoice {inv_num}', inv_num, 'INVOICE',
                        [{'account_code':'1100','debit':total,'credit':0,'description':f'Invoice {inv_num}'},
                         {'account_code':'4000','debit':0,'credit':subtotal,'description':'Sales'},
                         *([{'account_code':'2210','debit':0,'credit':tax_amt,'description':'Tax'}] if tax_amt > 0 else [])])
            c = Customer.query.get(data.get('customer_id'))
            if c: c.outstanding_balance = float(c.outstanding_balance or 0) + total
        except Exception as e: print(f'Invoice journal error: {e}')
    db.session.commit()
    receipt = f"*Invoice {inv_num}*\n{'━'*20}\n{business.name}\nDate: {datetime.utcnow().strftime('%d %b %Y')}\nSubtotal: {business.base_currency} {subtotal:.2f}\n" + (f"Tax: {business.base_currency} {tax_amt:.2f}\n" if tax_amt>0 else "") + f"*TOTAL: {business.base_currency} {total:.2f}*\n{'━'*20}\nPowered by LEDGR"
    wa_url = 'https://wa.me/?text=' + urllib.parse.quote(receipt)
    return jsonify({'ok':True,'invoice_id':inv.id,'invoice_number':inv_num,'total':total,'wa_url':wa_url})

@app.route('/api/invoice/<int:inv_id>/mark-paid', methods=['POST'])
@login_required
def api_invoice_mark_paid(inv_id):
    business = current_business()
    inv = Invoice.query.filter_by(id=inv_id, business_id=business.id).first()
    if not inv: return jsonify({'ok':False,'error':'Invoice not found'})
    inv.status = 'PAID'
    if inv.customer_id:
        c = Customer.query.get(inv.customer_id)
        if c: c.outstanding_balance = max(0, float(c.outstanding_balance or 0) - float(inv.total_amount))
    db.session.commit()
    return jsonify({'ok':True,'message':'Invoice marked as paid'})

# ── API: Admin ────────────────────────────────────────────────────────────────
@app.route('/admin/api/upgrade', methods=['POST'])
@login_required
@admin_required
def admin_upgrade():
    data = request.get_json()
    user = User.query.get(data.get('user_id'))
    if not user: return jsonify({'ok':False,'error':'User not found'})
    user.plan = data.get('plan','free')
    user.plan_activated_at = datetime.utcnow() if hasattr(user,'plan_activated_at') else None
    db.session.commit()
    return jsonify({'ok':True,'message':f'Plan updated to {user.plan}'})

@app.route('/api/request-upgrade', methods=['POST'])
@login_required
def api_request_upgrade():
    user = current_user()
    data = request.get_json()
    plan = data.get('plan','pro')
    print(f'UPGRADE REQUEST: {user.name} ({user.email}) → {plan}')
    return jsonify({'ok':True,'message':f'Upgrade request for {plan.title()} plan received. We will contact you at {user.email} within 24 hours.'})

if __name__ == '__main__':
    with app.app_context(): db.create_all()
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT',5000)))


# ── Document Archive ──────────────────────────────────────────────────────────

@app.route("/documents")
@business_required
def documents():
    user = current_user(); business = current_business()
    doc_type = request.args.get("type","")
    query = Document.query.filter_by(business_id=business.id)
    if doc_type: query = query.filter_by(doc_type=doc_type)
    docs = query.order_by(Document.created_at.desc()).all()
    return render_template("documents.html", user=user, business=business,
                           docs=docs, tax=business.tax_rules(), doc_type=doc_type,
                           plan=user.get_plan())


@app.route("/documents/<int:doc_id>")
@business_required
def document_detail(doc_id):
    user = current_user(); business = current_business()
    doc = Document.query.filter_by(id=doc_id, business_id=business.id).first()
    if not doc: return redirect(url_for("documents"))
    return render_template("document_detail.html", user=user, business=business,
                           doc=doc, tax=business.tax_rules())


@app.route("/api/document/<int:doc_id>/update", methods=["POST"])
@login_required
def api_document_update(doc_id):
    business = current_business()
    doc = Document.query.filter_by(id=doc_id, business_id=business.id).first()
    if not doc: return jsonify({"ok":False,"error":"Document not found"})
    data = request.get_json()
    for field in ["vendor_name","vendor_tax_id","invoice_number","currency"]:
        if field in data: setattr(doc, field, data[field])
    for field in ["subtotal","tax_amount","total_amount"]:
        if field in data: setattr(doc, field, float(data[field] or 0))
    try:
        if data.get("invoice_date"): doc.invoice_date = datetime.strptime(data["invoice_date"],"%Y-%m-%d").date()
        if data.get("due_date"): doc.due_date = datetime.strptime(data["due_date"],"%Y-%m-%d").date()
    except: pass
    db.session.commit()
    return jsonify({"ok":True,"message":"Document updated"})


@app.route("/api/document/manual", methods=["POST"])
@login_required
def api_document_manual():
    user = current_user(); business = current_business()
    data = request.get_json()
    inv_date = due_date = None
    try:
        if data.get("invoice_date"): inv_date = datetime.strptime(data["invoice_date"],"%Y-%m-%d").date()
        if data.get("due_date"): due_date = datetime.strptime(data["due_date"],"%Y-%m-%d").date()
    except: pass
    total = float(data.get("total_amount",0))
    tax_amt = float(data.get("tax_amount",0))
    doc = Document(business_id=business.id, user_id=user.id,
                   doc_type=data.get("doc_type","BILL"), vendor_name=data.get("vendor_name",""),
                   vendor_tax_id=data.get("vendor_tax_id"), invoice_number=data.get("invoice_number",""),
                   invoice_date=inv_date, due_date=due_date,
                   currency=data.get("currency",business.base_currency),
                   subtotal=float(data.get("subtotal",0)), tax_amount=tax_amt, total_amount=total,
                   raw_ai_data="{}", status="PROCESSED")
    db.session.add(doc)
    db.session.flush()
    cat_map = {"Office Supplies":"5400","Utilities":"5300","Travel":"5700","Meals":"5800",
               "Professional Services":"5600","Inventory Purchase":"1200","Payroll":"5100",
               "Tax Payment":"6200","Other":"6900"}
    expense_code = cat_map.get(data.get("category","Other"),"6900")
    try:
        lines = [{"account_code":expense_code,"debit":total-tax_amt,"credit":0,"description":data.get("vendor_name","")},
                 {"account_code":"2000","debit":0,"credit":total,"description":data.get("vendor_name","")}]
        if tax_amt > 0: lines.insert(1,{"account_code":"2210","debit":tax_amt,"credit":0,"description":"Tax"})
        post_journal(business.id, user.id, data.get("doc_type","BILL") + " — " + data.get("vendor_name",""),
                    data.get("invoice_number","DOC-"+str(doc.id)), "PURCHASE", lines, doc.id)
    except Exception as e: print("Manual doc journal error: " + str(e))
    db.session.add(LedgerEntry(business_id=business.id, document_id=doc.id, entry_type="EXPENSE",
                               amount=total, tax_amount=tax_amt, currency=data.get("currency",business.base_currency),
                               description=data.get("doc_type","BILL") + " — " + data.get("vendor_name",""),
                               category=data.get("category","Other")))
    doc.ledger_posted = True
    db.session.commit()
    return jsonify({"ok":True,"document_id":doc.id,"message":"Document saved"})


# ── Quotations ────────────────────────────────────────────────────────────────

@app.route("/quotations")
@business_required
def quotations():
    user = current_user(); business = current_business()
    quotes = Quotation.query.filter_by(business_id=business.id).order_by(Quotation.created_at.desc()).all()
    customers_list = Customer.query.filter_by(business_id=business.id).order_by(Customer.name).all()
    return render_template("quotations.html", user=user, business=business,
                           quotations=quotes, customers=customers_list, tax=business.tax_rules())


@app.route("/api/quotation/create", methods=["POST"])
@login_required
def api_quotation_create():
    user = current_user(); business = current_business()
    data = request.get_json()
    items = data.get("items",[])
    subtotal = sum(float(i.get("total",0)) for i in items)
    tax_rate = business.tax_rules()["tax_rate"] if business.is_tax_registered else 0
    tax_amt = round(subtotal * tax_rate, 2)
    total = subtotal + tax_amt
    q_num = business.next_quote_number()
    valid_until = None
    try:
        if data.get("valid_until"): valid_until = datetime.strptime(data["valid_until"],"%Y-%m-%d").date()
    except: pass
    quote = Quotation(business_id=business.id, customer_id=data.get("customer_id") or None,
                      quote_number=q_num, subtotal=subtotal, tax_amount=tax_amt,
                      total_amount=total, currency=business.base_currency,
                      notes=data.get("notes",""), items=json.dumps(items),
                      valid_until=valid_until, status="SENT")
    db.session.add(quote)
    db.session.commit()
    customer_name = ""
    if data.get("customer_id"):
        c = Customer.query.get(data.get("customer_id"))
        if c: customer_name = c.name
    lines_text = "\n".join(["- " + i.get("desc","") + " x" + str(i.get("qty",1)) + " = " + business.base_currency + " " + str(float(i.get("total",0))) for i in items])
    receipt = "*Quotation " + q_num + "*\n" + "━"*20 + "\n" + business.name + "\nDate: " + datetime.utcnow().strftime("%d %b %Y") + "\n" + (("Customer: " + customer_name + "\n") if customer_name else "") + "━"*20 + "\n" + lines_text + "\n" + "━"*20 + "\nSubtotal: " + business.base_currency + " " + str(subtotal) + "\n" + (("Tax: " + business.base_currency + " " + str(tax_amt) + "\n") if tax_amt>0 else "") + "*TOTAL: " + business.base_currency + " " + str(total) + "*\n" + "━"*20 + "\nThis is a quotation — not a tax invoice.\nPowered by LEDGR"
    wa_url = "https://wa.me/?text=" + urllib.parse.quote(receipt)
    return jsonify({"ok":True,"quote_id":quote.id,"quote_number":q_num,"total":total,"wa_url":wa_url})


@app.route("/api/quotation/<int:qid>/convert", methods=["POST"])
@login_required
def api_quotation_convert(qid):
    user = current_user(); business = current_business()
    quote = Quotation.query.filter_by(id=qid, business_id=business.id).first()
    if not quote: return jsonify({"ok":False,"error":"Quotation not found"})
    if quote.status == "CONVERTED": return jsonify({"ok":False,"error":"Already converted"})
    inv_num = business.next_invoice_number()
    inv = Invoice(business_id=business.id, customer_id=quote.customer_id,
                  invoice_number=inv_num, subtotal=quote.subtotal, tax_amount=quote.tax_amount,
                  total_amount=quote.total_amount, currency=quote.currency,
                  notes=quote.notes, items=quote.items, status="SENT")
    db.session.add(inv)
    db.session.flush()
    quote.status = "CONVERTED"
    quote.converted_invoice_id = inv.id
    if quote.customer_id:
        try:
            total_val = float(quote.total_amount)
            sub_val = float(quote.subtotal)
            tax_val = float(quote.tax_amount)
            lines = [{"account_code":"1100","debit":total_val,"credit":0},
                     {"account_code":"4000","debit":0,"credit":sub_val}]
            if tax_val > 0: lines.append({"account_code":"2210","debit":0,"credit":tax_val})
            post_journal(business.id, user.id, "Invoice " + inv_num + " (from " + quote.quote_number + ")",
                        inv_num, "INVOICE", lines)
            c = Customer.query.get(quote.customer_id)
            if c: c.outstanding_balance = float(c.outstanding_balance or 0) + float(quote.total_amount)
        except Exception as e: print("Quote convert error: " + str(e))
    db.session.commit()
    return jsonify({"ok":True,"invoice_id":inv.id,"invoice_number":inv_num})


@app.route("/api/quotation/<int:qid>/status", methods=["POST"])
@login_required
def api_quotation_status(qid):
    business = current_business()
    quote = Quotation.query.filter_by(id=qid, business_id=business.id).first()
    if not quote: return jsonify({"ok":False,"error":"Not found"})
    data = request.get_json()
    quote.status = data.get("status", quote.status)
    db.session.commit()
    return jsonify({"ok":True})


# ── Bank Statements ───────────────────────────────────────────────────────────

@app.route("/bank")
@business_required
def bank():
    user = current_user(); business = current_business()
    bank_accounts = BankAccount.query.filter_by(business_id=business.id, is_active=True).all()
    recent_txns = BankTransaction.query.filter_by(business_id=business.id).order_by(
        BankTransaction.txn_date.desc()).limit(50).all()
    return render_template("bank.html", user=user, business=business, tax=business.tax_rules(),
                           bank_accounts=bank_accounts, recent_txns=recent_txns)
@app.route("/api/bank/upload-statement", methods=["POST"])
@login_required
def api_bank_upload_statement():
    user = current_user()
    business, err = api_business_guard()
    if err: return err
    if not ANTHROPIC_KEY: return jsonify({"ok":False,"error":"AI not configured"})
    data = request.get_json()
    file_b64 = data.get("file","")
    media_type = data.get("media_type","image/jpeg")
    bank_account_id = data.get("bank_account_id")
    page_number = int(data.get("page_number", 1))
    total_pages = int(data.get("total_pages", 1))
    tax = business.tax_rules()
    currency = tax["currency"]
    region_name = tax["name"]

    page_note = ""
    if total_pages > 1:
        page_note = "This is page " + str(page_number) + " of " + str(total_pages) + ". "
    json_template = '{"account_name":"","account_number":"","bank_name":"","statement_period":"","opening_balance":0.00,"closing_balance":0.00,"currency":"' + currency + '","transactions":[{"date":"YYYY-MM-DD","description":"","reference":"","debit":0.00,"credit":0.00,"balance":0.00,"category":"Other"}]}'
    prompt = (
        "You are a precise accounting data extractor for a " + region_name + " business. "
        + page_note
        + "Extract EVERY transaction from this bank statement. "
        + "Return ONLY valid JSON matching this structure exactly: "
        + json_template
        + " Rules: debit=money out, credit=money in, use 0.00 not null. "
        + "Date format YYYY-MM-DD. "
        + "Categories: Sales Revenue, Salary Payment, Rent, Utilities, Supplier Payment, Tax Payment, Bank Charges, Transfer, Other."
    )

    content = ({"type":"document","source":{"type":"base64","media_type":"application/pdf","data":file_b64}}
               if media_type == "application/pdf" else
               {"type":"image","source":{"type":"base64","media_type":media_type,"data":file_b64}})

    try:
        body = json.dumps({
            "model":"claude-sonnet-4-6",
            "max_tokens":8000,
            "messages":[{"role":"user","content":[content,{"type":"text","text":prompt}]}]
        }).encode()
        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages", data=body,
            headers={"Content-Type":"application/json","x-api-key":ANTHROPIC_KEY,"anthropic-version":"2023-06-01"}
        )
        with urllib.request.urlopen(req, timeout=150) as resp:
            result = json.loads(resp.read())
            text = result["content"][0]["text"].strip()
            # Extract JSON — find outermost { }
            start = text.find("{")
            end = text.rfind("}") + 1
            if start == -1 or end == 0:
                return jsonify({"ok":False,"error":"AI could not extract transactions. Check the document is a clear bank statement."})
            try:
                extracted = json.loads(text[start:end])
            except json.JSONDecodeError:
                # Try to fix truncated JSON
                try:
                    partial = text[start:]
                    # Count open arrays and close them
                    extracted = json.loads(partial + "]}}")
                except:
                    return jsonify({"ok":False,"error":"Statement parsing failed. Try uploading fewer pages at once."})
        txn_count = len(extracted.get("transactions",[]))
        return jsonify({
            "ok":True,
            "extracted":extracted,
            "bank_account_id":bank_account_id,
            "page_number":page_number,
            "total_pages":total_pages,
            "message":str(txn_count) + " transactions extracted"
            + (" from page " + str(page_number) if total_pages > 1 else "")
        })
    except urllib.error.URLError:
        return jsonify({"ok":False,"error":"Request timed out after 2.5 minutes. Please try with fewer pages."})
    except Exception as e:
        return jsonify({"ok":False,"error":"Processing error: " + str(e)[:150]})


@app.route("/api/bank/auto-create-account", methods=["POST"])
@login_required
def api_bank_auto_create():
    """Auto-create bank account from statement details with user approval"""
    business, err = api_business_guard()
    if err: return err
    data = request.get_json()
    extracted = data.get("extracted", {})
    bank_name = extracted.get("bank_name", "Bank Account")
    account_name = extracted.get("account_name", business.display_name())
    account_number = extracted.get("account_number", "")
    currency = extracted.get("currency", business.base_currency)
    opening_balance = float(extracted.get("opening_balance", 0))
    existing = None
    if account_number:
        existing = BankAccount.query.filter_by(
            business_id=business.id, account_number=account_number).first()
    if existing:
        return jsonify({"ok":True,"account_id":existing.id,"created":False,
                        "message":"Using existing account: " + existing.account_name})
    acct = BankAccount(business_id=business.id, bank_name=bank_name,
                       account_name=account_name, account_number=account_number,
                       currency=currency, opening_balance=opening_balance,
                       current_balance=opening_balance)
    db.session.add(acct)
    db.session.commit()
    return jsonify({"ok":True,"account_id":acct.id,"created":True,
                    "account_name":account_name,"bank_name":bank_name,
                    "currency":currency,"opening_balance":opening_balance,
                    "message":"Bank account created: " + bank_name + " — " + account_name})


@app.route("/api/bank/post-transactions", methods=["POST"])
@login_required
def api_bank_post_transactions():
    user = current_user(); business = current_business()
    data = request.get_json()
    transactions = data.get("transactions",[])
    bank_account_id = data.get("bank_account_id")
    posted = 0
    cat_to_account = {"Sales Revenue":"4000","Salary Payment":"5100","Rent":"5200",
                      "Utilities":"5300","Supplier Payment":"2000","Tax Payment":"6200",
                      "Bank Charges":"5900","Transfer":"1010","Other":"6900"}
    for txn in transactions:
        if not txn.get("include", True): continue
        try:
            debit = float(txn.get("debit",0))
            credit = float(txn.get("credit",0))
            cat_code = cat_to_account.get(txn.get("category","Other"),"6900")
            try: txn_date = datetime.strptime(txn["date"],"%Y-%m-%d").date()
            except: txn_date = date.today()
            # Use user-selected GL account if provided, otherwise use category mapping
            user_gl = txn.get("account_code")
            if user_gl:
                cat_code = user_gl
            if debit > 0:
                lines = [{"account_code":cat_code,"debit":debit,"credit":0},{"account_code":"1010","debit":0,"credit":debit}]
                et = "BANK_DEBIT"
                le_type = "EXPENSE"
                amount = debit
            else:
                lines = [{"account_code":"1010","debit":credit,"credit":0},{"account_code":cat_code,"debit":0,"credit":credit}]
                et = "BANK_CREDIT"
                le_type = "REVENUE"
                amount = credit
            je = post_journal(business.id, user.id, txn.get("description","Bank txn"), txn.get("reference",""), et, lines)
            db.session.add(BankTransaction(business_id=business.id, bank_account_id=bank_account_id,
                                           txn_date=txn_date, description=txn.get("description",""),
                                           reference=txn.get("reference",""), debit=debit, credit=credit,
                                           balance=float(txn.get("balance",0)), category=txn.get("category","Other"),
                                           journal_entry_id=je.id, is_reconciled=True))
            db.session.add(LedgerEntry(business_id=business.id, entry_type=le_type, amount=amount,
                                       currency=business.base_currency, description=txn.get("description",""),
                                       category=txn.get("category","Other")))
            posted += 1
        except Exception as e: print("Bank txn error: " + str(e))
    db.session.commit()
    return jsonify({"ok":True,"posted":posted,"message":str(posted) + " transactions posted"})

