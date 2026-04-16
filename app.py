import os, json, base64, urllib.request, urllib.parse, urllib.error, re
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
    'MV': {'name':'Maldives','currency':'MVR','tax_name':'GST','tax_rate':0.08,'authority':'MIRA','tin_format':'XXXXXXXGSTXXX'},
    'AE': {'name':'UAE',     'currency':'AED','tax_name':'VAT','tax_rate':0.05,'authority':'FTA', 'tin_format':'TRN XXXXXXXXXXXXXXX'},
    'PK': {'name':'Pakistan','currency':'PKR','tax_name':'GST','tax_rate':0.17,'authority':'FBR', 'tin_format':'XXXXXXX-X'},
    'CN': {'name':'China',   'currency':'CNY','tax_name':'VAT','tax_rate':0.13,'authority':'SAT', 'tin_format':'XXXXXXXXXXXXXXXXXX'},
    'LK': {'name':'Sri Lanka','currency':'LKR','tax_name':'VAT','tax_rate':0.18,'authority':'IRD','tin_format':'XXXXXXXXX'},
    'IN': {'name':'India',   'currency':'INR','tax_name':'GST','tax_rate':0.18,'authority':'CBIC','tin_format':'XXAAAAAAAAAAXXX'},
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
    name = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(50))
    stock_level = db.Column(db.Integer, default=0)
    reorder_level = db.Column(db.Integer, default=10)
    unit_cost = db.Column(db.Numeric(12,2), default=0)
    unit_price = db.Column(db.Numeric(12,2), default=0)
    currency = db.Column(db.String(3), default='MVR')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Customer(db.Model):
    __tablename__ = 'customers'
    id = db.Column(db.Integer, primary_key=True)
    business_id = db.Column(db.Integer, db.ForeignKey('businesses.id'))
    name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(30))
    email = db.Column(db.String(150))
    notes = db.Column(db.Text)
    is_vip = db.Column(db.Boolean, default=False)
    credit_limit = db.Column(db.Numeric(12,2), default=0)
    outstanding_balance = db.Column(db.Numeric(12,2), default=0)
    total_spent = db.Column(db.Numeric(12,2), default=0)
    visit_count = db.Column(db.Integer, default=0)
    last_visit = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)



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
    full_name = db.Column(db.String(100), nullable=False)
    employee_id = db.Column(db.String(50))
    position = db.Column(db.String(100))
    department = db.Column(db.String(100))
    nationality = db.Column(db.String(50))
    id_card_number = db.Column(db.String(50))
    passport_number = db.Column(db.String(50))
    visa_number = db.Column(db.String(50))
    visa_expiry = db.Column(db.Date)
    work_permit_number = db.Column(db.String(50))
    work_permit_expiry = db.Column(db.Date)
    phone = db.Column(db.String(30))
    email = db.Column(db.String(150))
    monthly_salary = db.Column(db.Numeric(12,2))
    allowances = db.Column(db.Numeric(12,2), default=0)
    currency = db.Column(db.String(3), default='MVR')
    employment_type = db.Column(db.String(20), default='Full-time')
    joined_date = db.Column(db.Date)
    contract_end_date = db.Column(db.Date)
    is_active = db.Column(db.Boolean, default=True)

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
    invoice_number = db.Column(db.String(50))
    po_number = db.Column(db.String(100))        # Customer PO reference
    invoice_date = db.Column(db.Date, default=date.today)
    due_date = db.Column(db.Date)
    currency = db.Column(db.String(3), default='MVR')
    exchange_rate = db.Column(db.Numeric(10,4), default=1)  # For multicurrency
    subtotal = db.Column(db.Numeric(12,2), default=0)
    discount_amount = db.Column(db.Numeric(12,2), default=0)
    tax_amount = db.Column(db.Numeric(12,2), default=0)
    total_amount = db.Column(db.Numeric(12,2), default=0)
    amount_paid = db.Column(db.Numeric(12,2), default=0)
    status = db.Column(db.String(20), default='DRAFT')  # DRAFT SENT PAID PARTIAL OVERDUE CANCELLED
    payment_terms = db.Column(db.String(100))
    notes = db.Column(db.Text)
    items = db.Column(db.Text, default='[]')     # JSON line items
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
    prompt = f'''You are LEDGR AI, an expert accountant for {tax["name"]} businesses.
Rules: currency={tax["currency"]}, tax={tax["tax_name"]} at {tax["tax_rate"]*100:.0f}%, authority={tax["authority"]}.
{compliance_hints}
Return ONLY valid JSON:
{{"doc_type":"BILL","vendor_name":"","vendor_tax_id":null,"invoice_number":"","invoice_date":"YYYY-MM-DD","due_date":null,"currency":"{tax["currency"]}","subtotal":0.00,"tax_amount":0.00,"total_amount":0.00,"category":"Other","confidence":"high","notes":"","line_items":[{{"description":"","quantity":1,"unit_price":0.00,"total":0.00}}],"compliance_data":{{"irn":null,"qr_code":null,"supply_type":"standard"}}}}
doc_type: BILL RECEIPT INVOICE PAYROLL_SLIP BANK_STATEMENT
category: Office Supplies Utilities Travel Meals Professional Services Inventory Purchase Payroll Tax Payment Other'''
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
    employees = Employee.query.filter_by(business_id=business.id, is_active=True).all()
    total_payroll = sum(float(e.monthly_salary or 0) + float(e.allowances or 0) for e in employees)
    return render_template('payroll.html', user=user, business=business, employees=employees, total_payroll=total_payroll)

@app.route('/pos')
@login_required
def pos():
    user = current_user(); business = current_business()
    today_sales = POSSale.query.filter(POSSale.business_id==business.id,
        db.func.date(POSSale.timestamp)==datetime.utcnow().date()).order_by(POSSale.timestamp.desc()).all()
    today_total = sum(float(s.amount) for s in today_sales)
    products = Product.query.filter_by(business_id=business.id).order_by(Product.name).all() if business.has_inventory else []
    return render_template('pos.html', user=user, business=business, tax=business.tax_rules(),
                           today_sales=today_sales, today_total=today_total, products=products)

@app.route('/customers')
@login_required
def customers():
    user = current_user(); business = current_business()
    customer_list = Customer.query.filter_by(business_id=business.id).order_by(Customer.total_spent.desc()).all()
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
    return render_template('invoices.html', user=user, business=business, invoices=invoice_list,
                           customers=customers_list, tax=business.tax_rules())

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
        max_b = user.get_plan()['businesses']
        if existing_count >= max_b:
            flash(f'Your plan allows {max_b} business(es). Upgrade to add more.','error')
            return redirect(url_for('settings'))
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
    employees = Employee.query.filter_by(business_id=business.id, is_active=True).all()
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
            tax_amount = round(amount - (amount / (1 + tax_rate)), 2)
            net_amount = amount - tax_amount
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
    data = request.get_json()
    name = data.get('name','').strip()
    if not name: return jsonify({'ok':False,'error':'Name is required'})
    if data.get('phone'):
        existing = Customer.query.filter_by(business_id=business.id, phone=data.get('phone')).first() if data.get('phone') else None
        if existing: return jsonify({'ok':False,'error':'Customer with this phone exists','customer_id':existing.id,'name':existing.name})
    c = Customer(business_id=current_business().id, name=name, phone=data.get('phone',''),
                 email=data.get('email',''), notes=data.get('notes',''),
                 is_vip=data.get('is_vip',False), credit_limit=float(data.get('credit_limit',0)))
    db.session.add(c)
    db.session.commit()
    return jsonify({'ok':True,'customer_id':c.id,'name':c.name})

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
    return jsonify({'ok':True,'id':c.id,'name':c.name,'phone':c.phone,'email':c.email,'notes':c.notes,
                    'is_vip':c.is_vip,'total_spent':float(c.total_spent or 0),'visit_count':c.visit_count or 0,
                    'outstanding_balance':float(c.outstanding_balance or 0),'credit_limit':float(c.credit_limit or 0),
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
@app.route('/api/employee/add', methods=['POST'])
@login_required
def api_employee_add():
    user = current_user(); business = current_business()
    data = request.get_json()
    def pd(d):
        try: return datetime.strptime(d,'%Y-%m-%d').date() if d else None
        except: return None
    e = Employee(business_id=business.id, full_name=data.get('full_name',''),
                 employee_id=data.get('employee_id',''), position=data.get('position',''),
                 department=data.get('department',''), nationality=data.get('nationality',''),
                 id_card_number=data.get('id_card_number',''), passport_number=data.get('passport_number',''),
                 visa_number=data.get('visa_number',''), visa_expiry=pd(data.get('visa_expiry')),
                 work_permit_number=data.get('work_permit_number',''), work_permit_expiry=pd(data.get('work_permit_expiry')),
                 phone=data.get('phone',''), email=data.get('email',''),
                 monthly_salary=float(data.get('monthly_salary',0)), allowances=float(data.get('allowances',0)),
                 currency=business.base_currency, employment_type=data.get('employment_type','Full-time'),
                 joined_date=pd(data.get('joined_date')), contract_end_date=pd(data.get('contract_end_date')))
    db.session.add(e)
    db.session.commit()
    return jsonify({'ok':True,'employee_id':e.id,'message':'Employee added'})

# ── API: Settings & Business ──────────────────────────────────────────────────
@app.route('/api/business/settings', methods=['POST'])
@login_required
def api_business_settings():
    business, err = api_business_guard()
    if err: return err
    data = request.get_json()
    bool_fields = ['has_inventory','has_payroll','has_pos','is_tax_registered',
                   'has_full_accounting','collect_tax_on_sales']
    for field in bool_fields:
        if field in data: setattr(business, field, bool(data[field]))
    text_fields = ['tax_registration_number','tax_id','secondary_currency']
    for field in text_fields:
        if field in data: setattr(business, field, data[field])
    db.session.commit()
    return jsonify({'ok':True,'message':'Settings updated'})

# ── API: Invoices ─────────────────────────────────────────────────────────────
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


@app.route("/api/bank/add-account", methods=["POST"])
@login_required
def api_bank_add_account():
    business = current_business()
    data = request.get_json()
    acct = BankAccount(business_id=business.id, bank_name=data.get("bank_name",""),
                       account_name=data.get("account_name",""), account_number=data.get("account_number",""),
                       currency=data.get("currency",business.base_currency),
                       opening_balance=float(data.get("opening_balance",0)),
                       current_balance=float(data.get("opening_balance",0)))
    db.session.add(acct)
    db.session.commit()
    return jsonify({"ok":True,"account_id":acct.id})


@app.route("/api/bank/upload-statement", methods=["POST"])
@login_required
def api_bank_upload_statement():
    user = current_user(); business = current_business()
    if not ANTHROPIC_KEY: return jsonify({"ok":False,"error":"AI not configured"})
    data = request.get_json()
    file_b64 = data.get("file","")
    media_type = data.get("media_type","image/jpeg")
    bank_account_id = data.get("bank_account_id")
    tax = business.tax_rules()
    currency = tax["currency"]
    region_name = tax["name"]
    prompt = (
        "You are LEDGR AI analysing a bank statement for a " + region_name + " business. "
        "Extract ALL transactions. Return ONLY valid JSON: "
        "{\"account_name\":\"\",\"account_number\":\"\",\"bank_name\":\"\",\"statement_period\":\"\","
        "\"opening_balance\":0.00,\"closing_balance\":0.00,\"currency\":\"" + currency + "\","
        "\"transactions\":[{\"date\":\"YYYY-MM-DD\",\"description\":\"\",\"reference\":\"\","
        "\"debit\":0.00,\"credit\":0.00,\"balance\":0.00,\"category\":\"Other\"}]} "
        "debit=money out, credit=money in. "
        "category: Sales Revenue, Salary Payment, Rent, Utilities, Supplier Payment, Tax Payment, Bank Charges, Transfer, Other"
    )
    content = ({"type":"document","source":{"type":"base64","media_type":"application/pdf","data":file_b64}}
               if media_type=="application/pdf" else
               {"type":"image","source":{"type":"base64","media_type":media_type,"data":file_b64}})
    try:
        body = json.dumps({"model":"claude-sonnet-4-6","max_tokens":4096,
                           "messages":[{"role":"user","content":[content,{"type":"text","text":prompt}]}]}).encode()
        req = urllib.request.Request("https://api.anthropic.com/v1/messages", data=body,
                                     headers={"Content-Type":"application/json","x-api-key":ANTHROPIC_KEY,"anthropic-version":"2023-06-01"})
        with urllib.request.urlopen(req, timeout=120) as resp:
            result = json.loads(resp.read())
            text = result["content"][0]["text"]
            # Try to find JSON in response
            m = re.search(r"\{[\s\S]*\}", text)
            if not m:
                return jsonify({"ok":False,"error":"AI could not read this bank statement. Please ensure the image is clear and well-lit."})
            try:
                extracted = json.loads(m.group())
            except json.JSONDecodeError:
                return jsonify({"ok":False,"error":"Could not parse bank statement data. Try uploading a clearer image."})
        txn_count = len(extracted.get("transactions",[]))
        return jsonify({"ok":True,"extracted":extracted,"bank_account_id":bank_account_id,
                        "message":str(txn_count) + " transactions extracted from statement"})
    except urllib.error.URLError as e:
        return jsonify({"ok":False,"error":"Connection timeout. Bank statements can take up to 2 minutes — please try again."})
    except Exception as e:
        return jsonify({"ok":False,"error":"Processing error: " + str(e)[:100]})


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

