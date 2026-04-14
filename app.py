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
    business_type = db.Column(db.String(30), default='sole_proprietor')
    has_inventory = db.Column(db.Boolean, default=False)
    has_payroll = db.Column(db.Boolean, default=False)
    has_pos = db.Column(db.Boolean, default=True)
    has_full_accounting = db.Column(db.Boolean, default=False)
    is_tax_registered = db.Column(db.Boolean, default=False)
    tax_registration_number = db.Column(db.String(50))
    tax_registration_date = db.Column(db.Date)
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




# ── ACCOUNTING HEART ─────────────────────────────────────────────────────────

# Default Chart of Accounts per region
DEFAULT_COA = {
    'ASSET': [
        ('1000', 'Cash on Hand'),
        ('1010', 'Bank Account - Primary'),
        ('1020', 'Bank Account - Secondary'),
        ('1100', 'Accounts Receivable'),
        ('1200', 'Inventory'),
        ('1300', 'Prepaid Expenses'),
        ('1500', 'Fixed Assets'),
        ('1510', 'Equipment'),
        ('1520', 'Furniture & Fittings'),
        ('1600', 'Accumulated Depreciation'),
    ],
    'LIABILITY': [
        ('2000', 'Accounts Payable'),
        ('2100', 'Accrued Expenses'),
        ('2200', 'Tax Payable'),
        ('2210', 'GST/VAT Payable'),
        ('2300', 'Salaries Payable'),
        ('2400', 'Short-term Loans'),
        ('2500', 'Long-term Loans'),
    ],
    'EQUITY': [
        ('3000', 'Owner Capital'),
        ('3100', 'Retained Earnings'),
        ('3200', 'Current Year Profit/Loss'),
        ('3300', 'Owner Drawings'),
    ],
    'REVENUE': [
        ('4000', 'Sales Revenue'),
        ('4010', 'Service Revenue'),
        ('4020', 'Other Income'),
        ('4100', 'Sales Returns'),
    ],
    'EXPENSE': [
        ('5000', 'Cost of Goods Sold'),
        ('5100', 'Salaries & Wages'),
        ('5110', 'Allowances & Benefits'),
        ('5200', 'Rent Expense'),
        ('5300', 'Utilities'),
        ('5400', 'Office Supplies'),
        ('5500', 'Marketing & Advertising'),
        ('5600', 'Professional Services'),
        ('5700', 'Travel & Transportation'),
        ('5800', 'Meals & Entertainment'),
        ('5900', 'Bank Charges'),
        ('5910', 'Interest Expense'),
        ('6000', 'Depreciation Expense'),
        ('6100', 'Insurance'),
        ('6200', 'Tax Expense'),
        ('6900', 'Miscellaneous Expense'),
    ],
}

# Tax thresholds per region (annual revenue)
TAX_THRESHOLDS = {
    'MV': {'amount': 1000000, 'currency': 'MVR', 'authority': 'MIRA', 'tax': 'GST'},
    'AE': {'amount': 375000, 'currency': 'AED', 'authority': 'FTA', 'tax': 'VAT'},
    'PK': {'amount': 8000000, 'currency': 'PKR', 'authority': 'FBR', 'tax': 'GST'},
    'CN': {'amount': 500000, 'currency': 'CNY', 'authority': 'SAT', 'tax': 'VAT'},
    'LK': {'amount': 80000000, 'currency': 'LKR', 'authority': 'IRD', 'tax': 'VAT'},
    'IN': {'amount': 2000000, 'currency': 'INR', 'authority': 'CBIC', 'tax': 'GST'},
}


BUSINESS_TYPES = {
    'sole_proprietor': {'name': 'Sole Proprietor', 'accounting': 'simple', 'equity_accounts': False},
    'partnership':     {'name': 'Partnership',      'accounting': 'standard', 'equity_accounts': True},
    'limited_company': {'name': 'Limited Company',  'accounting': 'full', 'equity_accounts': True},
    'llc':             {'name': 'LLC',               'accounting': 'full', 'equity_accounts': True},
    'cooperative':     {'name': 'Cooperative',       'accounting': 'standard', 'equity_accounts': True},
    'ngo':             {'name': 'NGO / Non-Profit',  'accounting': 'standard', 'equity_accounts': False},
    'other':           {'name': 'Other',             'accounting': 'simple', 'equity_accounts': False},
}


class Account(db.Model):
    """Chart of Accounts"""
    __tablename__ = 'accounts'
    id = db.Column(db.Integer, primary_key=True)
    business_id = db.Column(db.Integer, db.ForeignKey('businesses.id'))
    code = db.Column(db.String(10), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    account_type = db.Column(db.String(20))  # ASSET, LIABILITY, EQUITY, REVENUE, EXPENSE
    parent_code = db.Column(db.String(10))
    is_active = db.Column(db.Boolean, default=True)
    opening_balance = db.Column(db.Numeric(12, 2), default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    journal_lines = db.relationship('JournalLine', backref='account', lazy=True)

    def balance(self, business_id):
        debits = db.session.query(db.func.sum(JournalLine.debit)).filter_by(account_id=self.id).scalar() or 0
        credits = db.session.query(db.func.sum(JournalLine.credit)).filter_by(account_id=self.id).scalar() or 0
        opening = float(self.opening_balance or 0)
        if self.account_type in ('ASSET', 'EXPENSE'):
            return opening + float(debits) - float(credits)
        else:
            return opening + float(credits) - float(debits)


class JournalEntry(db.Model):
    """Double-Entry Journal"""
    __tablename__ = 'journal_entries'
    id = db.Column(db.Integer, primary_key=True)
    business_id = db.Column(db.Integer, db.ForeignKey('businesses.id'))
    date = db.Column(db.DateTime, default=datetime.utcnow)
    description = db.Column(db.String(255))
    reference = db.Column(db.String(100))
    entry_type = db.Column(db.String(30))  # PURCHASE, SALE, PAYROLL, BANK, MANUAL
    document_id = db.Column(db.Integer, db.ForeignKey('documents.id'), nullable=True)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    is_posted = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    lines = db.relationship('JournalLine', backref='entry', lazy=True, cascade='all, delete-orphan')


class JournalLine(db.Model):
    __tablename__ = 'journal_lines'
    id = db.Column(db.Integer, primary_key=True)
    journal_entry_id = db.Column(db.Integer, db.ForeignKey('journal_entries.id'))
    account_id = db.Column(db.Integer, db.ForeignKey('accounts.id'))
    description = db.Column(db.String(255))
    debit = db.Column(db.Numeric(12, 2), default=0)
    credit = db.Column(db.Numeric(12, 2), default=0)


class BankAccount(db.Model):
    __tablename__ = 'bank_accounts'
    id = db.Column(db.Integer, primary_key=True)
    business_id = db.Column(db.Integer, db.ForeignKey('businesses.id'))
    account_id = db.Column(db.Integer, db.ForeignKey('accounts.id'))
    bank_name = db.Column(db.String(100))
    account_number = db.Column(db.String(50))
    account_name = db.Column(db.String(100))
    currency = db.Column(db.String(3), default='MVR')
    opening_balance = db.Column(db.Numeric(12, 2), default=0)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class POSSale(db.Model):
    """Mobile POS — 3-second sale recording"""
    __tablename__ = 'pos_sales'
    id = db.Column(db.Integer, primary_key=True)
    business_id = db.Column(db.Integer, db.ForeignKey('businesses.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    customer_id = db.Column(db.Integer, db.ForeignKey('customers.id'), nullable=True)
    amount = db.Column(db.Numeric(12, 2), nullable=False)
    tax_amount = db.Column(db.Numeric(12, 2), default=0)
    currency = db.Column(db.String(3), default='MVR')
    payment_method = db.Column(db.String(20), default='Cash')
    note = db.Column(db.String(100))
    category = db.Column(db.String(50), default='Sale')
    is_credit = db.Column(db.Boolean, default=False)
    journal_entry_id = db.Column(db.Integer, db.ForeignKey('journal_entries.id'), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)


def create_default_coa(business_id):
    """Auto-generate Chart of Accounts for new business"""
    for acct_type, accounts in DEFAULT_COA.items():
        for code, name in accounts:
            acct = Account(
                business_id=business_id,
                code=code,
                name=name,
                account_type=acct_type
            )
            db.session.add(acct)
    db.session.commit()


def get_account(business_id, code):
    return Account.query.filter_by(business_id=business_id, code=code, is_active=True).first()


def post_journal_entry(business_id, user_id, description, reference, entry_type, lines, document_id=None):
    """Create a balanced double-entry journal entry"""
    total_debits = sum(float(l.get('debit', 0)) for l in lines)
    total_credits = sum(float(l.get('credit', 0)) for l in lines)

    if abs(total_debits - total_credits) > 0.01:
        raise ValueError(f'Journal entry not balanced: debits={total_debits}, credits={total_credits}')

    entry = JournalEntry(
        business_id=business_id,
        description=description,
        reference=reference,
        entry_type=entry_type,
        document_id=document_id,
        created_by=user_id
    )
    db.session.add(entry)
    db.session.flush()

    for line in lines:
        account = get_account(business_id, line['account_code'])
        if not account:
            account = Account.query.filter_by(business_id=business_id, code=line['account_code']).first()
        if account:
            jl = JournalLine(
                journal_entry_id=entry.id,
                account_id=account.id,
                description=line.get('description', description),
                debit=float(line.get('debit', 0)),
                credit=float(line.get('credit', 0))
            )
            db.session.add(jl)

    db.session.commit()
    return entry



class Customer(db.Model):
    """CRM — Customer profiles linked to POS sales"""
    __tablename__ = 'customers'
    id = db.Column(db.Integer, primary_key=True)
    business_id = db.Column(db.Integer, db.ForeignKey('businesses.id'))
    name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(30))
    email = db.Column(db.String(150))
    notes = db.Column(db.Text)
    is_vip = db.Column(db.Boolean, default=False)
    credit_limit = db.Column(db.Numeric(12, 2), default=0)
    outstanding_balance = db.Column(db.Numeric(12, 2), default=0)
    total_spent = db.Column(db.Numeric(12, 2), default=0)
    visit_count = db.Column(db.Integer, default=0)
    last_visit = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    sales = db.relationship('POSSale', backref='customer', lazy=True)


class AIConversation(db.Model):
    """AI Accountant conversation history"""
    __tablename__ = 'ai_conversations'
    id = db.Column(db.Integer, primary_key=True)
    business_id = db.Column(db.Integer, db.ForeignKey('businesses.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    role = db.Column(db.String(10))  # user or assistant
    message = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class UserBusiness(db.Model):
    """Join table — one user can own/access many businesses"""
    __tablename__ = 'user_businesses'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    business_id = db.Column(db.Integer, db.ForeignKey('businesses.id'), nullable=False)
    role = db.Column(db.String(20), default='owner')  # owner, accountant, viewer
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    business = db.relationship('Business', backref='memberships', lazy=True)
    user = db.relationship('User', backref='memberships', lazy=True)


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

        business_type = request.form.get('business_type', 'sole_proprietor')
        tax = TAX_RULES.get(region, TAX_RULES['MV'])
        btype = BUSINESS_TYPES.get(business_type, BUSINESS_TYPES['sole_proprietor'])
        business = Business(
            name=business_name,
            region=region,
            base_currency=tax['currency'],
            business_type=business_type,
            has_full_accounting=btype['accounting'] == 'full',
            has_pos=True
        )
        db.session.add(business)
        db.session.flush()

        user = User(name=name, email=email, business_id=business.id, role='owner')
        user.set_password(password)
        db.session.add(user)
        db.session.flush()

        # Create UserBusiness link
        ub = UserBusiness(user_id=user.id, business_id=business.id, role='owner')
        db.session.add(ub)
        db.session.commit()

        session['user_id'] = user.id
        session['business_id'] = business.id
        session['user_name'] = user.name
        session['plan'] = 'Free'
        session['business_name'] = business_name
        session.permanent = True
        create_default_coa(business.id)
        flash(f'Welcome to LEDGR, {name}! Your {btype["name"]} workspace is ready.', 'success')
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
            session['business_name'] = user.business.name if user.business else 'My Business'
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

        # Map category to expense account code
        category_map = {
            'Office Supplies': '5400', 'Utilities': '5300', 'Travel': '5700',
            'Meals': '5800', 'Professional Services': '5600',
            'Inventory Purchase': '5000', 'Payroll': '5100',
            'Tax Payment': '6200', 'Other': '6900'
        }
        expense_code = category_map.get(extracted.get('category', 'Other'), '6900')
        total = float(extracted.get('total_amount') or 0)
        tax = float(extracted.get('tax_amount') or 0)

        try:
            post_journal_entry(
                business_id=business.id,
                user_id=user.id,
                description=f"{extracted.get('doc_type','BILL')} — {extracted.get('vendor_name','')}",
                reference=extracted.get('invoice_number', f'DOC-{doc.id}'),
                entry_type='PURCHASE',
                document_id=doc.id,
                lines=[
                    {'account_code': expense_code, 'debit': total - tax, 'credit': 0, 'description': extracted.get('vendor_name','')},
                    *([{'account_code': '2210', 'debit': tax, 'credit': 0, 'description': 'Tax on purchase'}] if tax > 0 else []),
                    {'account_code': '2000', 'debit': 0, 'credit': total, 'description': extracted.get('vendor_name','')},
                ]
            )
        except Exception as je:
            print(f'Journal error: {je}')

        # Also keep legacy LedgerEntry for backward compatibility
        entry = LedgerEntry(
            business_id=business.id,
            document_id=doc.id,
            entry_type='EXPENSE',
            amount=total,
            tax_amount=tax,
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




# ── POS Routes ────────────────────────────────────────────────────────────────

@app.route('/pos')
@login_required
def pos():
    user = current_user()
    business = user.business
    today_sales = POSSale.query.filter(
        POSSale.business_id == business.id,
        db.func.date(POSSale.timestamp) == datetime.utcnow().date()
    ).all()
    today_total = sum(float(s.amount) for s in today_sales)
    products = Product.query.filter_by(
        business_id=business.id
    ).order_by(Product.name).all() if business.has_inventory else []
    return render_template('pos.html', user=user, business=business,
                           today_sales=today_sales, today_total=today_total,
                           tax=business.tax_rules(), products=products)


@app.route('/api/pos/sale', methods=['POST'])
@login_required
def api_pos_sale():
    user = current_user()
    business = user.business
    data = request.get_json()
    amount = float(data.get('amount', 0))
    if amount <= 0:
        return jsonify({'ok': False, 'error': 'Amount must be greater than zero'})

    tax_rate = TAX_RULES.get(business.region, TAX_RULES['MV'])['tax_rate']
    is_tax_inclusive = data.get('tax_inclusive', True)
    if is_tax_inclusive:
        tax_amount = round(amount - (amount / (1 + tax_rate)), 2)
        net_amount = amount - tax_amount
    else:
        tax_amount = 0
        net_amount = amount

    sale = POSSale(
        business_id=business.id,
        user_id=user.id,
        amount=amount,
        tax_amount=tax_amount,
        currency=business.base_currency,
        payment_method=data.get('payment_method', 'Cash'),
        note=data.get('note', ''),
        category=data.get('category', 'Sale')
    )
    db.session.add(sale)
    db.session.flush()

    # Auto post to journal
    try:
        cash_code = '1000' if data.get('payment_method', 'Cash') == 'Cash' else '1010'
        lines = [
            {'account_code': cash_code, 'debit': amount, 'credit': 0, 'description': data.get('note', 'POS Sale')},
            {'account_code': '4000', 'debit': 0, 'credit': net_amount, 'description': 'Sales Revenue'},
        ]
        if tax_amount > 0:
            lines.append({'account_code': '2210', 'debit': 0, 'credit': tax_amount, 'description': 'Tax collected'})

        je = post_journal_entry(
            business_id=business.id, user_id=user.id,
            description=f'POS Sale — {data.get("note", "")}',
            reference=f'POS-{sale.id}',
            entry_type='SALE', lines=lines
        )
        sale.journal_entry_id = je.id

        # Also add to LedgerEntry
        entry = LedgerEntry(
            business_id=business.id, entry_type='REVENUE',
            amount=amount, tax_amount=tax_amount,
            currency=business.base_currency,
            description=f'POS Sale — {data.get("note", "")}',
            category=data.get('category', 'Sale')
        )
        db.session.add(entry)
    except Exception as e:
        print(f'POS journal error: {e}')

    db.session.commit()

    # Check threshold
    threshold = check_threshold(business)

    return jsonify({
        'ok': True,
        'sale_id': sale.id,
        'amount': amount,
        'tax_amount': tax_amount,
        'net_amount': net_amount,
        'currency': business.base_currency,
        'threshold_warning': threshold
    })


@app.route('/api/pos/today')
@login_required
def api_pos_today():
    user = current_user()
    business = user.business
    today_sales = POSSale.query.filter(
        POSSale.business_id == business.id,
        db.func.date(POSSale.timestamp) == datetime.utcnow().date()
    ).all()
    return jsonify({
        'ok': True,
        'count': len(today_sales),
        'total': sum(float(s.amount) for s in today_sales),
        'currency': business.base_currency
    })


# ── Chart of Accounts Routes ──────────────────────────────────────────────────

@app.route('/accounts')
@login_required
def chart_of_accounts():
    user = current_user()
    business = user.business
    accounts = Account.query.filter_by(business_id=business.id, is_active=True).order_by(Account.code).all()
    if not accounts:
        create_default_coa(business.id)
        accounts = Account.query.filter_by(business_id=business.id, is_active=True).order_by(Account.code).all()
    grouped = {}
    for acct in accounts:
        t = acct.account_type
        if t not in grouped:
            grouped[t] = []
        grouped[t].append(acct)
    return render_template('accounts.html', user=user, business=business,
                           grouped=grouped, tax=business.tax_rules())


@app.route('/journal')
@login_required
def journal():
    user = current_user()
    business = user.business
    entries = JournalEntry.query.filter_by(business_id=business.id).order_by(
        JournalEntry.date.desc()).limit(50).all()
    return render_template('journal.html', user=user, business=business,
                           entries=entries, tax=business.tax_rules())


# ── Reports ───────────────────────────────────────────────────────────────────

@app.route('/reports')
@login_required
def reports():
    user = current_user()
    business = user.business
    tax = business.tax_rules()
    threshold = check_threshold(business)

    # P&L
    revenue_entries = LedgerEntry.query.filter_by(business_id=business.id, entry_type='REVENUE').all()
    expense_entries = LedgerEntry.query.filter_by(business_id=business.id, entry_type='EXPENSE').all()
    total_revenue = sum(float(e.amount or 0) for e in revenue_entries)
    total_expenses = sum(float(e.amount or 0) for e in expense_entries)
    total_tax = sum(float(e.tax_amount or 0) for e in expense_entries + revenue_entries)
    net_profit = total_revenue - total_expenses

    # Balance sheet from CoA
    assets = Account.query.filter_by(business_id=business.id, account_type='ASSET', is_active=True).all()
    liabilities = Account.query.filter_by(business_id=business.id, account_type='LIABILITY', is_active=True).all()
    equity = Account.query.filter_by(business_id=business.id, account_type='EQUITY', is_active=True).all()

    total_assets = sum(a.balance(business.id) for a in assets)
    total_liabilities = sum(a.balance(business.id) for a in liabilities)
    total_equity = sum(a.balance(business.id) for a in equity) + net_profit

    return render_template('reports.html', user=user, business=business, tax=tax,
                           total_revenue=total_revenue, total_expenses=total_expenses,
                           total_tax=total_tax, net_profit=net_profit,
                           total_assets=total_assets, total_liabilities=total_liabilities,
                           total_equity=total_equity, threshold=threshold)


# ── Compliance Monitor ────────────────────────────────────────────────────────

def check_threshold(business):
    threshold_info = TAX_THRESHOLDS.get(business.region)
    if not threshold_info:
        return None
    from datetime import date
    twelve_months_ago = datetime.utcnow() - timedelta(days=365)
    revenue_entries = LedgerEntry.query.filter(
        LedgerEntry.business_id == business.id,
        LedgerEntry.entry_type == 'REVENUE',
        LedgerEntry.timestamp >= twelve_months_ago
    ).all()
    rolling_revenue = sum(float(e.amount or 0) for e in revenue_entries)
    threshold_amount = threshold_info['amount']
    percentage = (rolling_revenue / threshold_amount * 100) if threshold_amount > 0 else 0
    return {
        'rolling_revenue': rolling_revenue,
        'threshold': threshold_amount,
        'currency': threshold_info['currency'],
        'percentage': round(percentage, 1),
        'authority': threshold_info['authority'],
        'tax': threshold_info['tax'],
        'warning': percentage >= 80,
        'exceeded': percentage >= 100
    }


@app.route('/api/compliance/threshold')
@login_required
def api_compliance_threshold():
    user = current_user()
    threshold = check_threshold(user.business)
    return jsonify({'ok': True, 'threshold': threshold})




@app.route('/api/inventory/from-upload', methods=['POST'])
@login_required
def api_inventory_from_upload():
    """Auto-update inventory from uploaded document line items"""
    user = current_user()
    business = user.business

    if not business.has_inventory:
        return jsonify({'ok': False, 'error': 'Inventory tracking is not enabled for this business'})

    data = request.get_json()
    items = data.get('items', [])
    document_id = data.get('document_id')
    results = []

    for item in items:
        if not item.get('include', True):
            continue

        name = item.get('description', '').strip()
        qty = int(item.get('quantity') or 1)
        unit_cost = float(item.get('unit_price') or 0)

        if not name:
            continue

        # Try to match existing product by name
        existing = Product.query.filter(
            Product.business_id == business.id,
            db.func.lower(Product.name).contains(name.lower()[:20])
        ).first()

        if existing:
            old_stock = existing.stock_level
            existing.stock_level = (existing.stock_level or 0) + qty
            if unit_cost > 0:
                existing.unit_cost = unit_cost
            db.session.commit()
            results.append({
                'product': existing.name,
                'action': 'updated',
                'old_stock': old_stock,
                'new_stock': existing.stock_level
            })
        else:
            # Create new product
            product = Product(
                business_id=business.id,
                name=name,
                stock_level=qty,
                unit_cost=unit_cost,
                unit_price=round(unit_cost * 1.3, 2),  # default 30% markup
                currency=business.base_currency,
                reorder_level=max(5, qty // 2)
            )
            db.session.add(product)
            db.session.commit()
            results.append({
                'product': name,
                'action': 'created',
                'old_stock': 0,
                'new_stock': qty
            })

    # Post correct journal entry for inventory purchase
    if results and document_id:
        doc = Document.query.get(document_id)
        if doc:
            total = float(doc.total_amount or 0)
            tax = float(doc.tax_amount or 0)
            try:
                post_journal_entry(
                    business_id=business.id,
                    user_id=user.id,
                    description=f'Inventory Purchase — {doc.vendor_name or ""}',
                    reference=doc.invoice_number or f'INV-{doc.id}',
                    entry_type='INVENTORY_PURCHASE',
                    document_id=document_id,
                    lines=[
                        {'account_code': '1200', 'debit': total - tax, 'credit': 0, 'description': 'Inventory received'},
                        *([{'account_code': '2210', 'debit': tax, 'credit': 0, 'description': 'Tax on inventory purchase'}] if tax > 0 else []),
                        {'account_code': '2000', 'debit': 0, 'credit': total, 'description': doc.vendor_name or 'Supplier'},
                    ]
                )
            except Exception as e:
                print(f'Inventory journal error: {e}')

    return jsonify({'ok': True, 'results': results, 'updated': len(results)})







# ── Customer CRM Routes ───────────────────────────────────────────────────────

@app.route('/customers')
@login_required
def customers():
    user = current_user()
    business = user.business
    customer_list = Customer.query.filter_by(business_id=business.id).order_by(
        Customer.total_spent.desc()).all()
    total_customers = len(customer_list)
    vip_count = sum(1 for c in customer_list if c.is_vip)
    total_outstanding = sum(float(c.outstanding_balance or 0) for c in customer_list)
    return render_template('customers.html', user=user, business=business,
                           customers=customer_list, total_customers=total_customers,
                           vip_count=vip_count, total_outstanding=total_outstanding,
                           tax=business.tax_rules())


@app.route('/api/customer/add', methods=['POST'])
@login_required
def api_customer_add():
    user = current_user()
    data = request.get_json()
    name = data.get('name', '').strip()
    if not name:
        return jsonify({'ok': False, 'error': 'Name is required'})
    existing = Customer.query.filter_by(
        business_id=user.business_id, phone=data.get('phone')).first()
    if existing and data.get('phone'):
        return jsonify({'ok': False, 'error': 'Customer with this phone already exists',
                        'customer_id': existing.id, 'name': existing.name})
    customer = Customer(
        business_id=user.business_id,
        name=name,
        phone=data.get('phone', ''),
        email=data.get('email', ''),
        notes=data.get('notes', ''),
        is_vip=data.get('is_vip', False),
        credit_limit=float(data.get('credit_limit', 0))
    )
    db.session.add(customer)
    db.session.commit()
    return jsonify({'ok': True, 'customer_id': customer.id, 'name': customer.name})


@app.route('/api/customer/search')
@login_required
def api_customer_search():
    user = current_user()
    q = request.args.get('q', '').strip().lower()
    if not q or len(q) < 2:
        return jsonify([])
    customers = Customer.query.filter(
        Customer.business_id == user.business_id,
        db.or_(
            db.func.lower(Customer.name).contains(q),
            Customer.phone.contains(q)
        )
    ).limit(8).all()
    return jsonify([{
        'id': c.id, 'name': c.name, 'phone': c.phone or '',
        'total_spent': float(c.total_spent or 0),
        'visit_count': c.visit_count or 0,
        'is_vip': c.is_vip,
        'outstanding_balance': float(c.outstanding_balance or 0),
        'currency': user.business.base_currency
    } for c in customers])


@app.route('/api/customer/<int:customer_id>')
@login_required
def api_customer_detail(customer_id):
    user = current_user()
    customer = Customer.query.filter_by(
        id=customer_id, business_id=user.business_id).first()
    if not customer:
        return jsonify({'ok': False, 'error': 'Customer not found'})
    recent_sales = POSSale.query.filter_by(
        customer_id=customer_id).order_by(POSSale.timestamp.desc()).limit(10).all()
    return jsonify({
        'ok': True,
        'id': customer.id,
        'name': customer.name,
        'phone': customer.phone,
        'email': customer.email,
        'notes': customer.notes,
        'is_vip': customer.is_vip,
        'total_spent': float(customer.total_spent or 0),
        'visit_count': customer.visit_count or 0,
        'outstanding_balance': float(customer.outstanding_balance or 0),
        'credit_limit': float(customer.credit_limit or 0),
        'last_visit': customer.last_visit.strftime('%d %b %Y %H:%M') if customer.last_visit else None,
        'recent_sales': [{'amount': float(s.amount), 'date': s.timestamp.strftime('%d %b %Y'),
                          'method': s.payment_method, 'note': s.note} for s in recent_sales]
    })


# ── AI Accountant ─────────────────────────────────────────────────────────────

@app.route('/ai')
@login_required
def ai_accountant():
    user = current_user()
    business = user.business
    history = AIConversation.query.filter_by(
        business_id=business.id).order_by(AIConversation.created_at.desc()).limit(20).all()
    history = list(reversed(history))
    return render_template('ai.html', user=user, business=business,
                           history=history, tax=business.tax_rules())


@app.route('/api/ai/chat', methods=['POST'])
@login_required
def api_ai_chat():
    user = current_user()
    business = user.business
    data = request.get_json()
    message = data.get('message', '').strip()

    if not message:
        return jsonify({'ok': False, 'error': 'Message is empty'})

    if not ANTHROPIC_KEY:
        return jsonify({'ok': False, 'error': 'AI not configured'})

    # Build business context for AI
    tax = business.tax_rules()
    total_revenue = db.session.query(db.func.sum(LedgerEntry.amount)).filter_by(
        business_id=business.id, entry_type='REVENUE').scalar() or 0
    total_expenses = db.session.query(db.func.sum(LedgerEntry.amount)).filter_by(
        business_id=business.id, entry_type='EXPENSE').scalar() or 0
    total_docs = Document.query.filter_by(business_id=business.id).count()
    total_customers = Customer.query.filter_by(business_id=business.id).count()
    employee_count = Employee.query.filter_by(business_id=business.id, is_active=True).count()
    monthly_payroll = db.session.query(db.func.sum(Employee.monthly_salary)).filter_by(
        business_id=business.id, is_active=True).scalar() or 0

    threshold = check_threshold(business)
    threshold_info = f"Rolling 12-month revenue: {tax['currency']} {float(total_revenue):.2f} — {threshold['percentage'] if threshold else 0}% of {tax['authority']} threshold." if threshold else ""

    recent_entries = LedgerEntry.query.filter_by(business_id=business.id).order_by(
        LedgerEntry.timestamp.desc()).limit(5).all()
    recent_summary = '; '.join([f"{e.entry_type} {e.currency} {float(e.amount):.2f} ({e.description or e.category})" for e in recent_entries])

    system_prompt = f"""You are LEDGR AI Accountant — a friendly, expert financial advisor for {business.name}.

BUSINESS CONTEXT:
- Business: {business.name}
- Region: {tax['name']} | Currency: {tax['currency']}
- Tax Authority: {tax['authority']} | Tax: {tax['tax_name']} at {tax['tax_rate']*100:.0f}%
- Tax Registered: {'Yes' if business.is_tax_registered else 'No — below threshold'}
- Total Revenue: {tax['currency']} {float(total_revenue):.2f}
- Total Expenses: {tax['currency']} {float(total_expenses):.2f}
- Net Profit: {tax['currency']} {float(total_revenue - total_expenses):.2f}
- Documents Processed: {total_docs}
- Customers: {total_customers}
- Employees: {employee_count} | Monthly Payroll: {tax['currency']} {float(monthly_payroll):.2f}
- {threshold_info}
- Recent transactions: {recent_summary}

YOUR ROLE:
- Answer financial questions about this business in simple, friendly language
- Flag concerns proactively — cash flow issues, approaching tax threshold, high expenses
- Explain accounting concepts simply — no jargon unless asked
- Give actionable advice specific to {tax['name']} business regulations
- If asked about tax, reference {tax['authority']} rules
- Keep responses concise — 2-3 paragraphs maximum
- Use {tax['currency']} for all amounts

You are NOT a replacement for a licensed accountant. Always recommend consulting a professional for major decisions."""

    # Get conversation history
    history = AIConversation.query.filter_by(
        business_id=business.id).order_by(AIConversation.created_at.desc()).limit(10).all()
    history = list(reversed(history))

    messages = [{'role': h.role, 'content': h.message} for h in history]
    messages.append({'role': 'user', 'content': message})

    # Save user message
    user_msg = AIConversation(
        business_id=business.id, user_id=user.id,
        role='user', message=message)
    db.session.add(user_msg)

    try:
        req_body = json.dumps({
            'model': 'claude-sonnet-4-20250514',
            'max_tokens': 1024,
            'system': system_prompt,
            'messages': messages
        }).encode()

        req = urllib.request.Request('https://api.anthropic.com/v1/messages',
            data=req_body,
            headers={
                'Content-Type': 'application/json',
                'x-api-key': ANTHROPIC_KEY,
                'anthropic-version': '2023-06-01'
            })

        with urllib.request.urlopen(req, timeout=60) as resp:
            result = json.loads(resp.read())
            reply = result['content'][0]['text']

        # Save assistant reply
        ai_msg = AIConversation(
            business_id=business.id, user_id=user.id,
            role='assistant', message=reply)
        db.session.add(ai_msg)
        db.session.commit()

        return jsonify({'ok': True, 'reply': reply})

    except urllib.error.HTTPError as e:
        db.session.rollback()
        error_body = e.read().decode()
        return jsonify({'ok': False, 'error': f'AI API error {e.code}: {error_body}'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'ok': False, 'error': str(e)})


# ── Updated POS sale with customer + tax toggle ────────────────────────────────

@app.route('/api/pos/sale/v2', methods=['POST'])
@login_required
def api_pos_sale_v2():
    user = current_user()
    business = user.business
    data = request.get_json()
    amount = float(data.get('amount', 0))

    if amount <= 0:
        return jsonify({'ok': False, 'error': 'Amount must be greater than zero'})

    # Tax calculation — only if business is tax registered
    tax_amount = 0
    net_amount = amount
    if business.is_tax_registered:
        tax_rate = TAX_RULES.get(business.region, TAX_RULES['MV'])['tax_rate']
        if data.get('tax_inclusive', True):
            tax_amount = round(amount - (amount / (1 + tax_rate)), 2)
            net_amount = amount - tax_amount

    payment_method = data.get('payment_method', 'Cash')
    is_credit = payment_method == 'Credit'
    customer_id = data.get('customer_id')

    sale = POSSale(
        business_id=business.id,
        user_id=user.id,
        customer_id=customer_id,
        amount=amount,
        tax_amount=tax_amount,
        currency=business.base_currency,
        payment_method=payment_method,
        note=data.get('note', ''),
        category=data.get('category', 'Sale'),
        is_credit=is_credit
    )
    db.session.add(sale)
    db.session.flush()

    # Update customer stats
    if customer_id:
        customer = Customer.query.get(customer_id)
        if customer:
            customer.total_spent = float(customer.total_spent or 0) + amount
            customer.visit_count = (customer.visit_count or 0) + 1
            customer.last_visit = datetime.utcnow()
            if is_credit:
                customer.outstanding_balance = float(customer.outstanding_balance or 0) + amount
            db.session.commit()

    # Journal entry
    try:
        cash_code = '1100' if is_credit else ('1000' if payment_method == 'Cash' else '1010')
        lines = [
            {'account_code': cash_code, 'debit': amount, 'credit': 0,
             'description': data.get('note', 'POS Sale')},
            {'account_code': '4000', 'debit': 0, 'credit': net_amount,
             'description': 'Sales Revenue'},
        ]
        if tax_amount > 0:
            lines.append({'account_code': '2210', 'debit': 0, 'credit': tax_amount,
                          'description': 'Tax collected'})

        je = post_journal_entry(
            business_id=business.id, user_id=user.id,
            description=f'POS Sale — {data.get("note", "")}',
            reference=f'POS-{sale.id}', entry_type='SALE', lines=lines)
        sale.journal_entry_id = je.id

        entry = LedgerEntry(
            business_id=business.id, entry_type='REVENUE',
            amount=amount, tax_amount=tax_amount,
            currency=business.base_currency,
            description=f'POS Sale — {data.get("note", "")}',
            category=data.get('category', 'Sale'))
        db.session.add(entry)
    except Exception as e:
        print(f'POS v2 journal error: {e}')

    db.session.commit()

    threshold = check_threshold(business)
    return jsonify({
        'ok': True,
        'sale_id': sale.id,
        'amount': amount,
        'tax_amount': tax_amount,
        'net_amount': net_amount,
        'currency': business.base_currency,
        'is_tax_registered': business.is_tax_registered,
        'threshold_warning': threshold
    })


@app.route('/api/business/settings', methods=['POST'])
@login_required
def api_business_settings():
    user = current_user()
    business = user.business
    data = request.get_json()
    if 'has_inventory' in data:
        business.has_inventory = bool(data['has_inventory'])
    if 'has_payroll' in data:
        business.has_payroll = bool(data['has_payroll'])
    if 'has_pos' in data:
        business.has_pos = bool(data['has_pos'])
    if 'is_tax_registered' in data:
        business.is_tax_registered = bool(data['is_tax_registered'])
    if 'tax_registration_number' in data:
        business.tax_registration_number = data['tax_registration_number']
    if 'tax_id' in data:
        business.tax_id = data['tax_id']
    db.session.commit()
    return jsonify({'ok': True, 'message': 'Settings updated'})




# ── Multi-Business Routes ─────────────────────────────────────────────────────

@app.route('/business/add', methods=['GET', 'POST'])
@login_required
def add_business():
    user = current_user()
    if request.method == 'POST':
        business_name = request.form.get('business_name', '').strip()
        region = request.form.get('region', 'MV')
        business_type = request.form.get('business_type', 'sole_proprietor')

        if not business_name:
            flash('Business name is required', 'error')
            return render_template('add_business.html', regions=TAX_RULES,
                                   business_types=BUSINESS_TYPES, user=user)

        # Check plan limits
        existing = UserBusiness.query.filter_by(user_id=user.id).count()
        if existing >= 1 and user.plan == 'free':
            flash('Upgrade to Pro or Business plan to add multiple businesses', 'error')
            return redirect(url_for('settings'))

        tax = TAX_RULES.get(region, TAX_RULES['MV'])
        btype = BUSINESS_TYPES.get(business_type, BUSINESS_TYPES['sole_proprietor'])
        business = Business(
            name=business_name,
            region=region,
            base_currency=tax['currency'],
            business_type=business_type,
            has_full_accounting=btype['accounting'] == 'full',
            has_pos=True
        )
        db.session.add(business)
        db.session.flush()

        ub = UserBusiness(user_id=user.id, business_id=business.id, role='owner')
        db.session.add(ub)
        db.session.commit()

        create_default_coa(business.id)
        session['business_id'] = business.id
        flash(f'{business_name} workspace created!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('add_business.html', regions=TAX_RULES,
                           business_types=BUSINESS_TYPES, user=user)


@app.route('/business/switch/<int:business_id>')
@login_required
def switch_business(business_id):
    user = current_user()
    ub = UserBusiness.query.filter_by(
        user_id=user.id, business_id=business_id).first()
    if ub:
        session['business_id'] = business_id
        flash(f'Switched to {ub.business.name}', 'success')
    return redirect(url_for('dashboard'))


@app.route('/api/pos/receipt', methods=['POST'])
@login_required
def api_pos_receipt():
    """Generate WhatsApp receipt text"""
    user = current_user()
    business = user.business
    data = request.get_json()
    amount = float(data.get('amount', 0))
    tax = float(data.get('tax_amount', 0))
    note = data.get('note', 'Sale')
    payment = data.get('payment_method', 'Cash')
    customer_name = data.get('customer_name', '')
    now = datetime.utcnow().strftime('%d %b %Y %H:%M')

    receipt = f"""*{business.name}*
━━━━━━━━━━━━━━━
📋 RECEIPT
Date: {now}
{"Customer: " + customer_name if customer_name else ""}
Item: {note}
Payment: {payment}
━━━━━━━━━━━━━━━
{"Subtotal: " + business.base_currency + " " + f"{amount-tax:.2f}" if tax > 0 else ""}
{"Tax: " + business.base_currency + " " + f"{tax:.2f}" if tax > 0 else ""}
*TOTAL: {business.base_currency} {amount:.2f}*
━━━━━━━━━━━━━━━
Thank you! 🙏
Powered by LEDGR"""

    import urllib.parse
    wa_url = 'https://wa.me/?text=' + urllib.parse.quote(receipt)
    return jsonify({'ok': True, 'receipt': receipt, 'wa_url': wa_url})



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
