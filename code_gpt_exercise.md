# %% [markdown]
# # Exercise: Build a Code-GPT from Scratch
# 
# **What this is:** You'll build the full GPT (with attention) trained on Python code
# instead of Shakespeare. This is the direct foundation for your security scanner.
#
# **What you'll learn:**
# - The complete GPT architecture (everything from the diagram)
# - How to train on CODE instead of natural language
# - How tokenization works differently for code
# - How to make the model predict code patterns
#
# **By the end:** You'll have a model that can autocomplete Python code.
# That same architecture, trained on vulnerability data, becomes your scanner.
#
# Run each cell in order. Read every comment.

# %% Step 1: Imports
import torch
import torch.nn as nn
from torch.nn import functional as F
import os
import urllib.request

# %% Step 2: Get training data — REAL PYTHON CODE
# Instead of Shakespeare, we'll train on Python code.
# This is a small collection of Python snippets with common patterns
# including some with security issues (your future training data!)

code_samples = '''
import sqlite3
def login(username, password):
    conn = sqlite3.connect("users.db")
    query = f"SELECT * FROM users WHERE name='{username}' AND pass='{password}'"
    result = conn.execute(query).fetchone()
    conn.close()
    return result

import sqlite3
def safe_login(username, password):
    conn = sqlite3.connect("users.db")
    query = "SELECT * FROM users WHERE name=? AND pass=?"
    result = conn.execute(query, (username, password)).fetchone()
    conn.close()
    return result

from flask import Flask, request, render_template_string
app = Flask(__name__)

@app.route("/greet")
def greet():
    name = request.args.get("name", "")
    return render_template_string(f"<h1>Hello {name}</h1>")

@app.route("/safe_greet")
def safe_greet():
    name = request.args.get("name", "")
    return render_template_string("<h1>Hello {{ name }}</h1>", name=name)

import os
def read_file(filename):
    path = "/var/data/" + filename
    with open(path, "r") as f:
        return f.read()

def safe_read_file(filename):
    base = "/var/data/"
    path = os.path.normpath(os.path.join(base, filename))
    if not path.startswith(base):
        raise ValueError("Path traversal detected")
    with open(path, "r") as f:
        return f.read()

import hashlib
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

import bcrypt
def safe_hash_password(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt)

API_KEY = "sk-1234567890abcdef"
DATABASE_URL = "postgresql://admin:password123@localhost/mydb"

import os
api_key = os.environ.get("API_KEY")
database_url = os.environ.get("DATABASE_URL")

import subprocess
def run_command(user_input):
    result = subprocess.run(user_input, shell=True, capture_output=True)
    return result.stdout.decode()

import subprocess
import shlex
def safe_run_command(user_input):
    args = shlex.split(user_input)
    allowed = ["ls", "cat", "echo"]
    if args[0] not in allowed:
        raise ValueError("Command not allowed")
    result = subprocess.run(args, capture_output=True)
    return result.stdout.decode()

import pickle
def load_data(data_bytes):
    return pickle.loads(data_bytes)

import json
def safe_load_data(data_string):
    return json.loads(data_string)

def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " + str(user_id)
    return db.execute(query)

def safe_get_user(user_id):
    query = "SELECT * FROM users WHERE id = %s"
    return db.execute(query, (user_id,))

from flask import Flask, request, jsonify
import jwt

app = Flask(__name__)
SECRET = "mysecretkey123"

@app.route("/admin")
def admin():
    token = request.headers.get("Authorization")
    try:
        payload = jwt.decode(token, SECRET, algorithms=["HS256"])
        if payload.get("role") == "admin":
            return jsonify({"data": "secret admin data"})
    except jwt.InvalidTokenError:
        pass
    return jsonify({"error": "unauthorized"}), 401

class UserService:
    def __init__(self, db_connection):
        self.db = db_connection
        self.cache = {}

    def get_user(self, user_id):
        if user_id in self.cache:
            return self.cache[user_id]
        user = self.db.find_one({"id": user_id})
        self.cache[user_id] = user
        return user

    def create_user(self, username, email, password):
        hashed = safe_hash_password(password)
        user = {
            "username": username,
            "email": email,
            "password": hashed,
        }
        self.db.insert_one(user)
        return user

    def delete_user(self, user_id):
        self.db.delete_one({"id": user_id})
        if user_id in self.cache:
            del self.cache[user_id]

def validate_email(email):
    if "@" not in email:
        return False
    parts = email.split("@")
    if len(parts) != 2:
        return False
    domain = parts[1]
    if "." not in domain:
        return False
    return True

def process_payment(amount, card_number, cvv):
    print(f"Processing payment: card={card_number}, cvv={cvv}")
    return {"status": "success", "amount": amount}

def safe_process_payment(amount, card_token):
    return {"status": "success", "amount": amount, "token": card_token}

import logging
logger = logging.getLogger(__name__)

def transfer_funds(from_account, to_account, amount):
    if amount <= 0:
        raise ValueError("Amount must be positive")
    balance = get_balance(from_account)
    if balance < amount:
        raise ValueError("Insufficient funds")
    debit(from_account, amount)
    credit(to_account, amount)
    logger.info(f"Transferred {amount} from {from_account} to {to_account}")
    return True

class RateLimiter:
    def __init__(self, max_requests, window_seconds):
        self.max_requests = max_requests
        self.window = window_seconds
        self.requests = {}

    def is_allowed(self, client_ip):
        import time
        now = time.time()
        if client_ip not in self.requests:
            self.requests[client_ip] = []
        self.requests[client_ip] = [
            t for t in self.requests[client_ip]
            if now - t < self.window
        ]
        if len(self.requests[client_ip]) >= self.max_requests:
            return False
        self.requests[client_ip].append(now)
        return True

import re
def sanitize_html(text):
    text = re.sub(r"<script.*?>.*?</script>", "", text, flags=re.DOTALL)
    text = re.sub(r"on\w+\s*=", "", text)
    return text

def check_password_strength(password):
    if len(password) < 8:
        return "weak"
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in "!@#$%^&*" for c in password)
    score = sum([has_upper, has_lower, has_digit, has_special])
    if score >= 4:
        return "strong"
    elif score >= 2:
        return "medium"
    return "weak"

from cryptography.fernet import Fernet

def encrypt_data(data, key):
    f = Fernet(key)
    return f.encrypt(data.encode())

def decrypt_data(encrypted_data, key):
    f = Fernet(key)
    return f.decrypt(encrypted_data).decode()
'''

# Repeat the samples to give us more training data
# (In a real project you'd have thousands of files)
text = code_samples * 20
print(f"Training data: {len(text)} characters")

# %% Step 3: Build the tokenizer (character-level, same as before)
# NOTE: For a real security scanner, you'd use BPE (subword tokens)
# Character-level is fine for learning the architecture
chars = sorted(list(set(text)))
vocab_size = len(chars)
print(f"Vocab size: {vocab_size}")
print(f"Characters: {''.join(chars)}")

stoi = {ch: i for i, ch in enumerate(chars)}
itos = {i: ch for i, ch in enumerate(chars)}
encode = lambda s: [stoi[c] for c in s]
decode = lambda l: ''.join([itos[i] for i in l])

# Quick test
print(f"\nEncoded 'def ': {encode('def ')}")
print(f"Decoded back: '{decode(encode('def '))}'")

# %% Step 4: Train/val split
data = torch.tensor(encode(text), dtype=torch.long)
n = int(0.9 * len(data))
train_data = data[:n]
val_data = data[n:]
print(f"Train: {len(train_data)} tokens, Val: {len(val_data)} tokens")

# %% Step 5: Hyperparameters
# ============================================================
# EXERCISE: Try changing these and see what happens to the loss
# Start with these defaults, then experiment:
#   - What happens if you double n_embd?
#   - What if you use 1 head vs 4 heads?
#   - What if you use 1 layer vs 6 layers?
# ============================================================
batch_size = 32
block_size = 64       # longer context than Shakespeare (code needs more context)
max_iters = 5000
eval_interval = 500
learning_rate = 3e-4
device = 'cuda' if torch.cuda.is_available() else 'cpu'
eval_iters = 100
n_embd = 128          # embedding dimension
n_head = 4            # number of attention heads
n_layer = 4           # number of transformer blocks
dropout = 0.1         # dropout rate (prevents overfitting)
print(f"Device: {device}")

# %% Step 6: Data loader
def get_batch(split):
    data_source = train_data if split == 'train' else val_data
    ix = torch.randint(len(data_source) - block_size, (batch_size,))
    x = torch.stack([data_source[i:i+block_size] for i in ix])
    y = torch.stack([data_source[i+1:i+block_size+1] for i in ix])
    x, y = x.to(device), y.to(device)
    return x, y

# %% Step 7: Loss estimator
@torch.no_grad()
def estimate_loss():
    out = {}
    model.eval()
    for split in ['train', 'val']:
        losses = torch.zeros(eval_iters)
        for k in range(eval_iters):
            X, Y = get_batch(split)
            logits, loss = model(X, Y)
            losses[k] = loss.item()
        out[split] = losses.mean()
    model.train()
    return out

# %% Step 8: Attention Head
# ============================================================
# EXERCISE: Before reading, try writing this from memory.
# You already wrote it once! Then compare with this version.
# New addition: dropout (randomly zeros out attention weights
# during training to prevent overfitting)
# ============================================================
class Head(nn.Module):
    """One head of self-attention"""

    def __init__(self, head_size):
        super().__init__()
        self.key = nn.Linear(n_embd, head_size, bias=False)
        self.query = nn.Linear(n_embd, head_size, bias=False)
        self.value = nn.Linear(n_embd, head_size, bias=False)
        self.register_buffer('tril', torch.tril(torch.ones(block_size, block_size)))
        self.dropout = nn.Dropout(dropout)

    def forward(self, x):
        B, T, C = x.shape
        k = self.key(x)                                    # (B, T, head_size)
        q = self.query(x)                                  # (B, T, head_size)
        # Compute attention scores
        wei = q @ k.transpose(-2, -1) * C**-0.5            # (B, T, T)
        wei = wei.masked_fill(self.tril[:T, :T] == 0, float('-inf'))
        wei = F.softmax(wei, dim=-1)                        # (B, T, T)
        wei = self.dropout(wei)                             # randomly zero some connections
        # Weighted sum of values
        v = self.value(x)                                   # (B, T, head_size)
        out = wei @ v                                       # (B, T, head_size)
        return out

# %% Step 9: Multi-Head Attention
class MultiHeadAttention(nn.Module):
    """Multiple heads running in parallel, then combined"""

    def __init__(self, num_heads, head_size):
        super().__init__()
        self.heads = nn.ModuleList([Head(head_size) for _ in range(num_heads)])
        self.proj = nn.Linear(n_embd, n_embd)     # project back to n_embd
        self.dropout = nn.Dropout(dropout)

    def forward(self, x):
        # Run all heads, concatenate results
        out = torch.cat([h(x) for h in self.heads], dim=-1)  # (B, T, n_embd)
        out = self.dropout(self.proj(out))
        return out

# %% Step 10: FeedForward
class FeedForward(nn.Module):
    """The 'thinking' layer: expand, activate, shrink"""

    def __init__(self, n_embd):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(n_embd, 4 * n_embd),   # expand
            nn.ReLU(),                         # activate
            nn.Linear(4 * n_embd, n_embd),    # shrink back
            nn.Dropout(dropout),
        )

    def forward(self, x):
        return self.net(x)

# %% Step 11: Block (Attention + FeedForward + LayerNorm + Residual)
class Block(nn.Module):
    """One transformer block: look (attention) then think (feedforward)"""

    def __init__(self, n_embd, n_head):
        super().__init__()
        head_size = n_embd // n_head                       # 128 // 4 = 32
        self.sa = MultiHeadAttention(n_head, head_size)    # self-attention
        self.ffwd = FeedForward(n_embd)                    # feedforward
        self.ln1 = nn.LayerNorm(n_embd)                    # normalize before attention
        self.ln2 = nn.LayerNorm(n_embd)                    # normalize before feedforward

    def forward(self, x):
        x = x + self.sa(self.ln1(x))      # attend + residual connection
        x = x + self.ffwd(self.ln2(x))    # think + residual connection
        return x

# %% Step 12: The Complete GPT Model
# ============================================================
# This is YOUR ARCHITECTURE for the security scanner.
# Same structure, just trained on different data later.
# ============================================================
class CodeGPT(nn.Module):

    def __init__(self):
        super().__init__()
        # Embeddings — "what token" + "where in sequence"
        self.token_embedding = nn.Embedding(vocab_size, n_embd)
        self.position_embedding = nn.Embedding(block_size, n_embd)
        # Transformer blocks — the thinking layers
        self.blocks = nn.Sequential(*[Block(n_embd, n_head) for _ in range(n_layer)])
        # Final normalization
        self.ln_f = nn.LayerNorm(n_embd)
        # Output head — back to vocabulary predictions
        self.lm_head = nn.Linear(n_embd, vocab_size)

    def forward(self, idx, targets=None):
        B, T = idx.shape

        # Token embedding + position embedding
        tok_emb = self.token_embedding(idx)                          # (B, T, n_embd)
        pos_emb = self.position_embedding(torch.arange(T, device=device))  # (T, n_embd)
        x = tok_emb + pos_emb                                        # (B, T, n_embd)

        # Pass through all transformer blocks
        x = self.blocks(x)                                            # (B, T, n_embd)

        # Final LayerNorm
        x = self.ln_f(x)                                             # (B, T, n_embd)

        # Project to vocabulary
        logits = self.lm_head(x)                                     # (B, T, vocab_size)

        if targets is None:
            loss = None
        else:
            B, T, C = logits.shape
            logits = logits.view(B*T, C)
            targets = targets.view(B*T)
            loss = F.cross_entropy(logits, targets)

        return logits, loss

    def generate(self, idx, max_new_tokens):
        for _ in range(max_new_tokens):
            # Crop to block_size (position embedding limit)
            idx_cond = idx[:, -block_size:]
            # Forward pass
            logits, loss = self(idx_cond)
            # Get prediction at last position
            logits = logits[:, -1, :]                                 # (B, vocab_size)
            # Convert to probabilities
            probs = F.softmax(logits, dim=-1)
            # Sample next token
            idx_next = torch.multinomial(probs, num_samples=1)
            # Append to sequence
            idx = torch.cat((idx, idx_next), dim=1)
        return idx

# %% Step 13: Create model and count parameters
model = CodeGPT().to(device)
param_count = sum(p.numel() for p in model.parameters())
print(f"Model parameters: {param_count:,}")
print(f"That's {param_count/1e6:.2f}M parameters")

# Sanity check: initial loss should be ~ln(vocab_size)
xb, yb = get_batch('train')
logits, loss = model(xb, yb)
import math
expected = math.log(vocab_size)
print(f"\nInitial loss: {loss.item():.4f}")
print(f"Expected (random): {expected:.4f}")
print(f"{'✓ Looks correct!' if abs(loss.item() - expected) < 0.5 else '✗ Something might be wrong'}")

# %% Step 14: Train!
# ============================================================
# WATCH THE LOSS DROP
# It should go from ~4.x down to ~1.x
# Lower loss = better at predicting the next character in code
# ============================================================
optimizer = torch.optim.AdamW(model.parameters(), lr=learning_rate)

print("Training started...")
for iter in range(max_iters):
    if iter % eval_interval == 0 or iter == max_iters - 1:
        losses = estimate_loss()
        print(f"Step {iter:5d}: train loss {losses['train']:.4f}, val loss {losses['val']:.4f}")

    xb, yb = get_batch('train')
    logits, loss = model(xb, yb)
    optimizer.zero_grad(set_to_none=True)
    loss.backward()
    optimizer.step()

print("\nTraining complete!")

# %% Step 15: Generate code!
# ============================================================
# The model will try to autocomplete Python code.
# It won't be perfect (small model, character-level) but you
# should see recognizable Python patterns.
# ============================================================
print("=" * 60)
print("GENERATED CODE (from scratch, starting with empty input):")
print("=" * 60)
start = torch.zeros((1, 1), dtype=torch.long, device=device)
generated = model.generate(start, max_new_tokens=500)
print(decode(generated[0].tolist()))

# %% Step 16: Generate code from a prompt
# ============================================================
# Give the model a starting prompt and let it continue.
# Try different prompts to see what patterns it learned!
# ============================================================
def generate_from(prompt, max_tokens=300):
    """Give the model a starting prompt, let it continue"""
    context = torch.tensor([encode(prompt)], dtype=torch.long, device=device)
    generated = model.generate(context, max_new_tokens=max_tokens)
    return decode(generated[0].tolist())

print("=" * 60)
print('PROMPT: "def login("')
print("=" * 60)
print(generate_from("def login("))

print("\n" + "=" * 60)
print('PROMPT: "import "')
print("=" * 60)
print(generate_from("import "))

print("\n" + "=" * 60)
print('PROMPT: "class "')
print("=" * 60)
print(generate_from("class "))

print("\n" + "=" * 60)
print('PROMPT: "def safe_"')
print("=" * 60)
print(generate_from("def safe_"))

# %% Step 17: Experiments to try
# ============================================================
# NOW IT'S YOUR TURN. Try these experiments:
#
# EXPERIMENT 1: Change the training data
#   - What if you add more vulnerable code examples?
#   - What if you only train on safe code?
#   - Does the model generate different patterns?
#
# EXPERIMENT 2: Change the architecture
#   - Go back to Step 5 and try:
#     n_head = 1   (single attention head)
#     n_head = 8   (more attention heads, reduce n_embd to match)
#     n_layer = 1  (shallow) vs n_layer = 8 (deep)
#   - How does the loss change? How does generation quality change?
#
# EXPERIMENT 3: Temperature
#   - Add a temperature parameter to generation:
#
#     def generate_with_temp(self, idx, max_new_tokens, temperature=1.0):
#         for _ in range(max_new_tokens):
#             idx_cond = idx[:, -block_size:]
#             logits, loss = self(idx_cond)
#             logits = logits[:, -1, :] / temperature  # <-- divide by temperature
#             probs = F.softmax(logits, dim=-1)
#             idx_next = torch.multinomial(probs, num_samples=1)
#             idx = torch.cat((idx, idx_next), dim=1)
#         return idx
#
#   - temperature < 1.0 = more confident (picks likely tokens)
#   - temperature > 1.0 = more random (explores unlikely tokens)
#   - temperature = 0.0001 ≈ always picks the most likely token
#   - Try 0.5, 1.0, 1.5 and compare outputs
#
# EXPERIMENT 4: Block size
#   - block_size = 16  (very short context)
#   - block_size = 128 (longer context)
#   - How does context length affect code generation?
#   - For security scanning, you need LONG context — why?
#
# EXPERIMENT 5: Toward security scanning
#   - After training, try these prompts:
#     generate_from("query = f\"SELECT")
#     generate_from("subprocess.run(user_input")
#     generate_from("password = \"")
#   - Does the model generate vulnerable or safe patterns?
#   - This is the raw foundation of your scanner:
#     a model that knows what typically comes after risky code patterns
#
# ============================================================
# 
# NEXT STEPS (after finishing these experiments):
# 1. Move to nanochat — clone it, read gpt.py, run runcpu.sh
# 2. Study the SFT pipeline (scripts/chat_sft.py)
# 3. Build your vulnerability training dataset (Phase 3 of roadmap)
# 4. Fine-tune on vulnerability data
# ============================================================
