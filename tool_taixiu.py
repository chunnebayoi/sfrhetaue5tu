import streamlit as st
import hashlib
import random
import string
from collections import deque, Counter

st.set_page_config(page_title="Tool Dự Đoán Tài Xỉu", layout="wide")
st.markdown("""
    <style>
    .main-title {
        font-size: 2.5em;
        text-align: center;
        font-weight: bold;
        margin-bottom: 1em;
    }
    .card {
        background-color: #f9f9f9;
        padding: 1.5em;
        border-radius: 20px;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
        margin-bottom: 2em;
    }
    .highlight {
        font-size: 1.3em;
        font-weight: bold;
        color: #0072C6;
    }
    </style>
""", unsafe_allow_html=True)

st.markdown('<div class="main-title">🎲 Dự Đoán Tài Xỉu & Phân Tích Cầu SUNWIN</div>', unsafe_allow_html=True)

def generate_random_key():
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))

if 'db' not in st.session_state:
    sample_users = {
        f"user{i+1}": {
            "password": f"pass{i+1}",
            "role": "user",
            "active_key": generate_random_key()
        }
        for i in range(20)
    }
    st.session_state.sample_user_list = [f"{u} / {v['password']} / {v['active_key']}" for u, v in sample_users.items()]
    st.session_state.db = {
        'users': {
            'admin': {'password': 'admin123', 'role': 'admin', 'active_key': None},
            'giangson2102': {'password': 'son2102', 'role': 'admin', 'active_key': None},
            **sample_users
        },
        'used_keys': set([user['active_key'] for user in sample_users.values()]),
        'recent_results': deque(maxlen=10),
        'logged_in': False,
        'username': None,
        'role': None,
        'pending_users': set()
    }

db = st.session_state.db

def complex_calculation(input_str: str) -> float:
    md5_hash = int(hashlib.md5(input_str.encode()).hexdigest(), 16)
    sha256_hash = int(hashlib.sha256(input_str.encode()).hexdigest(), 16)
    blake2b_hash = int(hashlib.blake2b(input_str.encode()).hexdigest(), 16)
    combined_hash = (md5_hash % 100) * 0.3 + (sha256_hash % 100) * 0.4 + (blake2b_hash % 100) * 0.3
    return combined_hash % 100

def bayesian_adjustment(recent_results: deque) -> float:
    count = Counter(recent_results)
    total = len(recent_results)
    if total == 0:
        return 50.0
    prob_xiu = (count["Xỉu"] + 1) / (total + 2)
    return prob_xiu * 100

def detect_trend(recent_results: deque) -> str:
    if len(recent_results) < 4:
        return "Không đủ dữ liệu phân tích cầu."
    trend_str = ''.join(['T' if res == "Tài" else 'X' for res in recent_results])
    patterns = {
        "TTTT": "Cầu bệt Tài",
        "XXXX": "Cầu bệt Xỉu",
        "TXTX": "Cầu 1-1",
        "TXT": "Cầu 1-2-1",
        "TTTX": "Cầu bệt ngắt (Tài ngắt)",
        "XXXT": "Cầu bệt ngắt (Xỉu ngắt)",
        "TXXT": "Cầu 2-1-2",
        "XXTXX": "Cầu 3-2",
    }
    for pattern, label in patterns.items():
        if trend_str.endswith(pattern):
            return label
    if "TTT" in trend_str[-5:] and trend_str[-1] == "X":
        return "Cầu bẻ từ Tài sang Xỉu"
    elif "XXX" in trend_str[-5:] and trend_str[-1] == "T":
        return "Cầu bẻ từ Xỉu sang Tài"
    return "Cầu không xác định"

def adjust_prediction(percentage: float, trend: str) -> float:
    adjustments = {
        "Cầu bệt Tài": -7,
        "Cầu bệt Xỉu": +7,
        "Cầu 1-1": 5 if percentage > 50 else -5,
        "Cầu 1-2-1": 3,
        "Cầu bệt ngắt (Tài ngắt)": 2,
        "Cầu bệt ngắt (Xỉu ngắt)": 2,
        "Cầu 2-1-2": -4,
        "Cầu 3-2": 6,
        "Cầu bẻ từ Tài sang Xỉu": 10,
        "Cầu bẻ từ Xỉu sang Tài": -10,
    }
    return max(0, min(100, percentage + adjustments.get(trend, 0)))

menu = st.sidebar.selectbox("🔐 Chọn chức năng:", ["Phân tích", "Đăng nhập", "Đăng ký", "👑 Quản lý Key (Admin)"])

# (Phần xử lý từng menu sẽ tiếp tục được thêm bên dưới)
