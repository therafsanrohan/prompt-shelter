"""Prompt Shelter — Pixel-Perfect Light Theme Enterprise Security Platform.

Matches the reference modern SaaS dashboard (Stripe / Linear / Vercel / shadcn):
- Crisp White Sidebar with clean light gray borders, soft gray hover, and subtle active states
- Top Header matching Dashboard > Analytics breadcrumb, calendar range, and Export CSV
- Seamless light surface cards, pills, charts, and tables
- Zero emojis, clean SVG Lucide icons
"""

from __future__ import annotations

import sqlite3
from collections import Counter
from datetime import datetime
from html import escape
from pathlib import Path

import pandas as pd
import streamlit as st

from detection import RULES, analyze_prompt
from storage import DB_PATH, clear_scans, get_scans, save_scan

st.set_page_config(
    page_title="Prompt Shelter | Enterprise Security",
    layout="wide",
    initial_sidebar_state="expanded",
)

NAV_PAGES = [
    "Overview",
    "Prompt Scanner",
    "Detection Rules",
    "Scan History",
    "Analytics",
    "Research Notes",
]

CLASSIFICATIONS = ["SAFE", "SUSPICIOUS", "MALICIOUS"]

# Pure SVG Lucide-style line icons
ICONS = {
    "shield": '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/></svg>',
    "calendar": '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="18" height="18" x="3" y="4" rx="2" ry="2"/><line x1="16" x2="16" y1="2" y2="6"/><line x1="8" x2="8" y1="2" y2="6"/><line x1="3" x2="21" y1="10" y2="10"/></svg>',
    "download": '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" x2="12" y1="15" y2="3"/></svg>',
    "chevron-down": '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 12 15 18 9"/></svg>',
    "trending-up": '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 6 13.5 15.5 8.5 10.5 1 18"/><polyline points="17 6 23 6 23 12"/></svg>',
    "dollar-sign": '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="12" x2="12" y1="2" y2="22"/><path d="M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"/></svg>',
    "users": '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>',
    "credit-card": '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="20" height="14" x="2" y="5" rx="2"/><line x1="2" x2="22" y1="10" y2="10"/></svg>',
    "activity": '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>',
    "check-circle": '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#16A34A" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>',
    "alert-triangle": '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" x2="12" y1="9" y2="13"/><line x1="12" x2="12.01" y1="17" y2="17"/></svg>',
    "alert-octagon": '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2"/><line x1="12" x2="12" y1="8" y2="12"/><line x1="12" x2="12.01" y1="16" y2="16"/></svg>',
    "layout-dashboard": '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="7" height="9" x="3" y="3" rx="1"/><rect width="7" height="5" x="14" y="3" rx="1"/><rect width="7" height="9" x="14" y="12" rx="1"/><rect width="7" height="5" x="3" y="16" rx="1"/></svg>',
    "scan": '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 7V5a2 2 0 0 1 2-2h2"/><path d="M17 3h2a2 2 0 0 1 2 2v2"/><path d="M21 17v2a2 2 0 0 1-2 2h-2"/><path d="M7 21H5a2 2 0 0 1-2-2v-2"/><circle cx="12" cy="12" r="3"/></svg>',
    "list-checks": '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m3 17 2 2 4-4"/><path d="m3 7 2 2 4-4"/><path d="M13 6h8"/><path d="M13 12h8"/><path d="M13 18h8"/></svg>',
    "history": '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/><path d="M12 7v5l4 2"/></svg>',
    "bar-chart-2": '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" x2="18" y1="20" y2="10"/><line x1="12" x2="12" y1="20" y2="4"/><line x1="6" x2="6" y1="20" y2="14"/></svg>',
    "book-open": '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 3h6a4 4 0 0 1 4 4v14a3 3 0 0 0-3-3H2z"/><path d="M22 3h-6a4 4 0 0 0-4 4v14a3 3 0 0 1 3-3h7z"/></svg>',
}

st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');

    :root {
        --bg-app: #FAFAFA;
        --surface-white: #FFFFFF;
        --border-default: #E5E7EB;
        --border-subtle: #F3F4F6;
        --text-dark: #111827;
        --text-secondary: #4B5563;
        --text-muted: #6B7280;
        --primary-blue: #2563EB;
        --green-pill-bg: #DCFCE7;
        --green-pill-text: #15803D;
        --amber-pill-bg: #FEF3C7;
        --amber-pill-text: #B45309;
        --red-pill-bg: #FEE2E2;
        --red-pill-text: #B91C1C;
    }

    html, body, [class*="css"], [data-testid="stAppViewContainer"] {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif !important;
        background-color: var(--bg-app) !important;
        color: var(--text-dark) !important;
    }

    .stApp {
        background-color: var(--bg-app) !important;
    }

    /* Crisp Light-Theme Sidebar matching the clean aesthetic */
    [data-testid="stSidebar"] {
        background-color: #FFFFFF !important;
        border-right: 1px solid var(--border-default) !important;
        box-shadow: none !important;
    }
    [data-testid="stSidebar"] > div:first-child {
        padding: 1.25rem 1rem !important;
    }
    [data-testid="stSidebar"] hr {
        border-color: var(--border-subtle) !important;
        margin: 14px 0 !important;
    }

    /* Light Theme Nav Radio Items */
    [data-testid="stSidebar"] [data-testid="stRadio"] div[role="radiogroup"] {
        gap: 4px !important;
    }
    [data-testid="stSidebar"] [data-testid="stRadioOption"] {
        position: relative !important;
        background-color: transparent !important;
        color: #475569 !important;
        border-radius: 8px !important;
        padding: 9px 12px 9px 42px !important;
        font-size: 13.5px !important;
        font-weight: 500 !important;
        transition: all 0.15s ease !important;
        border: 1px solid transparent !important;
        margin: 0 !important;
        cursor: pointer !important;
        width: 100% !important;
    }
    [data-testid="stSidebar"] [data-testid="stRadioOption"]::before {
        content: "";
        position: absolute;
        left: 14px;
        top: 50%;
        transform: translateY(-50%);
        width: 18px;
        height: 18px;
        background-repeat: no-repeat;
        background-size: contain;
        opacity: 0.85;
        transition: all 0.15s ease;
    }
    [data-testid="stSidebar"] [data-testid="stRadioOption"]:hover::before,
    [data-testid="stSidebar"] [data-testid="stRadioOption"][data-selected="true"]::before {
        opacity: 1;
    }

    /* 1. Overview: Dashboard icon */
    [data-testid="stSidebar"] div[role="radiogroup"] > div:nth-child(1) [data-testid="stRadioOption"]::before {
        background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='24' height='24' viewBox='0 0 24 24' fill='none' stroke='%23475569' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Crect width='7' height='9' x='3' y='3' rx='1'/%3E%3Crect width='7' height='5' x='14' y='3' rx='1'/%3E%3Crect width='7' height='9' x='14' y='12' rx='1'/%3E%3Crect width='7' height='5' x='3' y='16' rx='1'/%3E%3C/svg%3E");
    }
    [data-testid="stSidebar"] div[role="radiogroup"] > div:nth-child(1) [data-testid="stRadioOption"][data-selected="true"]::before {
        background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='24' height='24' viewBox='0 0 24 24' fill='none' stroke='%232563EB' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Crect width='7' height='9' x='3' y='3' rx='1'/%3E%3Crect width='7' height='5' x='14' y='3' rx='1'/%3E%3Crect width='7' height='9' x='14' y='12' rx='1'/%3E%3Crect width='7' height='5' x='3' y='16' rx='1'/%3E%3C/svg%3E");
    }

    /* 2. Prompt Scanner: Target/Crosshair icon */
    [data-testid="stSidebar"] div[role="radiogroup"] > div:nth-child(2) [data-testid="stRadioOption"]::before {
        background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='24' height='24' viewBox='0 0 24 24' fill='none' stroke='%23475569' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M3 7V5a2 2 0 0 1 2-2h2'/%3E%3Cpath d='M17 3h2a2 2 0 0 1 2 2v2'/%3E%3Cpath d='M21 17v2a2 2 0 0 1-2 2h-2'/%3E%3Cpath d='M7 21H5a2 2 0 0 1-2-2v-2'/%3E%3Ccircle cx='12' cy='12' r='3'/%3E%3C/svg%3E");
    }
    [data-testid="stSidebar"] div[role="radiogroup"] > div:nth-child(2) [data-testid="stRadioOption"][data-selected="true"]::before {
        background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='24' height='24' viewBox='0 0 24 24' fill='none' stroke='%232563EB' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M3 7V5a2 2 0 0 1 2-2h2'/%3E%3Cpath d='M17 3h2a2 2 0 0 1 2 2v2'/%3E%3Cpath d='M21 17v2a2 2 0 0 1-2 2h-2'/%3E%3Cpath d='M7 21H5a2 2 0 0 1-2-2v-2'/%3E%3Ccircle cx='12' cy='12' r='3'/%3E%3C/svg%3E");
    }

    /* 3. Detection Rules: Shield/Checklist icon */
    [data-testid="stSidebar"] div[role="radiogroup"] > div:nth-child(3) [data-testid="stRadioOption"]::before {
        background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='24' height='24' viewBox='0 0 24 24' fill='none' stroke='%23475569' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='m3 17 2 2 4-4'/%3E%3Cpath d='m3 7 2 2 4-4'/%3E%3Cpath d='M13 6h8'/%3E%3Cpath d='M13 12h8'/%3E%3Cpath d='M13 18h8'/%3E%3C/svg%3E");
    }
    [data-testid="stSidebar"] div[role="radiogroup"] > div:nth-child(3) [data-testid="stRadioOption"][data-selected="true"]::before {
        background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='24' height='24' viewBox='0 0 24 24' fill='none' stroke='%232563EB' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='m3 17 2 2 4-4'/%3E%3Cpath d='m3 7 2 2 4-4'/%3E%3Cpath d='M13 6h8'/%3E%3Cpath d='M13 12h8'/%3E%3Cpath d='M13 18h8'/%3E%3C/svg%3E");
    }

    /* 4. Scan History: History/Clock icon */
    [data-testid="stSidebar"] div[role="radiogroup"] > div:nth-child(4) [data-testid="stRadioOption"]::before {
        background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='24' height='24' viewBox='0 0 24 24' fill='none' stroke='%23475569' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8'/%3E%3Cpath d='M3 3v5h5'/%3E%3Cpath d='M12 7v5l4 2'/%3E%3C/svg%3E");
    }
    [data-testid="stSidebar"] div[role="radiogroup"] > div:nth-child(4) [data-testid="stRadioOption"][data-selected="true"]::before {
        background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='24' height='24' viewBox='0 0 24 24' fill='none' stroke='%232563EB' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8'/%3E%3Cpath d='M3 3v5h5'/%3E%3Cpath d='M12 7v5l4 2'/%3E%3C/svg%3E");
    }

    /* 5. Analytics: Bar chart icon */
    [data-testid="stSidebar"] div[role="radiogroup"] > div:nth-child(5) [data-testid="stRadioOption"]::before {
        background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='24' height='24' viewBox='0 0 24 24' fill='none' stroke='%23475569' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cline x1='18' x2='18' y1='20' y2='10'/%3E%3Cline x1='12' x2='12' y1='20' y2='4'/%3E%3Cline x1='6' x2='6' y1='20' y2='14'/%3E%3C/svg%3E");
    }
    [data-testid="stSidebar"] div[role="radiogroup"] > div:nth-child(5) [data-testid="stRadioOption"][data-selected="true"]::before {
        background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='24' height='24' viewBox='0 0 24 24' fill='none' stroke='%232563EB' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cline x1='18' x2='18' y1='20' y2='10'/%3E%3Cline x1='12' x2='12' y1='20' y2='4'/%3E%3Cline x1='6' x2='6' y1='20' y2='14'/%3E%3C/svg%3E");
    }

    /* 6. Research Notes: Book icon */
    [data-testid="stSidebar"] div[role="radiogroup"] > div:nth-child(6) [data-testid="stRadioOption"]::before {
        background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='24' height='24' viewBox='0 0 24 24' fill='none' stroke='%23475569' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M2 3h6a4 4 0 0 1 4 4v14a3 3 0 0 0-3-3H2z'/%3E%3Cpath d='M22 3h-6a4 4 0 0 0-4 4v14a3 3 0 0 1 3-3h7z'/%3E%3C/svg%3E");
    }
    [data-testid="stSidebar"] div[role="radiogroup"] > div:nth-child(6) [data-testid="stRadioOption"][data-selected="true"]::before {
        background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='24' height='24' viewBox='0 0 24 24' fill='none' stroke='%232563EB' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M2 3h6a4 4 0 0 1 4 4v14a3 3 0 0 0-3-3H2z'/%3E%3Cpath d='M22 3h-6a4 4 0 0 0-4 4v14a3 3 0 0 1 3-3h7z'/%3E%3C/svg%3E");
    }

    [data-testid="stSidebar"] [data-testid="stRadioOption"]:hover {
        background-color: #F8FAFC !important;
        color: #0F172A !important;
        border-color: #F1F5F9 !important;
    }
    [data-testid="stSidebar"] [data-testid="stRadioOption"][data-selected="true"],
    [data-testid="stSidebar"] [data-testid="stRadioOption"]:has(input:checked) {
        background-color: #EFF6FF !important;
        color: #1D4ED8 !important;
        font-weight: 600 !important;
        border: 1px solid #BFDBFE !important;
    }
    [data-testid="stSidebar"] [data-testid="stRadioOption"][data-selected="true"] p,
    [data-testid="stSidebar"] [data-testid="stRadioOption"]:has(input:checked) p {
        color: #1D4ED8 !important;
        font-weight: 600 !important;
    }
    [data-testid="stSidebar"] [data-testid="stRadioOption"] p {
        color: #475569 !important;
        font-size: 13.5px !important;
        font-weight: 500 !important;
        margin: 0 !important;
    }
    /* Hide circular radio input dot */
    [data-testid="stSidebar"] [data-testid="stRadioOption"] div:has(> div[class*="ex50key5"]),
    [data-testid="stSidebar"] [data-testid="stRadioOption"] div[class*="ex50key4"] {
        display: none !important;
    }
    [data-testid="stSidebar"] [data-testid="stRadioOption"] > div {
        gap: 0px !important;
    }
    [data-testid="stSidebar"] [data-testid="stRadio"] input {
        display: none !important;
    }

    /* Content Area */
    .block-container {
        max-width: 1220px !important;
        padding: 1.8rem 2.5rem 3.5rem !important;
    }

    @media (max-width: 768px) {
        .block-container {
            padding: 1rem 1rem 2rem !important;
        }
        .header-row {
            flex-direction: column !important;
            align-items: flex-start !important;
            gap: 12px !important;
        }
    }

    /* Top Breadcrumb & Actions Bar */
    .header-breadcrumb {
        font-size: 13px;
        color: #6B7280;
        display: flex;
        align-items: center;
        gap: 6px;
        margin-bottom: 4px;
    }
    .header-breadcrumb-active {
        color: #111827;
        font-weight: 500;
    }
    .header-row {
        display: flex;
        align-items: center;
        justify-content: space-between;
        margin-bottom: 20px;
    }
    .header-title {
        font-size: 26px;
        font-weight: 700;
        color: #111827;
        margin: 0;
        letter-spacing: -0.03em;
    }
    .header-buttons {
        display: flex;
        align-items: center;
        gap: 8px;
    }
    .header-btn {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        background: #FFFFFF;
        border: 1px solid #E5E7EB;
        border-radius: 8px;
        padding: 6px 12px;
        font-size: 13px;
        font-weight: 500;
        color: #374151;
        cursor: pointer;
        box-shadow: 0 1px 2px rgba(0,0,0,0.03);
    }
    .header-btn:hover {
        background: #F9FAFB;
        border-color: #D1D5DB;
    }

    /* Status Banner */
    .alert-banner {
        background: #FFFFFF;
        border: 1px solid #E5E7EB;
        border-radius: 12px;
        padding: 14px 18px;
        display: flex;
        align-items: flex-start;
        gap: 12px;
        margin-bottom: 20px;
        box-shadow: 0 1px 2px rgba(0,0,0,0.02);
    }
    .alert-banner-title {
        font-size: 14px;
        font-weight: 600;
        color: #111827;
        margin-bottom: 2px;
    }
    .alert-banner-desc {
        font-size: 13px;
        color: #6B7280;
        line-height: 1.45;
    }

    /* 4-Stat Metric Cards */
    .metric-box {
        background: #FFFFFF;
        border: 1px solid #E5E7EB;
        border-radius: 12px;
        padding: 18px 20px;
        min-height: 112px;
        display: flex;
        flex-direction: column;
        justify-content: space-between;
        box-shadow: 0 1px 2px rgba(0,0,0,0.02);
        margin-bottom: 12px;
    }
    .metric-box-top {
        display: flex;
        align-items: center;
        justify-content: space-between;
        font-size: 13px;
        font-weight: 500;
        color: #4B5563;
    }
    .metric-box-icon {
        color: #9CA3AF;
        display: flex;
        align-items: center;
    }
    .metric-box-number {
        font-size: 28px;
        font-weight: 700;
        color: #111827;
        letter-spacing: -0.03em;
        line-height: 1.1;
        margin: 6px 0;
    }
    .trend-pill {
        display: inline-flex;
        align-items: center;
        gap: 4px;
        border-radius: 9999px;
        padding: 2px 8px;
        font-size: 11px;
        font-weight: 600;
        width: fit-content;
    }
    .pill-green {
        background: var(--green-pill-bg);
        color: var(--green-pill-text);
    }
    .pill-amber {
        background: var(--amber-pill-bg);
        color: var(--amber-pill-text);
    }
    .pill-red {
        background: var(--red-pill-bg);
        color: var(--red-pill-text);
    }
    .pill-gray {
        background: #F3F4F6;
        color: #4B5563;
    }

    /* Content Cards */
    .content-box {
        background: #FFFFFF;
        border: 1px solid #E5E7EB;
        border-radius: 12px;
        padding: 20px 22px;
        margin-top: 14px;
        margin-bottom: 14px;
        box-shadow: 0 1px 2px rgba(0,0,0,0.02);
    }
    .content-box-title {
        font-size: 15px;
        font-weight: 600;
        color: #111827;
        margin: 0 0 2px 0;
    }
    .content-box-sub {
        font-size: 12px;
        color: #6B7280;
        margin: 0 0 16px 0;
    }

    /* Responsive Data Table */
    .table-container {
        width: 100%;
        overflow-x: auto;
        -webkit-overflow-scrolling: touch;
        border-radius: 8px;
    }
    .clean-table {
        width: 100%;
        min-width: 620px;
        border-collapse: collapse;
        font-size: 13px;
        text-align: left;
    }
    .clean-table th {
        background: #F9FAFB;
        color: #6B7280;
        font-weight: 600;
        font-size: 11px;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        padding: 10px 14px;
        border-bottom: 1px solid #E5E7EB;
    }
    .clean-table td {
        padding: 12px 14px;
        border-bottom: 1px solid #F3F4F6;
        color: #111827;
        vertical-align: middle;
    }
    .clean-table tr:hover td {
        background-color: #F9FAFB;
    }

    /* Form Fields */
    .stTextArea textarea {
        background-color: #FFFFFF !important;
        border: 1px solid #E5E7EB !important;
        border-radius: 10px !important;
        font-size: 13px !important;
        line-height: 1.6 !important;
        color: #111827 !important;
    }
    .stTextArea textarea:focus {
        border-color: #2563EB !important;
        box-shadow: 0 0 0 2px rgba(37, 99, 235, 0.12) !important;
    }
    .stTextInput input {
        background-color: #FFFFFF !important;
        border: 1px solid #E5E7EB !important;
        border-radius: 8px !important;
        color: #111827 !important;
    }
    .stSelectbox div[data-baseweb="select"] > div {
        background-color: #FFFFFF !important;
        border: 1px solid #E5E7EB !important;
        border-radius: 8px !important;
        color: #111827 !important;
    }
    [data-baseweb="popover"], [data-baseweb="menu"], [data-baseweb="select"] ul {
        background-color: #FFFFFF !important;
        color: #111827 !important;
    }
    [data-baseweb="menu"] li {
        color: #111827 !important;
    }
    [data-baseweb="menu"] li:hover {
        background-color: #F3F4F6 !important;
    }
    [data-testid="stExpander"] {
        background-color: #FFFFFF !important;
        border: 1px solid #E5E7EB !important;
        border-radius: 10px !important;
        color: #111827 !important;
    }
    [data-testid="stExpander"] details {
        background-color: #FFFFFF !important;
        color: #111827 !important;
    }
    [data-testid="stExpander"] summary {
        color: #111827 !important;
    }
    .stTabs [data-baseweb="tab-list"] {
        background-color: transparent !important;
        border-bottom: 1px solid #E5E7EB !important;
        gap: 8px !important;
    }
    .stTabs [data-baseweb="tab"] {
        color: #6B7280 !important;
        font-weight: 500 !important;
        border: none !important;
        background-color: transparent !important;
    }
    .stTabs [data-baseweb="tab"][aria-selected="true"] {
        color: #2563EB !important;
        font-weight: 600 !important;
        border-bottom: 2px solid #2563EB !important;
    }
    .stTabs [data-testid="stTabContent"] {
        background-color: #FFFFFF !important;
        color: #111827 !important;
        padding-top: 14px !important;
    }
    .stButton button {
        border-radius: 8px !important;
        font-weight: 500 !important;
        font-size: 13px !important;
        border: 1px solid #E5E7EB !important;
        background-color: #FFFFFF !important;
        color: #374151 !important;
    }
    .stButton button:hover {
        background-color: #F9FAFB !important;
        border-color: #D1D5DB !important;
        color: #111827 !important;
    }
    .stButton button[kind="primary"] {
        background-color: #2563EB !important;
        border-color: #2563EB !important;
        color: #FFFFFF !important;
    }
    .stButton button[kind="primary"]:hover {
        background-color: #1D4ED8 !important;
        border-color: #1D4ED8 !important;
        color: #FFFFFF !important;
    }

    /* Progress bar */
    [data-testid="stProgressBar"] > div {
        background-color: #E5E7EB !important;
        height: 8px !important;
        border-radius: 999px !important;
    }
    [data-testid="stProgressBar"] > div > div {
        background-color: #2563EB !important;
        border-radius: 999px !important;
    }

    /* Hide Deploy Button, Hamburger 3-Dots Menu, and Footer, while keeping Sidebar Toggle accessible */
    #MainMenu,
    footer,
    .stAppDeployButton,
    [data-testid="stDecoration"],
    [data-testid="stToolbarActions"],
    [data-testid="stMainMenu"] {
        display: none !important;
        visibility: hidden !important;
        height: 0px !important;
        width: 0px !important;
        overflow: hidden !important;
    }

    /* Keep Toolbar header transparent and non-blocking */
    [data-testid="stHeader"] {
        background: transparent !important;
    }
    [data-testid="stToolbar"] {
        background: transparent !important;
        right: 14px !important;
    }

    /* Fixed, always accessible Expand Sidebar Button when collapsed */
    [data-testid="stExpandSidebarButton"] {
        display: inline-flex !important;
        visibility: visible !important;
        opacity: 1 !important;
        width: 36px !important;
        height: 36px !important;
        align-items: center !important;
        justify-content: center !important;
        background-color: #FFFFFF !important;
        border: 1px solid #E2E8F0 !important;
        border-radius: 8px !important;
        color: #0F172A !important;
        box-shadow: 0 1px 3px rgba(0,0,0,0.08) !important;
        position: fixed !important;
        top: 14px !important;
        left: 14px !important;
        z-index: 99999 !important;
        cursor: pointer !important;
        transition: all 0.15s ease !important;
    }
    [data-testid="stExpandSidebarButton"] button {
        display: inline-flex !important;
        visibility: visible !important;
        opacity: 1 !important;
        color: #0F172A !important;
    }
    [data-testid="stExpandSidebarButton"]:hover {
        background-color: #F8FAFC !important;
        border-color: #CBD5E1 !important;
        box-shadow: 0 2px 5px rgba(0,0,0,0.1) !important;
    }
    [data-testid="stSidebarCollapseButton"] button {
        color: #64748B !important;
        border-radius: 6px !important;
    }
    [data-testid="stSidebarCollapseButton"] button:hover {
        background-color: #F1F5F9 !important;
        color: #0F172A !important;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


def load_history():
    try:
        return get_scans()
    except sqlite3.Error as err:
        st.error(f"Database error: {err}")
        return None


def clear_scanner():
    st.session_state["prompt_input"] = ""
    st.session_state.pop("last_result", None)


# --- Load Data ---
history = load_history()
if history is None:
    st.stop()

# --- Crisp Light-Theme Sidebar ---
with st.sidebar:
    st.html(
        f"""
        <div style="display:flex;align-items:center;gap:11px;padding:6px 6px 18px;border-bottom:1px solid #E5E7EB;margin-bottom:16px;">
            <div style="background:#EFF6FF;color:#2563EB;width:36px;height:36px;border-radius:10px;display:flex;align-items:center;justify-content:center;border:1px solid #DBEAFE;box-shadow:0 1px 2px rgba(37,99,235,0.06);">
                {ICONS['shield']}
            </div>
            <div>
                <div style="font-size:14.5px;font-weight:700;color:#0F172A;letter-spacing:-0.02em;line-height:1.2;">Prompt Shelter</div>
                <div style="font-size:11px;color:#64748B;font-weight:500;">Enterprise Security</div>
            </div>
        </div>
        <div style="font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.06em;color:#94A3B8;padding:0 6px 8px;">Main Navigation</div>
        """
    )

    if "nav_route" not in st.session_state:
        st.session_state["nav_route"] = "Overview"

    cur_idx = NAV_PAGES.index(st.session_state["nav_route"]) if st.session_state["nav_route"] in NAV_PAGES else 0

    selected_route = st.radio(
        "Navigation",
        NAV_PAGES,
        index=cur_idx,
        key="nav_route",
        label_visibility="collapsed",
    )

    st.html(
        """
        <div style="margin-top:auto;padding-top:24px;border-top:1px solid #E5E7EB;font-size:11.5px;color:#64748B;">
            <div style="font-weight:600;text-transform:uppercase;letter-spacing:0.05em;color:#94A3B8;margin-bottom:8px">Engine Health</div>
            <div style="display:flex;align-items:center;justify-content:space-between;background:#F8FAFC;border:1px solid #E2E8F0;border-radius:8px;padding:8px 10px;margin-bottom:6px;">
                <span style="color:#0F172A;font-weight:600;display:flex;align-items:center;gap:6px;">
                    <span style="display:inline-block;width:7px;height:7px;border-radius:50%;background:#16A34A;box-shadow:0 0 0 2px #DCFCE7;"></span>
                    Operational
                </span>
                <span style="color:#2563EB;font-weight:600;font-size:11px;">20 Rules</span>
            </div>
            <div style="color:#94A3B8;font-size:11px;padding:0 2px;">Heuristic Core · v1.2</div>
        </div>
        """
    )


def render_page_header(breadcrumb_name: str, main_title: str):
    st.markdown(
        f"""
        <div class="header-breadcrumb">
            <span>Dashboard</span>
            <span>›</span>
            <span class="header-breadcrumb-active">{escape(breadcrumb_name)}</span>
        </div>
        <div class="header-row">
            <h1 class="header-title">{escape(main_title)}</h1>
            <div class="header-buttons">
                <div class="header-btn">{ICONS['calendar']} Select date range</div>
                <div class="header-btn">{ICONS['download']} Export CSV {ICONS['chevron-down']}</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


# ==============================================================================
# 1. OVERVIEW
# ==============================================================================
if selected_route == "Overview":
    render_page_header("Overview", "Overview")

    total_scans = len(history)
    counts = Counter(r["classification"] for r in history)
    safe_pct = (counts["SAFE"] / max(1, total_scans)) * 100

    # Status banner — real security data only
    if total_scans == 0:
        banner_title = "No scan data yet"
        banner_desc = "Submit a prompt in the Prompt Scanner to begin evaluating threat patterns."
        banner_icon = ICONS["alert-triangle"]
    elif safe_pct >= 80:
        banner_title = "Detection posture: Nominal"
        banner_desc = (
            f"{safe_pct:.1f}% of evaluated prompts were classified SAFE "
            f"across {total_scans} recorded submission{'s' if total_scans != 1 else ''}."
        )
        banner_icon = ICONS["check-circle"]
    else:
        banner_title = "Elevated threat activity detected"
        banner_desc = (
            f"{100 - safe_pct:.1f}% of evaluated prompts were flagged SUSPICIOUS or MALICIOUS "
            f"across {total_scans} recorded submission{'s' if total_scans != 1 else ''}."
        )
        banner_icon = ICONS["alert-triangle"]

    st.markdown(
        f"""
        <div class="alert-banner">
            <div style="margin-top:2px">{banner_icon}</div>
            <div>
                <div class="alert-banner-title">{banner_title}</div>
                <div class="alert-banner-desc">{banner_desc}</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # 4-Column Security Stat Cards — real data only
    c1, c2, c3, c4 = st.columns(4)
    safe_count = counts["SAFE"]
    suspicious_count = counts["SUSPICIOUS"]
    malicious_count = counts["MALICIOUS"]

    with c1:
        st.markdown(
            f"""
            <div class="metric-box">
                <div class="metric-box-top">
                    <span>Total Scans</span>
                    <span class="metric-box-icon">{ICONS['activity']}</span>
                </div>
                <div class="metric-box-number">{total_scans:,}</div>
                <div>
                    <span class="trend-pill pill-gray">All-time evaluations</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with c2:
        st.markdown(
            f"""
            <div class="metric-box">
                <div class="metric-box-top">
                    <span>Safe Prompts</span>
                    <span class="metric-box-icon">{ICONS['check-circle']}</span>
                </div>
                <div class="metric-box-number">{safe_count:,}</div>
                <div>
                    <span class="trend-pill pill-green">SAFE — no rules matched</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with c3:
        st.markdown(
            f"""
            <div class="metric-box">
                <div class="metric-box-top">
                    <span>Suspicious</span>
                    <span class="metric-box-icon">{ICONS['alert-triangle']}</span>
                </div>
                <div class="metric-box-number">{suspicious_count:,}</div>
                <div>
                    <span class="trend-pill pill-amber">SUSPICIOUS — review advised</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with c4:
        st.markdown(
            f"""
            <div class="metric-box">
                <div class="metric-box-top">
                    <span>Malicious</span>
                    <span class="metric-box-icon">{ICONS['alert-octagon']}</span>
                </div>
                <div class="metric-box-number">{malicious_count:,}</div>
                <div>
                    <span class="trend-pill pill-red">MALICIOUS — high-risk</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # 2-Column Charts — real security data
    col_chart_left, col_chart_right = st.columns(2)

    with col_chart_left:
        st.markdown(
            """
            <div class="content-box">
                <h3 class="content-box-title">Scan Activity Over Time</h3>
                <p class="content-box-sub">Daily evaluation volume</p>
            """,
            unsafe_allow_html=True,
        )
        dates = Counter(datetime.fromisoformat(s["scanned_at"]).date().isoformat() for s in history)
        if len(dates) >= 2:
            date_df = pd.DataFrame({"Scans": list(dict(sorted(dates.items())).values())},
                                   index=list(dict(sorted(dates.items())).keys()))
            st.line_chart(date_df, y="Scans")
        elif history:
            score_df = pd.DataFrame({"Risk Score": [s["risk_score"] for s in history]})
            st.line_chart(score_df, y="Risk Score")
        else:
            st.info("Insufficient data for trend visualization.")
        st.markdown("</div>", unsafe_allow_html=True)

    with col_chart_right:
        st.markdown(
            """
            <div class="content-box">
                <h3 class="content-box-title">Detection Category Breakdown</h3>
                <p class="content-box-sub">Most triggered rule categories</p>
            """,
            unsafe_allow_html=True,
        )
        cat_map = {r["name"]: r["category"] for r in RULES}
        cats = [cat_map.get(rn, "General") for h in history for rn in h.get("matched_rules", [])]
        if not cats:
            st.info("No category data recorded yet.")
        else:
            top_cats = Counter(cats).most_common(5)
            cat_df = pd.DataFrame(
                {"Count": [c[1] for c in top_cats]},
                index=[c[0] for c in top_cats],
            )
            st.bar_chart(cat_df, y="Count", color="#2563EB")
        st.markdown("</div>", unsafe_allow_html=True)

    # Recent scan table
    st.markdown(
        """
        <div class="content-box">
            <h3 class="content-box-title">Recent Scan Activity</h3>
            <p class="content-box-sub">Most recent prompt evaluations</p>
        """,
        unsafe_allow_html=True,
    )
    if not history:
        st.info("No recorded activity.")
    else:
        table_rows = ""
        for rec in history[:5]:
            dt = datetime.fromisoformat(rec["scanned_at"]).astimezone()
            preview = escape(rec["prompt_preview"] or "Preview not stored")
            cls_name = rec["classification"]
            pill_class = "pill-green" if cls_name == "SAFE" else "pill-amber" if cls_name == "SUSPICIOUS" else "pill-red"
            badge = f'<span class="trend-pill {pill_class}">{cls_name}</span>'
            table_rows += f"""
            <tr>
                <td style="font-family:monospace;font-size:12px;color:#6B7280">#{rec['id']}</td>
                <td style="font-size:12px;color:#6B7280;white-space:nowrap">{dt:%b %d, %H:%M}</td>
                <td style="max-width:320px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{preview}</td>
                <td style="font-weight:600;font-size:13px">{rec['risk_score']}/100</td>
                <td>{badge}</td>
                <td style="font-size:12px;color:#6B7280">{len(rec['matched_rules'])} indicators</td>
            </tr>
            """
        st.html(
            f"""<div class="table-container">
<table class="clean-table">
<thead>
<tr>
<th>ID</th>
<th>Date</th>
<th>Prompt Preview</th>
<th>Score</th>
<th>Status</th>
<th>Indicators</th>
</tr>
</thead>
<tbody>
{table_rows}
</tbody>
</table>
</div>"""
        )
    st.markdown("</div>", unsafe_allow_html=True)


# ==============================================================================
# 2. PROMPT SCANNER
# ==============================================================================
elif selected_route == "Prompt Scanner":
    render_page_header("Prompt Scanner", "Prompt Scanner")

    st.markdown(
        """
        <div class="content-box" style="margin-top:0">
            <h3 class="content-box-title">Analyze a Prompt</h3>
            <p class="content-box-sub">Paste a prompt below to identify potential prompt injection patterns and examine risk findings.</p>
        """,
        unsafe_allow_html=True,
    )

    prompt = st.text_area(
        "Prompt Editor",
        key="prompt_input",
        placeholder="Paste a prompt here to evaluate against configured threat indicators...",
        height=190,
        max_chars=20000,
        label_visibility="collapsed",
    )

    col_meta, col_btns = st.columns([2, 1])
    with col_meta:
        st.caption(f"{len(prompt):,} / 20,000 characters entered")
        store_preview = st.checkbox(
            "Persist redacted 120-character preview in SQLite",
            value=True,
            help="Common secrets and email addresses are automatically redacted.",
        )
    with col_btns:
        btn_a, btn_b = st.columns([1.6, 1])
        with btn_a:
            submitted = st.button("Analyze Prompt", type="primary", use_container_width=True)
        with btn_b:
            st.button("Clear", use_container_width=True, on_click=clear_scanner)

    st.markdown("</div>", unsafe_allow_html=True)

    if submitted:
        if not prompt.strip():
            st.warning("Input prompt is empty. Please enter text before initiating evaluation.")
            st.session_state.pop("last_result", None)
        else:
            with st.spinner("Executing rule matching across 20 precompiled patterns..."):
                score, classification, matched = analyze_prompt(prompt)
                try:
                    save_scan(
                        prompt,
                        score,
                        classification,
                        [item["name"] for item in matched],
                        store_preview=store_preview,
                    )
                except sqlite3.Error as err:
                    st.error(f"Failed to persist scan record: {err}")

                st.session_state["last_result"] = {
                    "score": score,
                    "classification": classification,
                    "matched": matched,
                    "prompt": prompt,
                }
            st.rerun()

    res = st.session_state.get("last_result")
    if res:
        res_score = res["score"]
        res_class = res["classification"]
        res_matched = res["matched"]
        matched_cats = sorted(list({item["category"] for item in res_matched}))

        st.markdown(
            """
            <div class="content-box">
                <h3 class="content-box-title">Evaluation Findings</h3>
                <p class="content-box-sub">Category-capped score model with explainable triggers</p>
            """,
            unsafe_allow_html=True,
        )

        r1, r2, r3, r4 = st.columns(4)
        with r1:
            st.markdown(
                f"""
                <div class="metric-box">
                    <div class="metric-box-top"><span>Risk Score</span></div>
                    <div class="metric-box-number">{res_score} <span style="font-size:14px;color:#9CA3AF;font-weight:500">/ 100</span></div>
                    <div><span class="trend-pill pill-gray">Capped weighted score</span></div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        with r2:
            pill_class = "pill-green" if res_class == "SAFE" else "pill-amber" if res_class == "SUSPICIOUS" else "pill-red"
            st.markdown(
                f"""
                <div class="metric-box">
                    <div class="metric-box-top"><span>Classification</span></div>
                    <div class="metric-box-number" style="font-size:22px;padding-top:4px">{res_class}</div>
                    <div><span class="trend-pill {pill_class}">Security status tier</span></div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        with r3:
            st.markdown(
                f"""
                <div class="metric-box">
                    <div class="metric-box-top"><span>Matched Rules</span></div>
                    <div class="metric-box-number">{len(res_matched)}</div>
                    <div><span class="trend-pill pill-gray">Out of 20 signatures</span></div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        with r4:
            st.markdown(
                f"""
                <div class="metric-box">
                    <div class="metric-box-top"><span>Categories</span></div>
                    <div class="metric-box-number">{len(matched_cats)}</div>
                    <div><span class="trend-pill pill-gray">Distinct attack angles</span></div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        st.markdown("<div style='height: 14px'></div>", unsafe_allow_html=True)
        st.progress(res_score / 100)

        if res_class == "SAFE":
            b_title = "SAFE · 0/100"
            b_desc = "No configured detection rules matched this prompt. This does not guarantee that the prompt is safe."
        elif res_class == "SUSPICIOUS":
            b_title = f"SUSPICIOUS · {res_score}/100"
            b_desc = "Potentially risky instruction patterns were detected. Review the findings before processing this prompt."
        else:
            b_title = f"MALICIOUS · {res_score}/100"
            b_desc = "Multiple high-risk indicators were detected. Treat this prompt as potentially malicious."

        st.markdown(
            f"""
            <div class="alert-banner" style="margin-top:16px">
                <div style="margin-top:2px">{ICONS['check-circle']}</div>
                <div>
                    <div class="alert-banner-title">{b_title}</div>
                    <div class="alert-banner-desc">{b_desc}</div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.markdown(f"#### Detailed Threat Indicators ({len(res_matched)})")
        if not res_matched:
            st.info("No threat indicators matched the submitted text.")
        else:
            for item in res_matched:
                with st.expander(f"{item['name']} — {item['category']} (+{item['weight']} pts)", expanded=True):
                    st.markdown(
                        f"""
                        <div style="font-size:13px;line-height:1.7;color:#374151">
                            <div><strong>Rule Identifier:</strong> <code style="font-family:monospace;font-size:11px;background:#F3F4F6;padding:2px 6px;border-radius:4px">{escape(item.get('rule_id', ''))}</code></div>
                            <div><strong>Category:</strong> {escape(item['category'])}</div>
                            <div><strong>Assigned Weight:</strong> +{item['weight']} points</div>
                            <div><strong>Detection Description:</strong> {escape(item.get('description', ''))}</div>
                            <div style="margin-top:8px"><strong>Matched Substring:</strong></div>
                            <div style="font-family:monospace;font-size:12px;background:#F9FAFB;border:1px solid #E5E7EB;border-radius:6px;padding:8px 12px;color:#111827">"{escape(item.get('matched_phrase', ''))}"</div>
                            <div style="margin-top:8px;font-size:12px;color:#6B7280"><strong>Explanation:</strong> {escape(item.get('explanation', ''))}</div>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )
        st.markdown("</div>", unsafe_allow_html=True)


# ==============================================================================
# 3. DETECTION RULES DIRECTORY
# ==============================================================================
elif selected_route == "Detection Rules":
    render_page_header("Detection Rules", "Detection Rules")

    all_cats = sorted(list({r["category"] for r in RULES}))

    c_search, c_filter = st.columns([2.5, 1.2])
    with c_search:
        search_query = st.text_input("Filter directory", placeholder="Search by name, ID, pattern, or category...", label_visibility="collapsed")
    with c_filter:
        selected_cat = st.selectbox("Category", ["All Categories", *all_cats], label_visibility="collapsed")

    filtered = RULES
    if selected_cat != "All Categories":
        filtered = [r for r in filtered if r["category"] == selected_cat]
    if search_query.strip():
        q = search_query.casefold()
        filtered = [
            r for r in filtered
            if q in r["name"].casefold()
            or q in r.get("id", "").casefold()
            or q in r["category"].casefold()
            or q in r["pattern"].casefold()
            or q in r["description"].casefold()
        ]

    st.caption(f"Showing {len(filtered)} of {len(RULES)} active detection signatures")

    table_rows = ""
    for idx, rule in enumerate(filtered, start=1):
        rule_id = escape(rule.get("id", f"RULE_{idx:02d}"))
        name = escape(rule["name"])
        cat = escape(rule["category"])
        pattern = escape(rule["pattern"])
        desc = escape(rule["description"])
        weight = rule.get("weight", 0)

        table_rows += f"""
        <tr>
            <td style="font-family:monospace;font-size:11px;color:#6B7280">{rule_id}</td>
            <td style="font-weight:600;font-size:13px">{name}</td>
            <td style="font-size:12px"><span style="background:#F3F4F6;padding:2px 6px;border-radius:4px;color:#4B5563">{cat}</span></td>
            <td style="font-weight:600;font-size:12px;color:#2563EB">+{weight}</td>
            <td style="font-size:12px;color:#4B5563;max-width:320px">{desc}</td>
            <td style="font-family:monospace;font-size:11px;color:#111827;max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="{pattern}"><code>{pattern}</code></td>
        </tr>
        """

    st.html(
        f"""<div class="content-box" style="margin-top:0">
<div class="table-container">
<table class="clean-table">
<thead>
<tr>
<th>Rule ID</th>
<th>Name</th>
<th>Category</th>
<th>Weight</th>
<th>Description</th>
<th>Pattern</th>
</tr>
</thead>
<tbody>
{table_rows}
</tbody>
</table>
</div>
</div>"""
    )


# ==============================================================================
# 4. SCAN HISTORY
# ==============================================================================
elif selected_route == "Scan History":
    render_page_header("Scan History", "Scan History")

    c_s, c_c, c_o = st.columns([2, 1, 1])
    with c_s:
        sq = st.text_input("Search audit log", placeholder="Search prompt preview or matched indicator...", label_visibility="collapsed")
    with c_c:
        cf = st.selectbox("Classification Filter", ["All Classifications", *CLASSIFICATIONS], label_visibility="collapsed")
    with c_o:
        so = st.selectbox("Sort Order", ["Newest First", "Oldest First", "Highest Risk", "Lowest Risk"], label_visibility="collapsed")

    filtered_scans = history
    if cf != "All Classifications":
        filtered_scans = [s for s in filtered_scans if s["classification"] == cf]
    if sq.strip():
        q = sq.casefold()
        filtered_scans = [
            s for s in filtered_scans
            if q in (s["prompt_preview"] or "").casefold()
            or any(q in rn.casefold() for rn in s["matched_rules"])
        ]

    if so == "Newest First":
        filtered_scans = sorted(filtered_scans, key=lambda x: x["scanned_at"], reverse=True)
    elif so == "Oldest First":
        filtered_scans = sorted(filtered_scans, key=lambda x: x["scanned_at"], reverse=False)
    elif so == "Highest Risk":
        filtered_scans = sorted(filtered_scans, key=lambda x: x["risk_score"], reverse=True)
    elif so == "Lowest Risk":
        filtered_scans = sorted(filtered_scans, key=lambda x: x["risk_score"], reverse=False)

    if not history:
        st.info("No recorded scan events found.")
    elif not filtered_scans:
        st.info("No records match the active filter criteria.")
    else:
        st.caption(f"Showing {len(filtered_scans)} of {len(history)} records")

        table_rows = ""
        for rec in filtered_scans:
            dt = datetime.fromisoformat(rec["scanned_at"]).astimezone()
            cls_name = rec["classification"]
            pill_class = "pill-green" if cls_name == "SAFE" else "pill-amber" if cls_name == "SUSPICIOUS" else "pill-red"
            badge = f'<span class="trend-pill {pill_class}">{cls_name}</span>'
            preview = escape(rec["prompt_preview"] or "Content not stored")
            indicators = escape(", ".join(rec["matched_rules"])) if rec["matched_rules"] else "None"

            table_rows += f"""
            <tr>
                <td style="font-family:monospace;font-size:11px;color:#6B7280">#{rec['id']}</td>
                <td style="font-size:12px;color:#6B7280;white-space:nowrap">{dt:%Y-%m-%d %H:%M}</td>
                <td style="font-size:13px;max-width:320px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{preview}</td>
                <td style="font-weight:600;font-size:13px">{rec['risk_score']}/100</td>
                <td>{badge}</td>
                <td style="font-size:12px;color:#4B5563;max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{indicators}</td>
            </tr>
            """

        st.html(
            f"""<div class="content-box" style="margin-top:0">
<div class="table-container">
<table class="clean-table">
<thead>
<tr>
<th>ID</th>
<th>Timestamp</th>
<th>Prompt Preview</th>
<th>Risk Score</th>
<th>Classification</th>
<th>Matched Rules</th>
</tr>
</thead>
<tbody>
{table_rows}
</tbody>
</table>
</div>
</div>"""
        )

    st.markdown("<div style='height: 24px'></div>", unsafe_allow_html=True)
    with st.expander("Database Maintenance & Storage Controls"):
        st.caption("Permanent deletion removes all scan records from the local SQLite store.")
        conf = st.checkbox("Confirm permanent deletion of local scan history")
        if st.button("Delete All Records", disabled=not conf):
            try:
                clear_scans()
                st.success("Audit records cleared.")
                st.rerun()
            except sqlite3.Error as e:
                st.error(f"Failed to clear history: {e}")


# ==============================================================================
# 5. ANALYTICS
# ==============================================================================
elif selected_route == "Analytics":
    render_page_header("Analytics", "Analytics")

    if not history:
        st.info("Telemetry data requires at least one evaluated prompt.")
    else:
        cnts = Counter(s["classification"] for s in history)
        scores = [s["risk_score"] for s in history]

        col1, col2 = st.columns(2)
        with col1:
            st.markdown(
                """
                <div class="content-box">
                    <h3 class="content-box-title">Risk Tier Distribution</h3>
                    <p class="content-box-sub">Volume breakdown across SAFE, SUSPICIOUS, and MALICIOUS</p>
                """,
                unsafe_allow_html=True,
            )
            st.bar_chart(
                {
                    "SAFE": [cnts["SAFE"]],
                    "SUSPICIOUS": [cnts["SUSPICIOUS"]],
                    "MALICIOUS": [cnts["MALICIOUS"]],
                },
                color=["#15803D", "#B45309", "#B91C1C"],
                y_label="Count",
            )
            st.markdown("</div>", unsafe_allow_html=True)

        with col2:
            st.markdown(
                f"""
                <div class="content-box">
                    <h3 class="content-box-title">Risk Score Interval Frequency</h3>
                    <p class="content-box-sub">Mean risk score: {sum(scores) / max(1, len(scores)):.1f}/100</p>
                """,
                unsafe_allow_html=True,
            )
            bands = Counter(
                "0–24 (Low)" if s < 25 else "25–59 (Medium)" if s < 60 else "60–100 (High)"
                for s in scores
            )
            band_df = pd.DataFrame(
                {"Frequency": [bands["0–24 (Low)"], bands["25–59 (Medium)"], bands["60–100 (High)"]]},
                index=["0–24 (Low)", "25–59 (Medium)", "60–100 (High)"],
            )
            st.bar_chart(band_df, y="Frequency", color="#6B7280")
            st.markdown("</div>", unsafe_allow_html=True)

        all_rules = [r for s in history for r in s.get("matched_rules", [])]
        rule_counts = Counter(all_rules).most_common(8)

        st.markdown(
            """
            <div class="content-box">
                <h3 class="content-box-title">Frequently Triggered Signatures</h3>
                <p class="content-box-sub">Top 8 most triggered detection patterns</p>
            """,
            unsafe_allow_html=True,
        )
        if not rule_counts:
            st.info("No threat signatures have triggered in recorded history.")
        else:
            rules_df = pd.DataFrame(
                {"Triggers": [r[1] for r in rule_counts]},
                index=[r[0] for r in rule_counts],
            )
            st.bar_chart(rules_df, y="Triggers", color="#2563EB")
        st.markdown("</div>", unsafe_allow_html=True)


# ==============================================================================
# 6. RESEARCH NOTES
# ==============================================================================
elif selected_route == "Research Notes":
    render_page_header("Research Notes", "Research Notes")

    st.markdown(
        """
        <div class="content-box" style="margin-top:0">
            <h3 class="content-box-title">Research Scope & Architecture</h3>
            <p class="content-box-sub">
                Prompt Shelter is an experimental security platform designed to explore transparent,
                explainable rule-based prompt injection detection. The architecture evaluates inputs purely
                client-side without streaming prompt payloads to external LLMs or third-party APIs.
            </p>
        """,
        unsafe_allow_html=True,
    )

    t1, t2 = st.tabs(["Technical Pipeline & Scoring", "Limitations & Threat Boundary"])

    with t1:
        st.markdown(
            """
            ### Detection Pipeline
            1. **Input Normalization:** Sanitizes input strings using Unicode NFKC decomposition, CRLF normalization, and horizontal whitespace collapsing.
            2. **Signature Evaluation:** Precompiles and matches 20 distinct regex signatures categorized across role manipulation, authority impersonation, boundary disruption, and credential exfiltration.
            3. **Category Contribution Capping:** Applies hard category score ceilings (`CATEGORY_CAPS`) to prevent artificial score escalation from overlapping synonymous patterns.
            4. **Classification Calibration:**
               - **SAFE (0–24):** Zero configured signatures detected.
               - **SUSPICIOUS (25–59):** Single or moderate-weight threat patterns identified.
               - **MALICIOUS (60–100):** Multiple coordinated or high-weight indicators triggered across categories.
            """
        )

    with t2:
        st.markdown(
            """
            ### Research Boundaries
            - **No Semantic Intent Inference:** Regex rules execute syntactic pattern matching. They cannot distinguish between malicious instruction overrides and educational papers quoting attack vectors.
            - **Encoding Evasion:** Adversaries utilizing character insertion, Leetspeak, base64 encoding, or non-English prompts can bypass static lexical filters.
            - **Heuristic Indicators:** Scores represent detection heuristics, not mathematical guarantees of prompt safety.
            - **Layered Defense:** Rule-based scanners must be deployed as an initial edge inspection layer alongside system prompt isolation, output encoding, and model alignment.
            """
        )

    st.markdown("</div>", unsafe_allow_html=True)

st.markdown(
    """
    <div style="text-align:center;padding:28px 0 12px;color:#9CA3AF;font-size:12px">
        Prompt Shelter · Enterprise Security Research Platform · Client-Side Inspection
    </div>
    """,
    unsafe_allow_html=True,
)
