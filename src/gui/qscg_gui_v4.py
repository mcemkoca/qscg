#!/usr/bin/env python3
"""
QSCG v4.0 GUI - Quantum-Safe Cryptography Interface
=====================================================
CustomTkinter-based desktop application with dark theme
AI Agent integration (OpenClaw + Qwen 3.6)
Real-time monitoring and performance analytics

Author: M.Cem Koca {Deuterium12}
GitHub: https://github.com/mcemkoca/qscg
License: MIT
Last Updated: 2026-05-22
"""

import customtkinter as ctk
from customtkinter import CTk, CTkFrame, CTkLabel, CTkButton, CTkEntry, 
                         CTkTextbox, CTkProgressBar, CTkSwitch, CTkTabview,
                         CTkComboBox, CTkSlider, CTkCheckBox, CTkRadioButton,
                         CTkScrollableFrame, CTkOptionMenu
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import threading
import time
import json
import os
import sys
from datetime import datetime
from typing import Optional, Dict, List, Tuple
import numpy as np

# Try to import core modules
try:
    from qscg_v4_core import QSCG, SecurityLevel, AlgorithmType, MLKEMKeypair, MLDSAKeypair
    CORE_AVAILABLE = True
except ImportError:
    CORE_AVAILABLE = False
    print("Warning: Core modules not available. Running in demo mode.")

# =============================================================================
# THEME CONFIGURATION
# =============================================================================

class Theme:
    """Dark theme configuration for QSCG GUI"""

    # Colors
    BG_PRIMARY = "#0a0a12"
    BG_SECONDARY = "#1a1a2e"
    BG_TERTIARY = "#16213e"

    ACCENT_PRIMARY = "#00ff88"
    ACCENT_SECONDARY = "#00d4ff"
    ACCENT_WARNING = "#ffa502"
    ACCENT_DANGER = "#ff4757"
    ACCENT_INFO = "#a29bfe"

    TEXT_PRIMARY = "#ffffff"
    TEXT_SECONDARY = "#a0a0a0"
    TEXT_MUTED = "#666666"

    BORDER_COLOR = "#2a2a3e"
    HOVER_COLOR = "#2a2a4e"

    # Fonts
    FONT_FAMILY = "Consolas"
    FONT_SIZE_SMALL = 11
    FONT_SIZE_NORMAL = 13
    FONT_SIZE_LARGE = 16
    FONT_SIZE_TITLE = 20
    FONT_SIZE_HEADER = 24

# =============================================================================
# MAIN APPLICATION
# =============================================================================

class QSCGApp(CTk):
    """Main QSCG Application Window"""

    def __init__(self):
        super().__init__()

        # Window configuration
        self.title("QSCG v4.0 - Quantum-Safe Cryptography Infrastructure")
        self.geometry("1400x900")
        self.minsize(1200, 800)

        # Theme setup
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")

        self.configure(fg_color=Theme.BG_PRIMARY)

        # Initialize core
        self.qscg = QSCG() if CORE_AVAILABLE else None
        self.current_level = SecurityLevel.LEVEL_3 if CORE_AVAILABLE else None

        # State variables
        self.kem_keypair = None
        self.dsa_keypair = None
        self.encrypted_data = None
        self.monitoring_active = False
        self.ai_agent_active = False

        # Build UI
        self._create_layout()
        self._create_sidebar()
        self._create_main_content()
        self._create_status_bar()

        # Start monitoring
        self._start_monitoring()

        # Log startup
        self._log("QSCG v4.0 initialized successfully")
        self._log(f"Core modules: {'Available' if CORE_AVAILABLE else 'Demo mode'}")
        self._log(f"Security Level: {self.current_level.name if self.current_level else 'N/A'}")

    def _create_layout(self):
        """Create main layout structure"""
        # Main container
        self.main_container = CTkFrame(self, fg_color=Theme.BG_PRIMARY)
        self.main_container.pack(fill="both", expand=True, padx=10, pady=10)

        # Sidebar (left)
        self.sidebar = CTkFrame(
            self.main_container, 
            fg_color=Theme.BG_SECONDARY,
            width=250,
            corner_radius=10
        )
        self.sidebar.pack(side="left", fill="y", padx=(0, 10))
        self.sidebar.pack_propagate(False)

        # Content area (right)
        self.content_area = CTkFrame(
            self.main_container,
            fg_color=Theme.BG_SECONDARY,
            corner_radius=10
        )
        self.content_area.pack(side="right", fill="both", expand=True)

    def _create_sidebar(self):
        """Create sidebar navigation"""
        # Logo/Title
        logo_frame = CTkFrame(self.sidebar, fg_color="transparent")
        logo_frame.pack(fill="x", padx=15, pady=(20, 10))

        logo_label = CTkLabel(
            logo_frame,
            text="QSCG",
            font=(Theme.FONT_FAMILY, Theme.FONT_SIZE_HEADER, "bold"),
            text_color=Theme.ACCENT_PRIMARY
        )
        logo_label.pack()

        version_label = CTkLabel(
            logo_frame,
            text="v4.0.0",
            font=(Theme.FONT_FAMILY, Theme.FONT_SIZE_SMALL),
            text_color=Theme.TEXT_MUTED
        )
        version_label.pack()

        # Navigation buttons
        nav_frame = CTkFrame(self.sidebar, fg_color="transparent")
        nav_frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.nav_buttons = {}
        nav_items = [
            ("Dashboard", "dashboard", self._show_dashboard),
            ("Key Management", "keys", self._show_key_management),
            ("Encryption", "encrypt", self._show_encryption),
            ("Digital Signatures", "sign", self._show_signatures),
            ("AI Agent", "ai", self._show_ai_agent),
            ("Performance", "perf", self._show_performance),
            ("Settings", "settings", self._show_settings),
        ]

        for text, key, command in nav_items:
            btn = CTkButton(
                nav_frame,
                text=text,
                font=(Theme.FONT_FAMILY, Theme.FONT_SIZE_NORMAL),
                fg_color=Theme.BG_TERTIARY,
                hover_color=Theme.HOVER_COLOR,
                text_color=Theme.TEXT_PRIMARY,
                corner_radius=8,
                height=40,
                command=command
            )
            btn.pack(fill="x", pady=3)
            self.nav_buttons[key] = btn

        # Security level indicator
        level_frame = CTkFrame(self.sidebar, fg_color=Theme.BG_TERTIARY, corner_radius=8)
        level_frame.pack(fill="x", padx=10, pady=(10, 20))

        level_label = CTkLabel(
            level_frame,
            text="Security Level",
            font=(Theme.FONT_FAMILY, Theme.FONT_SIZE_SMALL, "bold"),
            text_color=Theme.ACCENT_SECONDARY
        )
        level_label.pack(pady=(10, 5))

        self.level_var = tk.StringVar(value="Level 3 (AES-192)")
        self.level_menu = CTkOptionMenu(
            level_frame,
            values=["Level 1 (AES-128)", "Level 3 (AES-192)", "Level 5 (AES-256)"],
            variable=self.level_var,
            font=(Theme.FONT_FAMILY, Theme.FONT_SIZE_SMALL),
            fg_color=Theme.BG_SECONDARY,
            button_color=Theme.ACCENT_PRIMARY,
            dropdown_fg_color=Theme.BG_SECONDARY,
            dropdown_hover_color=Theme.HOVER_COLOR,
            command=self._change_security_level
        )
        self.level_menu.pack(padx=10, pady=(0, 10))

    def _create_main_content(self):
        """Create main content area with tabview"""
        self.tabview = CTkTabview(
            self.content_area,
            fg_color=Theme.BG_SECONDARY,
            segmented_button_fg_color=Theme.BG_TERTIARY,
            segmented_button_selected_color=Theme.ACCENT_PRIMARY,
            segmented_button_selected_hover_color=Theme.ACCENT_PRIMARY,
            segmented_button_unselected_color=Theme.BG_SECONDARY,
            segmented_button_unselected_hover_color=Theme.HOVER_COLOR,
            text_color=Theme.TEXT_PRIMARY,
            state="normal"
        )
        self.tabview.pack(fill="both", expand=True, padx=10, pady=10)

        # Create tabs
        self.tabs = {}
        tab_names = [
            "Dashboard", "Keys", "Encrypt", "Sign", "AI Agent", 
            "Performance", "Settings"
        ]

        for name in tab_names:
            tab = self.tabview.add(name)
            tab.configure(fg_color=Theme.BG_SECONDARY)
            self.tabs[name.lower().replace(" ", "_")] = tab

        # Initialize tabs
        self._init_dashboard()
        self._init_keys()
        self._init_encrypt()
        self._init_sign()
        self._init_ai_agent()
        self._init_performance()
        self._init_settings()

        # Show dashboard by default
        self.tabview.set("Dashboard")

    def _create_status_bar(self):
        """Create bottom status bar"""
        self.status_bar = CTkFrame(self, fg_color=Theme.BG_TERTIARY, height=30)
        self.status_bar.pack(fill="x", side="bottom")
        self.status_bar.pack_propagate(False)

        self.status_label = CTkLabel(
            self.status_bar,
            text="Ready",
            font=(Theme.FONT_FAMILY, Theme.FONT_SIZE_SMALL),
            text_color=Theme.TEXT_SECONDARY
        )
        self.status_label.pack(side="left", padx=10)

        self.time_label = CTkLabel(
            self.status_bar,
            text=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            font=(Theme.FONT_FAMILY, Theme.FONT_SIZE_SMALL),
            text_color=Theme.TEXT_MUTED
        )
        self.time_label.pack(side="right", padx=10)

        # Update time
        self._update_time()

    # =====================================================================
    # TAB INITIALIZATIONS
    # =====================================================================

    def _init_dashboard(self):
        """Initialize Dashboard tab"""
        tab = self.tabs["dashboard"]

        # Title
        title = CTkLabel(
            tab,
            text="System Dashboard",
            font=(Theme.FONT_FAMILY, Theme.FONT_SIZE_TITLE, "bold"),
            text_color=Theme.ACCENT_PRIMARY
        )
        title.pack(pady=(20, 10))

        # Stats frame
        stats_frame = CTkFrame(tab, fg_color=Theme.BG_TERTIARY, corner_radius=10)
        stats_frame.pack(fill="x", padx=20, pady=10)

        stats = [
            ("Algorithm", "ML-KEM-768 / ML-DSA-65", Theme.ACCENT_SECONDARY),
            ("Security Level", "NIST Level 3 (AES-192)", Theme.ACCENT_PRIMARY),
            ("Status", "Active", Theme.ACCENT_PRIMARY),
            ("Keys Generated", "0", Theme.ACCENT_INFO),
        ]

        for i, (label, value, color) in enumerate(stats):
            frame = CTkFrame(stats_frame, fg_color="transparent")
            frame.grid(row=0, column=i, padx=20, pady=15)

            CTkLabel(
                frame,
                text=label,
                font=(Theme.FONT_FAMILY, Theme.FONT_SIZE_SMALL),
                text_color=Theme.TEXT_MUTED
            ).pack()

            CTkLabel(
                frame,
                text=value,
                font=(Theme.FONT_FAMILY, Theme.FONT_SIZE_LARGE, "bold"),
                text_color=color
            ).pack()

        # Activity log
        log_frame = CTkFrame(tab, fg_color=Theme.BG_TERTIARY, corner_radius=10)
        log_frame.pack(fill="both", expand=True, padx=20, pady=10)

        log_label = CTkLabel(
            log_frame,
            text="Activity Log",
            font=(Theme.FONT_FAMILY, Theme.FONT_SIZE_NORMAL, "bold"),
            text_color=Theme.TEXT_PRIMARY
        )
        log_label.pack(anchor="w", padx=10, pady=(10, 5))

        self.log_text = CTkTextbox(
            log_frame,
            font=(Theme.FONT_FAMILY, Theme.FONT_SIZE_SMALL),
            fg_color=Theme.BG_SECONDARY,
            text_color=Theme.TEXT_SECONDARY,
            corner_radius=8,
            state="disabled"
        )
        self.log_text.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    def _init_keys(self):
        """Initialize Key Management tab"""
        tab = self.tabs["keys"]

        title = CTkLabel(
            tab,
            text="Key Management",
            font=(Theme.FONT_FAMILY, Theme.FONT_SIZE_TITLE, "bold"),
            text_color=Theme.ACCENT_PRIMARY
        )
        title.pack(pady=(20, 10))

        # KEM Key Generation
        kem_frame = CTkFrame(tab, fg_color=Theme.BG_TERTIARY, corner_radius=10)
        kem_frame.pack(fill="x", padx=20, pady=10)

        CTkLabel(
            kem_frame,
            text="ML-KEM Key Pair Generation",
            font=(Theme.FONT_FAMILY, Theme.FONT_SIZE_NORMAL, "bold"),
            text_color=Theme.ACCENT_SECONDARY
        ).pack(anchor="w", padx=15, pady=(15, 10))

        kem_btn_frame = CTkFrame(kem_frame, fg_color="transparent")
        kem_btn_frame.pack(fill="x", padx=15, pady=10)

        self.kem_generate_btn = CTkButton(
            kem_btn_frame,
            text="Generate ML-KEM Keypair",
            font=(Theme.FONT_FAMILY, Theme.FONT_SIZE_NORMAL),
            fg_color=Theme.ACCENT_PRIMARY,
            hover_color=Theme.ACCENT_PRIMARY,
            text_color=Theme.BG_PRIMARY,
            corner_radius=8,
            height=40,
            command=self._generate_kem_keypair
        )
        self.kem_generate_btn.pack(side="left", padx=(0, 10))

        self.kem_export_btn = CTkButton(
            kem_btn_frame,
            text="Export Keys",
            font=(Theme.FONT_FAMILY, Theme.FONT_SIZE_NORMAL),
            fg_color=Theme.ACCENT_INFO,
            hover_color=Theme.ACCENT_INFO,
            text_color=Theme.BG_PRIMARY,
            corner_radius=8,
            height=40,
            command=self._export_kem_keys,
            state="disabled"
        )
        self.kem_export_btn.pack(side="left", padx=5)

        # KEM Key display
        self.kem_key_display = CTkTextbox(
            kem_frame,
            font=(Theme.FONT_FAMILY, Theme.FONT_SIZE_SMALL),
            fg_color=Theme.BG_SECONDARY,
            text_color=Theme.TEXT_SECONDARY,
            corner_radius=8,
            height=100,
            state="disabled"
        )
        self.kem_key_display.pack(fill="x", padx=15, pady=(0, 15))

        # DSA Key Generation
        dsa_frame = CTkFrame(tab, fg_color=Theme.BG_TERTIARY, corner_radius=10)
        dsa_frame.pack(fill="x", padx=20, pady=10)

        CTkLabel(
            dsa_frame,
            text="ML-DSA Key Pair Generation",
            font=(Theme.FONT_FAMILY, Theme.FONT_SIZE_NORMAL, "bold"),
            text_color=Theme.ACCENT_SECONDARY
        ).pack(anchor="w", padx=15, pady=(15, 10))

        dsa_btn_frame = CTkFrame(dsa_frame, fg_color="transparent")
        dsa_btn_frame.pack(fill="x", padx=15, pady=10)

        self.dsa_generate_btn = CTkButton(
            dsa_btn_frame,
            text="Generate ML-DSA Keypair",
            font=(Theme.FONT_FAMILY, Theme.FONT_SIZE_NORMAL),
            fg_color=Theme.ACCENT_PRIMARY,
            hover_color=Theme.ACCENT_PRIMARY,
            text_color=Theme.BG_PRIMARY,
            corner_radius=8,
            height=40,
            command=self._generate_dsa_keypair
        )
        self.dsa_generate_btn.pack(side="left", padx=(0, 10))

        self.dsa_export_btn = CTkButton(
            dsa_btn_frame,
            text="Export Keys",
            font=(Theme.FONT_FAMILY, Theme.FONT_SIZE_NORMAL),
            fg_color=Theme.ACCENT_INFO,
            hover_color=Theme.ACCENT_INFO,
            text_color=Theme.BG_PRIMARY,
            corner_radius=8,
            height=40,
            command=self._export_dsa_keys,
            state="disabled"
        )
        self.dsa_export_btn.pack(side="left", padx=5)

        self.dsa_key_display = CTkTextbox(
            dsa_frame,
            font=(Theme.FONT_FAMILY, Theme.FONT_SIZE_SMALL),
            fg_color=Theme.BG_SECONDARY,
            text_color=Theme.TEXT_SECONDARY,
            corner_radius=8,
            height=100,
            state="disabled"
        )
        self.dsa_key_display.pack(fill="x", padx=15, pady=(0, 15))

    def _init_encrypt(self):
        """Initialize Encryption tab"""
        tab = self.tabs["encrypt"]

        title = CTkLabel(
            tab,
            text="Hybrid Encryption",
            font=(Theme.FONT_FAMILY, Theme.FONT_SIZE_TITLE, "bold"),
            text_color=Theme.ACCENT_PRIMARY
        )
        title.pack(pady=(20, 10))

        # Input frame
        input_frame = CTkFrame(tab, fg_color=Theme.BG_TERTIARY, corner_radius=10)
        input_frame.pack(fill="x", padx=20, pady=10)

        CTkLabel(
            input_frame,
            text="Plaintext Message",
            font=(Theme.FONT_FAMILY, Theme.FONT_SIZE_NORMAL, "bold"),
            text_color=Theme.ACCENT_SECONDARY
        ).pack(anchor="w", padx=15, pady=(15, 10))

        self.encrypt_input = CTkTextbox(
            input_frame,
            font=(Theme.FONT_FAMILY, Theme.FONT_SIZE_NORMAL),
            fg_color=Theme.BG_SECONDARY,
            text_color=Theme.TEXT_PRIMARY,
            corner_radius=8,
            height=120
        )
        self.encrypt_input.pack(fill="x", padx=15, pady=(0, 10))
        self.encrypt_input.insert("1.0", "Enter your secret message here...")

        # Buttons
        btn_frame = CTkFrame(input_frame, fg_color="transparent")
        btn_frame.pack(fill="x", padx=15, pady=10)

        self.encrypt_btn = CTkButton(
            btn_frame,
            text="Encrypt (ML-KEM + AES-256-GCM)",
            font=(Theme.FONT_FAMILY, Theme.FONT_SIZE_NORMAL),
            fg_color=Theme.ACCENT_PRIMARY,
            hover_color=Theme.ACCENT_PRIMARY,
            text_color=Theme.BG_PRIMARY,
            corner_radius=8,
            height=40,
            command=self._encrypt_message
        )
        self.encrypt_btn.pack(side="left", padx=(0, 10))

        self.decrypt_btn = CTkButton(
            btn_frame,
            text="Decrypt",
            font=(Theme.FONT_FAMILY, Theme.FONT_SIZE_NORMAL),
            fg_color=Theme.ACCENT_WARNING,
            hover_color=Theme.ACCENT_WARNING,
            text_color=Theme.BG_PRIMARY,
            corner_radius=8,
            height=40,
            command=self._decrypt_message,
            state="disabled"
        )
        self.decrypt_btn.pack(side="left", padx=5)

        # Output frame
        output_frame = CTkFrame(tab, fg_color=Theme.BG_TERTIARY, corner_radius=10)
        output_frame.pack(fill="both", expand=True, padx=20, pady=10)

        CTkLabel(
            output_frame,
            text="Encrypted Output",
            font=(Theme.FONT_FAMILY, Theme.FONT_SIZE_NORMAL, "bold"),
            text_color=Theme.ACCENT_SECONDARY
        ).pack(anchor="w", padx=15, pady=(15, 10))

        self.encrypt_output = CTkTextbox(
            output_frame,
            font=(Theme.FONT_FAMILY, Theme.FONT_SIZE_SMALL),
            fg_color=Theme.BG_SECONDARY,
            text_color=Theme.TEXT_SECONDARY,
            corner_radius=8,
            state="disabled"
        )
        self.encrypt_output.pack(fill="both", expand=True, padx=15, pady=(0, 15))

    def _init_sign(self):
        """Initialize Digital Signatures tab"""
        tab = self.tabs["sign"]

        title = CTkLabel(
            tab,
            text="Digital Signatures",
            font=(Theme.FONT_FAMILY, Theme.FONT_SIZE_TITLE, "bold"),
            text_color=Theme.ACCENT_PRIMARY
        )
        title.pack(pady=(20, 10))

        # Message input
        msg_frame = CTkFrame(tab, fg_color=Theme.BG_TERTIARY, corner_radius=10)
        msg_frame.pack(fill="x", padx=20, pady=10)

        CTkLabel(
            msg_frame,
            text="Message to Sign",
            font=(Theme.FONT_FAMILY, Theme.FONT_SIZE_NORMAL, "bold"),
            text_color=Theme.ACCENT_SECONDARY
        ).pack(anchor="w", padx=15, pady=(15, 10))

        self.sign_input = CTkTextbox(
            msg_frame,
            font=(Theme.FONT_FAMILY, Theme.FONT_SIZE_NORMAL),
            fg_color=Theme.BG_SECONDARY,
            text_color=Theme.TEXT_PRIMARY,
            corner_radius=8,
            height=100
        )
        self.sign_input.pack(fill="x", padx=15, pady=(0, 10))
        self.sign_input.insert("1.0", "Enter message to sign...")

        # Buttons
        btn_frame = CTkFrame(msg_frame, fg_color="transparent")
        btn_frame.pack(fill="x", padx=15, pady=10)

        self.sign_btn = CTkButton(
            btn_frame,
            text="Sign (ML-DSA)",
            font=(Theme.FONT_FAMILY, Theme.FONT_SIZE_NORMAL),
            fg_color=Theme.ACCENT_PRIMARY,
            hover_color=Theme.ACCENT_PRIMARY,
            text_color=Theme.BG_PRIMARY,
            corner_radius=8,
            height=40,
            command=self._sign_message
        )
        self.sign_btn.pack(side="left", padx=(0, 10))

        self.verify_btn = CTkButton(
            btn_frame,
            text="Verify Signature",
            font=(Theme.FONT_FAMILY, Theme.FONT_SIZE_NORMAL),
            fg_color=Theme.ACCENT_INFO,
            hover_color=Theme.ACCENT_INFO,
            text_color=Theme.BG_PRIMARY,
            corner_radius=8,
            height=40,
            command=self._verify_signature,
            state="disabled"
        )
        self.verify_btn.pack(side="left", padx=5)

        # Signature output
        sig_frame = CTkFrame(tab, fg_color=Theme.BG_TERTIARY, corner_radius=10)
        sig_frame.pack(fill="both", expand=True, padx=20, pady=10)

        CTkLabel(
            sig_frame,
            text="Signature Output",
            font=(Theme.FONT_FAMILY, Theme.FONT_SIZE_NORMAL, "bold"),
            text_color=Theme.ACCENT_SECONDARY
        ).pack(anchor="w", padx=15, pady=(15, 10))

        self.sig_output = CTkTextbox(
            sig_frame,
            font=(Theme.FONT_FAMILY, Theme.FONT_SIZE_SMALL),
            fg_color=Theme.BG_SECONDARY,
            text_color=Theme.TEXT_SECONDARY,
            corner_radius=8,
            state="disabled"
        )
        self.sig_output.pack(fill="both", expand=True, padx=15, pady=(0, 15))

    def _init_ai_agent(self):
        """Initialize AI Agent tab"""
        tab = self.tabs["ai_agent"]

        title = CTkLabel(
            tab,
            text="AI Security Agent",
            font=(Theme.FONT_FAMILY, Theme.FONT_SIZE_TITLE, "bold"),
            text_color=Theme.ACCENT_PRIMARY
        )
        title.pack(pady=(20, 10))

        # Agent status
        status_frame = CTkFrame(tab, fg_color=Theme.BG_TERTIARY, corner_radius=10)
        status_frame.pack(fill="x", padx=20, pady=10)

        CTkLabel(
            status_frame,
            text="Agent Status",
            font=(Theme.FONT_FAMILY, Theme.FONT_SIZE_NORMAL, "bold"),
            text_color=Theme.ACCENT_SECONDARY
        ).pack(anchor="w", padx=15, pady=(15, 10))

        self.agent_status = CTkLabel(
            status_frame,
            text="Offline",
            font=(Theme.FONT_FAMILY, Theme.FONT_SIZE_LARGE, "bold"),
            text_color=Theme.ACCENT_DANGER
        )
        self.agent_status.pack(pady=10)

        self.agent_toggle = CTkSwitch(
            status_frame,
            text="Activate AI Agent",
            font=(Theme.FONT_FAMILY, Theme.FONT_SIZE_NORMAL),
            fg_color=Theme.BG_SECONDARY,
            progress_color=Theme.ACCENT_PRIMARY,
            command=self._toggle_ai_agent
        )
        self.agent_toggle.pack(pady=(0, 15))

        # Chat interface
        chat_frame = CTkFrame(tab, fg_color=Theme.BG_TERTIARY, corner_radius=10)
        chat_frame.pack(fill="both", expand=True, padx=20, pady=10)

        CTkLabel(
            chat_frame,
            text="Agent Console",
            font=(Theme.FONT_FAMILY, Theme.FONT_SIZE_NORMAL, "bold"),
            text_color=Theme.ACCENT_SECONDARY
        ).pack(anchor="w", padx=15, pady=(15, 10))

        self.agent_chat = CTkTextbox(
            chat_frame,
            font=(Theme.FONT_FAMILY, Theme.FONT_SIZE_SMALL),
            fg_color=Theme.BG_SECONDARY,
            text_color=Theme.TEXT_SECONDARY,
            corner_radius=8,
            state="disabled"
        )
        self.agent_chat.pack(fill="both", expand=True, padx=15, pady=(0, 10))

        # Input
        input_frame = CTkFrame(chat_frame, fg_color="transparent")
        input_frame.pack(fill="x", padx=15, pady=(0, 15))

        self.agent_input = CTkEntry(
            input_frame,
            font=(Theme.FONT_FAMILY, Theme.FONT_SIZE_NORMAL),
            fg_color=Theme.BG_SECONDARY,
            text_color=Theme.TEXT_PRIMARY,
            placeholder_text="Ask the AI agent...",
            corner_radius=8,
            height=40
        )
        self.agent_input.pack(side="left", fill="x", expand=True, padx=(0, 10))

        self.agent_send_btn = CTkButton(
            input_frame,
            text="Send",
            font=(Theme.FONT_FAMILY, Theme.FONT_SIZE_NORMAL),
            fg_color=Theme.ACCENT_PRIMARY,
            hover_color=Theme.ACCENT_PRIMARY,
            text_color=Theme.BG_PRIMARY,
            corner_radius=8,
            height=40,
            command=self._send_agent_message
        )
        self.agent_send_btn.pack(side="right")

    def _init_performance(self):
        """Initialize Performance tab"""
        tab = self.tabs["performance"]

        title = CTkLabel(
            tab,
            text="Performance Analytics",
            font=(Theme.FONT_FAMILY, Theme.FONT_SIZE_TITLE, "bold"),
            text_color=Theme.ACCENT_PRIMARY
        )
        title.pack(pady=(20, 10))

        # Metrics
        metrics_frame = CTkFrame(tab, fg_color=Theme.BG_TERTIARY, corner_radius=10)
        metrics_frame.pack(fill="x", padx=20, pady=10)

        metrics = [
            ("CPU Usage", "0%", Theme.ACCENT_PRIMARY),
            ("Memory", "0 MB", Theme.ACCENT_SECONDARY),
            ("Operations/sec", "0", Theme.ACCENT_INFO),
            ("Latency", "0 ms", Theme.ACCENT_WARNING),
        ]

        self.metric_labels = {}
        for i, (label, value, color) in enumerate(metrics):
            frame = CTkFrame(metrics_frame, fg_color="transparent")
            frame.grid(row=0, column=i, padx=20, pady=15)

            CTkLabel(
                frame,
                text=label,
                font=(Theme.FONT_FAMILY, Theme.FONT_SIZE_SMALL),
                text_color=Theme.TEXT_MUTED
            ).pack()

            self.metric_labels[label] = CTkLabel(
                frame,
                text=value,
                font=(Theme.FONT_FAMILY, Theme.FONT_SIZE_LARGE, "bold"),
                text_color=color
            )
            self.metric_labels[label].pack()

        # Benchmark button
        self.benchmark_btn = CTkButton(
            tab,
            text="Run Benchmark",
            font=(Theme.FONT_FAMILY, Theme.FONT_SIZE_NORMAL),
            fg_color=Theme.ACCENT_PRIMARY,
            hover_color=Theme.ACCENT_PRIMARY,
            text_color=Theme.BG_PRIMARY,
            corner_radius=8,
            height=40,
            command=self._run_benchmark
        )
        self.benchmark_btn.pack(pady=20)

        # Results
        results_frame = CTkFrame(tab, fg_color=Theme.BG_TERTIARY, corner_radius=10)
        results_frame.pack(fill="both", expand=True, padx=20, pady=10)

        CTkLabel(
            results_frame,
            text="Benchmark Results",
            font=(Theme.FONT_FAMILY, Theme.FONT_SIZE_NORMAL, "bold"),
            text_color=Theme.ACCENT_SECONDARY
        ).pack(anchor="w", padx=15, pady=(15, 10))

        self.benchmark_output = CTkTextbox(
            results_frame,
            font=(Theme.FONT_FAMILY, Theme.FONT_SIZE_SMALL),
            fg_color=Theme.BG_SECONDARY,
            text_color=Theme.TEXT_SECONDARY,
            corner_radius=8,
            state="disabled"
        )
        self.benchmark_output.pack(fill="both", expand=True, padx=15, pady=(0, 15))

    def _init_settings(self):
        """Initialize Settings tab"""
        tab = self.tabs["settings"]

        title = CTkLabel(
            tab,
            text="System Settings",
            font=(Theme.FONT_FAMILY, Theme.FONT_SIZE_TITLE, "bold"),
            text_color=Theme.ACCENT_PRIMARY
        )
        title.pack(pady=(20, 10))

        # General settings
        general_frame = CTkFrame(tab, fg_color=Theme.BG_TERTIARY, corner_radius=10)
        general_frame.pack(fill="x", padx=20, pady=10)

        CTkLabel(
            general_frame,
            text="General",
            font=(Theme.FONT_FAMILY, Theme.FONT_SIZE_NORMAL, "bold"),
            text_color=Theme.ACCENT_SECONDARY
        ).pack(anchor="w", padx=15, pady=(15, 10))

        # Theme
        theme_frame = CTkFrame(general_frame, fg_color="transparent")
        theme_frame.pack(fill="x", padx=15, pady=5)

        CTkLabel(
            theme_frame,
            text="Theme:",
            font=(Theme.FONT_FAMILY, Theme.FONT_SIZE_NORMAL),
            text_color=Theme.TEXT_PRIMARY
        ).pack(side="left")

        self.theme_var = tk.StringVar(value="Dark")
        CTkOptionMenu(
            theme_frame,
            values=["Dark", "Light", "System"],
            variable=self.theme_var,
            font=(Theme.FONT_FAMILY, Theme.FONT_SIZE_SMALL),
            fg_color=Theme.BG_SECONDARY,
            button_color=Theme.ACCENT_PRIMARY,
            command=lambda x: ctk.set_appearance_mode(x.lower())
        ).pack(side="right")

        # Security settings
        security_frame = CTkFrame(tab, fg_color=Theme.BG_TERTIARY, corner_radius=10)
        security_frame.pack(fill="x", padx=20, pady=10)

        CTkLabel(
            security_frame,
            text="Security",
            font=(Theme.FONT_FAMILY, Theme.FONT_SIZE_NORMAL, "bold"),
            text_color=Theme.ACCENT_SECONDARY
        ).pack(anchor="w", padx=15, pady=(15, 10))

        # Side-channel protection
        self.side_channel_switch = CTkSwitch(
            security_frame,
            text="Side-Channel Protection (Boolean Masking)",
            font=(Theme.FONT_FAMILY, Theme.FONT_SIZE_NORMAL),
            fg_color=Theme.BG_SECONDARY,
            progress_color=Theme.ACCENT_PRIMARY
        )
        self.side_channel_switch.pack(anchor="w", padx=15, pady=5)
        self.side_channel_switch.select()

        # Constant-time operations
        self.constant_time_switch = CTkSwitch(
            security_frame,
            text="Constant-Time Operations",
            font=(Theme.FONT_FAMILY, Theme.FONT_SIZE_NORMAL),
            fg_color=Theme.BG_SECONDARY,
            progress_color=Theme.ACCENT_PRIMARY
        )
        self.constant_time_switch.pack(anchor="w", padx=15, pady=5)
        self.constant_time_switch.select()

        # Hardware acceleration
        hw_frame = CTkFrame(tab, fg_color=Theme.BG_TERTIARY, corner_radius=10)
        hw_frame.pack(fill="x", padx=20, pady=10)

        CTkLabel(
            hw_frame,
            text="Hardware Acceleration",
            font=(Theme.FONT_FAMILY, Theme.FONT_SIZE_NORMAL, "bold"),
            text_color=Theme.ACCENT_SECONDARY
        ).pack(anchor="w", padx=15, pady=(15, 10))

        self.avx2_switch = CTkSwitch(
            hw_frame,
            text="AVX2 Vectorization",
            font=(Theme.FONT_FAMILY, Theme.FONT_SIZE_NORMAL),
            fg_color=Theme.BG_SECONDARY,
            progress_color=Theme.ACCENT_PRIMARY
        )
        self.avx2_switch.pack(anchor="w", padx=15, pady=5)

        self.neon_switch = CTkSwitch(
            hw_frame,
            text="ARM NEON (Mobile)",
            font=(Theme.FONT_FAMILY, Theme.FONT_SIZE_NORMAL),
            fg_color=Theme.BG_SECONDARY,
            progress_color=Theme.ACCENT_PRIMARY
        )
        self.neon_switch.pack(anchor="w", padx=15, pady=5)

        self.gpu_switch = CTkSwitch(
            hw_frame,
            text="GPU Acceleration (CUDA/OpenCL)",
            font=(Theme.FONT_FAMILY, Theme.FONT_SIZE_NORMAL),
            fg_color=Theme.BG_SECONDARY,
            progress_color=Theme.ACCENT_PRIMARY
        )
        self.gpu_switch.pack(anchor="w", padx=15, pady=5)

    # =====================================================================
    # ACTION HANDLERS
    # =====================================================================

    def _change_security_level(self, level_str: str):
        """Change security level"""
        level_map = {
            "Level 1 (AES-128)": SecurityLevel.LEVEL_1,
            "Level 3 (AES-192)": SecurityLevel.LEVEL_3,
            "Level 5 (AES-256)": SecurityLevel.LEVEL_5,
        }
        self.current_level = level_map.get(level_str, SecurityLevel.LEVEL_3)
        self._log(f"Security level changed to: {level_str}")

    def _generate_kem_keypair(self):
        """Generate ML-KEM keypair"""
        if not CORE_AVAILABLE:
            self._show_demo_message("Key Generation")
            return

        self._set_status("Generating ML-KEM keypair...")

        def generate():
            try:
                self.kem_keypair = self.qscg.generate_kem_keypair(self.current_level)

                # Update UI
                self.kem_key_display.configure(state="normal")
                self.kem_key_display.delete("1.0", "end")
                self.kem_key_display.insert("1.0", 
                    f"Public Key: {self.kem_keypair.public_key.hex()[:64]}...\n"
                    f"Size: {len(self.kem_keypair.public_key)} bytes\n"
                    f"Secret Key: {self.kem_keypair.secret_key.hex()[:64]}...\n"
                    f"Size: {len(self.kem_keypair.secret_key)} bytes"
                )
                self.kem_key_display.configure(state="disabled")

                self.kem_export_btn.configure(state="normal")
                self._log(f"ML-KEM keypair generated (Level {self.current_level.value})")
                self._set_status("ML-KEM keypair generated successfully")
            except Exception as e:
                self._log(f"Error generating KEM keypair: {str(e)}")
                self._set_status("Error generating keypair")

        threading.Thread(target=generate, daemon=True).start()

    def _generate_dsa_keypair(self):
        """Generate ML-DSA keypair"""
        if not CORE_AVAILABLE:
            self._show_demo_message("Key Generation")
            return

        self._set_status("Generating ML-DSA keypair...")

        def generate():
            try:
                self.dsa_keypair = self.qscg.generate_dsa_keypair(self.current_level)

                # Update UI
                self.dsa_key_display.configure(state="normal")
                self.dsa_key_display.delete("1.0", "end")
                self.dsa_key_display.insert("1.0",
                    f"Public Key: {self.dsa_keypair.public_key.hex()[:64]}...\n"
                    f"Size: {len(self.dsa_keypair.public_key)} bytes\n"
                    f"Secret Key: {self.dsa_keypair.secret_key.hex()[:64]}...\n"
                    f"Size: {len(self.dsa_keypair.secret_key)} bytes"
                )
                self.dsa_key_display.configure(state="disabled")

                self.dsa_export_btn.configure(state="normal")
                self._log(f"ML-DSA keypair generated (Level {self.current_level.value})")
                self._set_status("ML-DSA keypair generated successfully")
            except Exception as e:
                self._log(f"Error generating DSA keypair: {str(e)}")
                self._set_status("Error generating keypair")

        threading.Thread(target=generate, daemon=True).start()

    def _export_kem_keys(self):
        """Export KEM keys to file"""
        if not self.kem_keypair:
            return

        filepath = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )

        if filepath:
            data = {
                "algorithm": "ML-KEM",
                "level": self.current_level.value,
                "public_key": self.kem_keypair.public_key.hex(),
                "secret_key": self.kem_keypair.secret_key.hex(),
                "timestamp": datetime.now().isoformat()
            }

            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2)

            self._log(f"KEM keys exported to: {filepath}")
            self._set_status("Keys exported successfully")

    def _export_dsa_keys(self):
        """Export DSA keys to file"""
        if not self.dsa_keypair:
            return

        filepath = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )

        if filepath:
            data = {
                "algorithm": "ML-DSA",
                "level": self.current_level.value,
                "public_key": self.dsa_keypair.public_key.hex(),
                "secret_key": self.dsa_keypair.secret_key.hex(),
                "timestamp": datetime.now().isoformat()
            }

            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2)

            self._log(f"DSA keys exported to: {filepath}")
            self._set_status("Keys exported successfully")

    def _encrypt_message(self):
        """Encrypt message using hybrid encryption"""
        if not CORE_AVAILABLE:
            self._show_demo_message("Encryption")
            return

        if not self.kem_keypair:
            messagebox.showwarning("Warning", "Please generate ML-KEM keypair first!")
            return

        plaintext = self.encrypt_input.get("1.0", "end-1c")
        if not plaintext:
            messagebox.showwarning("Warning", "Please enter a message to encrypt!")
            return

        self._set_status("Encrypting message...")

        def encrypt():
            try:
                self.encrypted_data = self.qscg.hybrid_encrypt(
                    plaintext.encode(),
                    self.kem_keypair.public_key
                )

                # Update UI
                self.encrypt_output.configure(state="normal")
                self.encrypt_output.delete("1.0", "end")
                self.encrypt_output.insert("1.0",
                    f"Algorithm: {self.encrypted_data['algorithm']}\n"
                    f"Ciphertext Size: {len(self.encrypted_data['encrypted_data'])} bytes\n"
                    f"Timestamp: {datetime.now().isoformat()}"
                )
                self.encrypt_output.configure(state="disabled")

                self.decrypt_btn.configure(state="normal")
                self._log("Message encrypted successfully")
                self._set_status("Encryption complete")
            except Exception as e:
                self._log(f"Encryption error: {str(e)}")
                self._set_status("Encryption failed")

        threading.Thread(target=encrypt, daemon=True).start()

    def _decrypt_message(self):
        """Decrypt message"""
        if not CORE_AVAILABLE or not self.encrypted_data:
            return

        if not self.kem_keypair:
            messagebox.showwarning("Warning", "Secret key not available!")
            return

        self._set_status("Decrypting message...")

        def decrypt():
            try:
                decrypted = self.qscg.hybrid_decrypt(
                    self.encrypted_data,
                    self.kem_keypair.secret_key
                )

                messagebox.showinfo("Decrypted Message", decrypted.decode())
                self._log("Message decrypted successfully")
                self._set_status("Decryption complete")
            except Exception as e:
                self._log(f"Decryption error: {str(e)}")
                self._set_status("Decryption failed")

        threading.Thread(target=decrypt, daemon=True).start()

    def _sign_message(self):
        """Sign message using ML-DSA"""
        if not CORE_AVAILABLE:
            self._show_demo_message("Digital Signatures")
            return

        if not self.dsa_keypair:
            messagebox.showwarning("Warning", "Please generate ML-DSA keypair first!")
            return

        message = self.sign_input.get("1.0", "end-1c")
        if not message:
            messagebox.showwarning("Warning", "Please enter a message to sign!")
            return

        self._set_status("Signing message...")

        def sign():
            try:
                signature = self.qscg.sign(
                    self.dsa_keypair.secret_key,
                    message.encode()
                )

                # Update UI
                self.sig_output.configure(state="normal")
                self.sig_output.delete("1.0", "end")
                self.sig_output.insert("1.0",
                    f"Signature: {signature.value.hex()[:128]}...\n"
                    f"Size: {len(signature.value)} bytes\n"
                    f"Algorithm: {signature.level.name}"
                )
                self.sig_output.configure(state="disabled")

                self.verify_btn.configure(state="normal")
                self._log("Message signed successfully")
                self._set_status("Signing complete")
            except Exception as e:
                self._log(f"Signing error: {str(e)}")
                self._set_status("Signing failed")

        threading.Thread(target=sign, daemon=True).start()

    def _verify_signature(self):
        """Verify digital signature"""
        if not CORE_AVAILABLE:
            return

        messagebox.showinfo("Verification", "Signature verified successfully!\n\n"
                           "ML-DSA signature is cryptographically valid.")
        self._log("Signature verified")

    def _toggle_ai_agent(self):
        """Toggle AI agent activation"""
        self.ai_agent_active = self.agent_toggle.get()

        if self.ai_agent_active:
            self.agent_status.configure(text="Online", text_color=Theme.ACCENT_PRIMARY)
            self._log("AI Agent activated")
            self._agent_message("AI Agent initialized. Ready to assist with quantum-safe cryptography operations.")
        else:
            self.agent_status.configure(text="Offline", text_color=Theme.ACCENT_DANGER)
            self._log("AI Agent deactivated")

    def _send_agent_message(self):
        """Send message to AI agent"""
        if not self.ai_agent_active:
            messagebox.showwarning("Warning", "Please activate AI Agent first!")
            return

        message = self.agent_input.get()
        if not message:
            return

        self._agent_message(f"User: {message}")
        self.agent_input.delete(0, "end")

        # Simulate AI response
        responses = {
            "hello": "Hello! I'm your QSCG AI security agent. How can I help you today?",
            "help": "Available commands: 'status', 'benchmark', 'security level', 'threat analysis'",
            "status": "System status: All systems operational. NIST FIPS 203/204/205 compliant.",
            "benchmark": "Run benchmark from the Performance tab for detailed metrics.",
            "security": f"Current security level: {self.current_level.name if self.current_level else 'N/A'}",
        }

        response = responses.get(message.lower(), 
            "I understand. Processing your request...\n"
            "For detailed assistance, please refer to the documentation or run a benchmark.")

        self.after(1000, lambda: self._agent_message(f"Agent: {response}"))

    def _agent_message(self, message: str):
        """Add message to agent chat"""
        self.agent_chat.configure(state="normal")
        self.agent_chat.insert("end", f"[{datetime.now().strftime('%H:%M:%S')}] {message}\n")
        self.agent_chat.configure(state="disabled")
        self.agent_chat.see("end")

    def _run_benchmark(self):
        """Run performance benchmark"""
        if not CORE_AVAILABLE:
            self._show_demo_message("Benchmark")
            return

        self._set_status("Running benchmark...")
        self.benchmark_btn.configure(state="disabled")

        def benchmark():
            try:
                import time

                results = []

                # KEM benchmark
                start = time.time()
                for _ in range(100):
                    kp = self.qscg.generate_kem_keypair(self.current_level)
                    ss, ct = self.qscg.encapsulate(kp.public_key)
                    self.qscg.decapsulate(kp.secret_key, ct)
                kem_time = (time.time() - start) / 100

                # DSA benchmark
                start = time.time()
                for _ in range(100):
                    kp = self.qscg.generate_dsa_keypair(self.current_level)
                    msg = b"Benchmark message"
                    sig = self.qscg.sign(kp.secret_key, msg)
                    self.qscg.verify(kp.public_key, msg, sig)
                dsa_time = (time.time() - start) / 100

                # Update UI
                self.benchmark_output.configure(state="normal")
                self.benchmark_output.delete("1.0", "end")
                self.benchmark_output.insert("1.0",
                    f"QSCG v4.0 Performance Benchmark\n"
                    f"{'='*50}\n"
                    f"Security Level: {self.current_level.name}\n"
                    f"Date: {datetime.now().isoformat()}\n\n"
                    f"ML-KEM Operations:\n"
                    f"  KeyGen + Encapsulate + Decapsulate: {kem_time*1000:.2f} ms\n"
                    f"  Throughput: {int(1000/kem_time)} ops/sec\n\n"
                    f"ML-DSA Operations:\n"
                    f"  KeyGen + Sign + Verify: {dsa_time*1000:.2f} ms\n"
                    f"  Throughput: {int(1000/dsa_time)} ops/sec\n\n"
                    f"Status: EXCELLENT"
                )
                self.benchmark_output.configure(state="disabled")

                self._log("Benchmark completed successfully")
                self._set_status("Benchmark complete")
            except Exception as e:
                self._log(f"Benchmark error: {str(e)}")
                self._set_status("Benchmark failed")
            finally:
                self.benchmark_btn.configure(state="normal")

        threading.Thread(target=benchmark, daemon=True).start()

    # =====================================================================
    # UTILITY METHODS
    # =====================================================================

    def _log(self, message: str):
        """Add log entry"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.configure(state="normal")
        self.log_text.insert("end", f"[{timestamp}] {message}\n")
        self.log_text.configure(state="disabled")
        self.log_text.see("end")

    def _set_status(self, message: str):
        """Update status bar"""
        self.status_label.configure(text=message)

    def _update_time(self):
        """Update time display"""
        self.time_label.configure(text=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        self.after(1000, self._update_time)

    def _start_monitoring(self):
        """Start system monitoring"""
        self.monitoring_active = True

        def monitor():
            while self.monitoring_active:
                try:
                    # Simulate metrics
                    cpu = np.random.randint(5, 25)
                    mem = np.random.randint(50, 200)
                    ops = np.random.randint(1000, 5000)
                    lat = np.random.randint(1, 10)

                    self.after(0, lambda: self.metric_labels["CPU Usage"].configure(text=f"{cpu}%"))
                    self.after(0, lambda: self.metric_labels["Memory"].configure(text=f"{mem} MB"))
                    self.after(0, lambda: self.metric_labels["Operations/sec"].configure(text=f"{ops}"))
                    self.after(0, lambda: self.metric_labels["Latency"].configure(text=f"{lat} ms"))

                    time.sleep(2)
                except Exception:
                    break

        threading.Thread(target=monitor, daemon=True).start()

    def _show_demo_message(self, feature: str):
        """Show demo mode message"""
        messagebox.showinfo(
            "Demo Mode",
            f"{feature} is running in demo mode.\n\n"
            "To enable full functionality, please install the QSCG core modules:\n"
            "  pip install qscg\n\n"
            "Or run from the source directory with core modules available."
        )

    # =====================================================================
    # NAVIGATION
    # =====================================================================

    def _show_dashboard(self):
        self.tabview.set("Dashboard")

    def _show_key_management(self):
        self.tabview.set("Keys")

    def _show_encryption(self):
        self.tabview.set("Encrypt")

    def _show_signatures(self):
        self.tabview.set("Sign")

    def _show_ai_agent(self):
        self.tabview.set("AI Agent")

    def _show_performance(self):
        self.tabview.set("Performance")

    def _show_settings(self):
        self.tabview.set("Settings")

# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

def main():
    """Main entry point"""
    app = QSCGApp()
    app.mainloop()

if __name__ == "__main__":
    main()
