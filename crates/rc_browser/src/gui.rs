use crate::bookmarks::BookmarkSortMode;
use crate::tab_manager::{
    BrowserController, BrowserSettings, ClickOutcome, EqualizerPreset, SETTINGS_URL,
    SearchEngine, StartupBehavior, ThemeMode, UiFontFamily, VideoUpscalerMode, is_settings_url,
};
use eframe::egui;
use raw_window_handle::{HasWindowHandle, RawWindowHandle};
use rc_cdp::CdpRequest;
use rc_ipc::{Color, DrawCommand};
use rc_log::{DiagnosticEvent, LogCategory, Severity, write_emergency_event_to_disk};
use rc_sandbox::{
    get_win32_client_physical_size, reclaim_win32_keyboard_focus, set_win32_fullscreen,
    validate_and_extract_origin,
};
use rc_vault::{BiometricModality, SecurityVault};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::{Duration, Instant};
use wry::dpi::{LogicalPosition, LogicalSize, PhysicalPosition, PhysicalSize, Position, Size};
use wry::{
    MemoryUsageLevel, NewWindowResponse, PageLoadEvent, PermissionKind, PermissionResponse, Rect as WryRect, WebContext, WebView,
    WebViewBuilder, WebViewBuilderExtWindows, WebViewExtWindows,
};
use zeroize::Zeroize;

#[path = "gui_panes.rs"]
mod panes;
#[path = "gui_security.rs"]
mod security;
use security::{
    BlockedDownload, PermissionSink, StagedText, TaskResult, enforce_smartscreen,
};
pub(crate) use security::is_risky_download;

const OYA_LOGO_BYTES: &[u8] = include_bytes!("../../../assets/oya_logo.jpg");

const CHROME_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36";

const EQ_BAND_LABELS: [&str; 10] = [
    "31Hz", "62Hz", "125Hz", "250Hz", "500Hz", "1kHz", "2kHz", "4kHz", "8kHz", "16kHz",
];

const WEBVIEW_DIAG_BRIDGE: &str = r###"
(function() {
    // All state lives inside this closure: pages cannot see or call any of it. The browser talks
    // to the bridge only through WebView2 messages (see the "message" listener at the end).
    var allowBg = false;
    var browserFs = false;
    var loginNotifiedHref = "";
    var pausedByTab = new WeakSet();
    var lockedPlayers = new WeakSet();

    // Keep Page Visibility API reporting 'visible' when 'Allow in Background' is enabled on this tab
    try {
        var origHidden = Object.getOwnPropertyDescriptor(Document.prototype, "hidden");
        var origVis = Object.getOwnPropertyDescriptor(Document.prototype, "visibilityState");
        Object.defineProperty(document, "hidden", {
            configurable: true,
            get: function() {
                if (allowBg) return false;
                return origHidden && origHidden.get ? origHidden.get.call(document) : false;
            }
        });
        Object.defineProperty(document, "visibilityState", {
            configurable: true,
            get: function() {
                if (allowBg) return "visible";
                return origVis && origVis.get ? origVis.get.call(document) : "visible";
            }
        });
        document.addEventListener("visibilitychange", function(e) {
            if (allowBg) {
                e.stopImmediatePropagation();
            }
        }, true);
    } catch (_) {}

    function send(payload) {
        try {
            if (window.ipc && window.ipc.postMessage) {
                window.ipc.postMessage(JSON.stringify(payload));
            }
        } catch (_) {}
    }

    // Event-driven URL change detection (zero continuous polling overhead during 4K video playback!)
    var lastHref = location.href;
    function notifyUrlIfChanged() {
        if (location.href !== lastHref) {
            lastHref = location.href;
            loginNotifiedHref = "";
            send({ kind: "url", url: lastHref, title: document.title || "" });
            setTimeout(scanForLoginForms, 350);
            setTimeout(applyMediaFxToAllVideos, 400);
        }
    }
    window.addEventListener("popstate", notifyUrlIfChanged);
    window.addEventListener("hashchange", notifyUrlIfChanged);
    window.addEventListener("yt-navigate-finish", function() {
        notifyUrlIfChanged();
        setTimeout(applyMediaFxToAllVideos, 300);
    });
    try {
        var origPush = history.pushState;
        history.pushState = function() {
            var r = origPush.apply(this, arguments);
            setTimeout(notifyUrlIfChanged, 0);
            return r;
        };
        var origReplace = history.replaceState;
        history.replaceState = function() {
            var r = origReplace.apply(this, arguments);
            setTimeout(notifyUrlIfChanged, 0);
            return r;
        };
    } catch (_) {}

    // HTML5 Fullscreen & F11/Escape Synchronization
    function onFullscreenChange() {
        var fsEl = document.fullscreenElement || document.webkitFullscreenElement || document.msFullscreenElement;
        var isFs = !!fsEl;
        if (!isFs) {
            browserFs = false;
            var styleEl = document.getElementById("__oya_fullscreen_style");
            if (styleEl && styleEl.parentNode) {
                styleEl.parentNode.removeChild(styleEl);
            }
            window.dispatchEvent(new Event("resize"));
        }
        send({ kind: "fullscreen", fullscreen: isFs });
    }
    document.addEventListener("fullscreenchange", onFullscreenChange, true);
    document.addEventListener("webkitfullscreenchange", onFullscreenChange, true);

    // True Fullscreen Video Expander when triggered from Oya Browser toolbar / F11
    function setBrowserFullscreen(enable) {
        try {
            browserFs = !!enable;
            var styleEl = document.getElementById("__oya_fullscreen_style");
            if (enable) {
                var hasVideo = !!document.querySelector("video, #movie_player, .html5-video-player");
                if (hasVideo && !document.fullscreenElement) {
                    if (!styleEl) {
                        styleEl = document.createElement("style");
                        styleEl.id = "__oya_fullscreen_style";
                        document.head.appendChild(styleEl);
                    }
                    styleEl.textContent =
                        "html, body { overflow: hidden !important; background: #000 !important; margin: 0 !important; padding: 0 !important; width: 100vw !important; height: 100vh !important; } " +
                        "#masthead-container, ytd-masthead, #secondary, #related, #comments, #below, #guide, tp-yt-app-drawer { display: none !important; } " +
                        "#page-manager, ytd-watch-flexy, #columns, #primary, #primary-inner, #player, #player-theater-container, #player-container-outer, #player-container-inner, #player-container, #movie_player, .html5-video-player, .html5-video-container { " +
                        "position: fixed !important; inset: 0 !important; left: 0 !important; top: 0 !important; width: 100vw !important; height: 100vh !important; max-width: 100vw !important; max-height: 100vh !important; margin: 0 !important; padding: 0 !important; z-index: 2147483640 !important; background: #000 !important; } " +
                        "video.html5-main-video, video { position: fixed !important; inset: 0 !important; left: 0 !important; top: 0 !important; width: 100vw !important; height: 100vh !important; object-fit: contain !important; z-index: 2147483641 !important; } " +
                        ".ytp-chrome-bottom { z-index: 2147483645 !important; width: 98vw !important; left: 1vw !important; }";
                    window.dispatchEvent(new Event("resize"));
                }
            } else {
                if (styleEl && styleEl.parentNode) {
                    styleEl.parentNode.removeChild(styleEl);
                }
                if (document.fullscreenElement && document.exitFullscreen) {
                    document.exitFullscreen().catch(function(){});
                }
                window.dispatchEvent(new Event("resize"));
            }
        } catch (_) {}
    }

    // =========================================================================
    // 10-Band WebAudio Graphic Equalizer + Dynamic GPU Video Upscaler + 4K Lock
    // =========================================================================
    var fxConfig = {
        eqEnabled: false,
        preampDb: 0.0,
        bandsDb: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        upscaleMode: "auto",
        sharpness: 55.0,
        vibrance: 25.0,
        optimize4k: true
    };

    var audioCtx = null;
    var connectedElements = new WeakMap();
    var activeChains = [];
    var eqFreqs = [31, 62, 125, 250, 500, 1000, 2000, 4000, 8000, 16000];

    function ensureAudioChain(mediaEl) {
        if (!mediaEl || connectedElements.has(mediaEl)) return connectedElements.get(mediaEl);
        try {
            var Ctx = window.AudioContext || window.webkitAudioContext;
            if (!Ctx) return null;
            if (!audioCtx) audioCtx = new Ctx();
            if (audioCtx.state === "suspended") {
                audioCtx.resume().catch(function(){});
            }
            var source = audioCtx.createMediaElementSource(mediaEl);
            var preamp = audioCtx.createGain();
            var filters = [];
            for (var i = 0; i < eqFreqs.length; i++) {
                var f = audioCtx.createBiquadFilter();
                if (i === 0) f.type = "lowshelf";
                else if (i === eqFreqs.length - 1) f.type = "highshelf";
                else {
                    f.type = "peaking";
                    f.Q.value = 1.4;
                }
                f.frequency.value = eqFreqs[i];
                f.gain.value = 0;
                filters.push(f);
            }
            source.connect(preamp);
            var prev = preamp;
            for (var j = 0; j < filters.length; j++) {
                prev.connect(filters[j]);
                prev = filters[j];
            }
            prev.connect(audioCtx.destination);
            var chain = { preamp: preamp, filters: filters };
            connectedElements.set(mediaEl, chain);
            activeChains.push(chain);
            return chain;
        } catch (_) {
            return null;
        }
    }

    function updateAudioChains() {
        var cfg = fxConfig;
        if (!cfg.eqEnabled && activeChains.length === 0) return;
        var mediaList = document.querySelectorAll("video, audio");
        for (var m = 0; m < mediaList.length; m++) {
            if (cfg.eqEnabled) ensureAudioChain(mediaList[m]);
        }
        var gainLinear = cfg.eqEnabled ? Math.pow(10, (cfg.preampDb || 0) / 20.0) : 1.0;
        for (var c = 0; c < activeChains.length; c++) {
            var ch = activeChains[c];
            ch.preamp.gain.value = gainLinear;
            for (var b = 0; b < ch.filters.length; b++) {
                ch.filters[b].gain.value = cfg.eqEnabled ? (cfg.bandsDb[b] || 0) : 0;
            }
        }
    }

    function ensureUpscalerSvg(kernelAmount) {
        var svgId = "__oya_upscaler_svg_root";
        var matrixEl = document.getElementById("__oya_convolve_matrix");
        if (!matrixEl) {
            var div = document.createElement("div");
            div.id = svgId;
            div.style.cssText = "position:absolute;width:0;height:0;overflow:hidden;pointer-events:none;";
            div.innerHTML =
                '<svg xmlns="http://www.w3.org/2000/svg" width="0" height="0">' +
                '<filter id="__oya_gpu_upscale" color-interpolation-filters="sRGB">' +
                '<feConvolveMatrix id="__oya_convolve_matrix" order="3 3" preserveAlpha="true" kernelMatrix="0 -0.25 0 -0.25 2.0 -0.25 0 -0.25 0"/>' +
                '</filter></svg>';
            (document.body || document.documentElement).appendChild(div);
            matrixEl = document.getElementById("__oya_convolve_matrix");
        }
        if (matrixEl) {
            var s = Math.max(0, Math.min(1.2, kernelAmount));
            var center = (1.0 + 4.0 * s).toFixed(3);
            var edge = (-s).toFixed(3);
            var k = "0 " + edge + " 0 " + edge + " " + center + " " + edge + " 0 " + edge + " 0";
            if (matrixEl.getAttribute("kernelMatrix") !== k) {
                matrixEl.setAttribute("kernelMatrix", k);
            }
        }
    }

    function applyMediaFxToAllVideos() {
        try {
            var cfg = fxConfig;
            updateAudioChains();

            // Inject Modern CSS Layout Containment & GPU Compositor Layer Hints once per document
            // (Ref: https://web.dev/articles/avoid-large-complex-layouts-and-layout-thrashing
            //  and https://developer.chrome.com/docs/modern-web-guidance/guides/css/css-layout)
            if (cfg.optimize4k && !document.getElementById("__oya_layout_opt_style") && document.head) {
                var layoutStyle = document.createElement("style");
                layoutStyle.id = "__oya_layout_opt_style";
                layoutStyle.textContent =
                    "video { transform: translateZ(0); backface-visibility: hidden; will-change: transform; } " +
                    "#secondary, #related, #comments, ytd-watch-next-secondary-results-renderer { contain: style layout; }";
                document.head.appendChild(layoutStyle);
            }

            var videos = document.querySelectorAll("video");
            if (!videos || videos.length === 0) return;

            // =================================================================
            // PHASE 1: BATCH ALL GEOMETRIC & STYLE READS FIRST
            // Prevents Forced Synchronous Layout / Layout Thrashing!
            // (Ref: https://web.dev/articles/avoid-large-complex-layouts-and-layout-thrashing
            //  and https://browser.engineering/layout.html)
            // =================================================================
            var measurements = [];
            for (var r = 0; r < videos.length; r++) {
                var rv = videos[r];
                measurements.push({
                    el: rv,
                    vh: rv.videoHeight || 1080,
                    curFilter: rv.style.filter || "",
                    curDecoding: rv.getAttribute("decoding") || ""
                });
            }

            // =================================================================
            // PHASE 2: BATCH ALL DOM & COMPOSITOR STYLE WRITES SECOND
            // =================================================================
            var bypassUpscale = (!cfg.upscaleMode || cfg.upscaleMode === "off" || cfg.sharpness <= 1.0);
            var vibNorm = cfg.vibrance / 100.0;
            var contrast = (1.0 + vibNorm * (cfg.upscaleMode === "hdr" ? 0.16 : 0.08)).toFixed(3);
            var saturate = (1.0 + vibNorm * (cfg.upscaleMode === "hdr" ? 0.28 : 0.15)).toFixed(3);
            var brightness = (cfg.upscaleMode === "hdr" ? 1.02 : 1.0).toFixed(2);
            var filterStr =
                "url(#__oya_gpu_upscale) contrast(" + contrast + ") saturate(" + saturate + ") brightness(" + brightness + ")";

            var targetKernelNorm = 0.0;
            for (var i = 0; i < measurements.length; i++) {
                var item = measurements[i];
                var v = item.el;
                if (cfg.optimize4k && item.curDecoding !== "async") {
                    v.setAttribute("decoding", "async");
                }
                if (bypassUpscale) {
                    if (item.curFilter !== "") v.style.filter = "";
                    continue;
                }
                var vh = item.vh;
                var resFactor = 1.0;
                if (cfg.upscaleMode === "auto") {
                    if (vh <= 480) resFactor = 1.35;
                    else if (vh <= 720) resFactor = 1.15;
                    else if (vh <= 1080) resFactor = 0.95;
                    else resFactor = 0.55; // Native 1440p/4K/8K gets light micro-detail
                } else if (cfg.upscaleMode === "crisp4k") {
                    resFactor = 1.25;
                } else if (cfg.upscaleMode === "anime") {
                    resFactor = 1.40;
                } else if (cfg.upscaleMode === "hdr") {
                    resFactor = 0.85;
                }
                targetKernelNorm = (cfg.sharpness / 100.0) * 0.55 * resFactor;
                if (item.curFilter !== filterStr) {
                    v.style.filter = filterStr;
                }
            }

            if (!bypassUpscale) {
                ensureUpscalerSvg(targetKernelNorm);
            }

            // YouTube 4K Stream Quality Optimizer
            if (cfg.optimize4k && location.hostname.indexOf("youtube.com") !== -1) {
                var ytPlayer = document.getElementById("movie_player");
                if (ytPlayer && typeof ytPlayer.getAvailableQualityLevels === "function") {
                    var levels = ytPlayer.getAvailableQualityLevels();
                    if (levels && levels.length > 0) {
                        var best = levels[0]; // e.g. highres / hd2160 / hd1440
                        if (typeof ytPlayer.setPlaybackQualityRange === "function" && !lockedPlayers.has(ytPlayer)) {
                            lockedPlayers.add(ytPlayer);
                            ytPlayer.setPlaybackQualityRange(best, best);
                        }
                    }
                }
            }
        } catch (_) {}
    }

    var fxRafPending = false;
    function scheduleMediaFxPass() {
        if (fxRafPending) return;
        fxRafPending = true;
        var run = function() {
            fxRafPending = false;
            applyMediaFxToAllVideos();
        };
        if (typeof window.requestAnimationFrame === "function") {
            window.requestAnimationFrame(run);
        } else {
            setTimeout(run, 0);
        }
    }

    function applyFx(newCfg) {
        if (newCfg) {
            fxConfig = newCfg;
        }
        updateAudioChains();
        scheduleMediaFxPass();
    }

    document.addEventListener("loadedmetadata", function(e) {
        if (e.target && e.target.tagName === "VIDEO") {
            scheduleMediaFxPass();
        }
    }, true);
    document.addEventListener("play", function(e) {
        if (e.target && (e.target.tagName === "VIDEO" || e.target.tagName === "AUDIO")) {
            scheduleMediaFxPass();
        }
    }, true);

    // =========================================================================
    // Login & Credential Capture + Keyboard Shortcuts
    // =========================================================================
    function isVisible(el) {
        if (!el) return false;
        var rect = el.getBoundingClientRect();
        return rect.width > 0 && rect.height > 0;
    }

    function findUserField(root) {
        var scope = root || document;
        var candidates = scope.querySelectorAll(
            'input[type="email"], input[autocomplete="username"], input[name="identifier"], input[name*="user" i], input[name*="email" i], input[name*="login" i], input[id*="user" i], input[id*="email" i], input[type="text"]'
        );
        for (var i = 0; i < candidates.length; i++) {
            var el = candidates[i];
            if (el.type !== "password" && el.type !== "hidden" && isVisible(el)) {
                return el;
            }
        }
        return null;
    }

    function findPasswordField() {
        var passInputs = document.querySelectorAll('input[type="password"]');
        for (var i = 0; i < passInputs.length; i++) {
            if (isVisible(passInputs[i])) {
                return passInputs[i];
            }
        }
        return null;
    }

    document.addEventListener("input", function(e) {
        var t = e.target;
        if (!t || t.tagName !== "INPUT") return;
        if (t.type === "email" || t.name === "identifier" || t.autocomplete === "username" ||
            /user|email|login/i.test(t.name || "") || /user|email|login/i.test(t.id || "")) {
            if (t.value && t.value.trim().length > 0) {
                try { sessionStorage.setItem("__rc_pending_user", t.value.trim()); } catch (_) {}
            }
        }
    }, true);

    var lastSubmittedHash = "";
    function checkAndCaptureSubmission() {
        try {
            var p = findPasswordField();
            if (!p || !p.value || p.value.length === 0) return;
            var uField = findUserField(p.form || document);
            var uVal = (uField && uField.value) ? uField.value.trim() : "";
            if (!uVal) {
                try { uVal = sessionStorage.getItem("__rc_pending_user") || ""; } catch (_) {}
            }
            if (!uVal) uVal = "user";
            var sig = location.origin + "|" + uVal + "|" + p.value;
            if (sig === lastSubmittedHash) return;
            lastSubmittedHash = sig;
            send({
                kind: "login_submitted",
                origin: location.origin,
                username: uVal,
                password: p.value
            });
        } catch (_) {}
    }

    document.addEventListener("submit", function() {
        checkAndCaptureSubmission();
    }, true);

    document.addEventListener("keydown", function(e) {
        if (e.key === "F11") {
            e.preventDefault();
            send({ kind: "toggle_fullscreen" });
            return;
        }
        if (e.key === "Escape") {
            setBrowserFullscreen(false);
            send({ kind: "fullscreen", fullscreen: false });
        }
        if (e.key === "Enter") {
            var t = e.target;
            if (t && t.tagName === "INPUT") {
                if (t.type === "password") {
                    checkAndCaptureSubmission();
                } else if (t.value && t.value.trim().length > 0) {
                    try { sessionStorage.setItem("__rc_pending_user", t.value.trim()); } catch (_) {}
                }
            }
        }
    }, true);

    window.addEventListener("keyup", function(e) {
        if (e.key === "Escape") {
            if (browserFs || !document.fullscreenElement) {
                setBrowserFullscreen(false);
                send({ kind: "fullscreen", fullscreen: false });
            }
        }
    }, true);

    document.addEventListener("click", function(e) {
        var fsBtn = e.target && e.target.closest
            ? e.target.closest('.ytp-fullscreen-button, [aria-label*="Full screen" i], [title*="Full screen" i], [aria-label*="Exit full screen" i]')
            : null;
        if (fsBtn && browserFs && !document.fullscreenElement) {
            e.preventDefault();
            e.stopPropagation();
            setBrowserFullscreen(false);
            send({ kind: "fullscreen", fullscreen: false });
            return;
        }
        var btn = e.target && e.target.closest ? e.target.closest('button, input[type="submit"], [role="button"]') : null;
        if (btn) {
            var u = findUserField(document);
            if (u && u.value && u.value.trim().length > 0) {
                try { sessionStorage.setItem("__rc_pending_user", u.value.trim()); } catch (_) {}
            }
            // Only a button that actually submits the sign-in form counts as a login attempt.
            // Any other click leaves the typed password inside the page.
            if (isSubmitLike(btn)) checkAndCaptureSubmission();
        }
    }, true);

    function isSubmitLike(b) {
        var p = findPasswordField();
        if (!p) return false;
        var type = (b.getAttribute("type") || "").toLowerCase();
        if (p.form && b.form === p.form && type !== "button" && type !== "reset") return true;
        var txt = (b.innerText || b.value || b.getAttribute("aria-label") || "").toLowerCase().trim();
        return /^(sign in|log in|login|log on|sign on|next|continue|submit)$/.test(txt);
    }

    loginNotifiedHref = "";
    function scanForLoginForms() {
        try {
            var passField = findPasswordField();
            var loginUserField = document.querySelector(
                'input[type="email"], input[autocomplete="username"], input[name="identifier"], input[autocomplete="current-password"]'
            );
            if (passField || (loginUserField && isVisible(loginUserField))) {
                if (loginNotifiedHref !== location.href) {
                    loginNotifiedHref = location.href;
                    send({
                        kind: "login_form_detected",
                        origin: location.origin
                    });
                }
            }
        } catch (_) {}
    }
    document.addEventListener("focusin", function(e) {
        if (e.target && e.target.tagName === "INPUT") {
            scanForLoginForms();
        }
    }, true);
    window.addEventListener("DOMContentLoaded", function() {
        setTimeout(scanForLoginForms, 300);
        setTimeout(applyMediaFxToAllVideos, 350);
    });
    window.addEventListener("load", function() {
        setTimeout(scanForLoginForms, 500);
        setTimeout(applyMediaFxToAllVideos, 500);
    });

    function setNativeInputValue(el, val) {
        if (!el) return;
        el.focus();
        var proto = Object.getPrototypeOf(el);
        var desc = Object.getOwnPropertyDescriptor(proto, "value") ||
                   Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value");
        if (desc && desc.set) {
            desc.set.call(el, val);
        } else {
            el.value = val;
        }
        el.dispatchEvent(new Event("input", { bubbles: true }));
        el.dispatchEvent(new Event("change", { bubbles: true }));
    }

    function clickSubmitForInput(inputEl) {
        if (!inputEl) return;
        if (inputEl.form) {
            var submitBtn = inputEl.form.querySelector('button[type="submit"], input[type="submit"], button:not([type="button"])');
            if (submitBtn && isVisible(submitBtn)) {
                submitBtn.click();
                return;
            }
            if (typeof inputEl.form.requestSubmit === "function") {
                inputEl.form.requestSubmit();
                return;
            }
            inputEl.form.submit();
            return;
        }
        var buttons = document.querySelectorAll('button, input[type="submit"], [role="button"]');
        for (var i = 0; i < buttons.length; i++) {
            var b = buttons[i];
            var txt = (b.innerText || b.value || "").toLowerCase().trim();
            if (isVisible(b) && (txt === "next" || txt === "sign in" || txt === "log in" || txt === "login" || txt === "continue" || txt === "submit")) {
                b.click();
                return;
            }
        }
    }

    // Locked (non-writable, non-configurable) before any page script runs, so a page cannot swap
    // in its own function to receive the credential. The host passes the origin it verified; if
    // the document navigated in between, nothing is filled.
    var rcAutofill = function(expectedOrigin, username, password, autoSubmit) {
        if (location.origin !== expectedOrigin) { password = ""; return; }
        try {
            var targetPass = findPasswordField();
            if (targetPass) {
                var uField = findUserField(targetPass.form || document);
                if (uField && username) {
                    setNativeInputValue(uField, username);
                }
                setNativeInputValue(targetPass, password);
                lastSubmittedHash = location.origin + "|" + (username || "user") + "|" + password;
                if (autoSubmit) {
                    setTimeout(function() {
                        clickSubmitForInput(targetPass);
                    }, 200);
                }
            } else {
                var uOnly = findUserField(document);
                if (uOnly && username) {
                    setNativeInputValue(uOnly, username);
                    if (autoSubmit) {
                        setTimeout(function() {
                            clickSubmitForInput(uOnly);
                        }, 200);
                        var attempts = 0;
                        var step2Timer = setInterval(function() {
                            attempts++;
                            var p2 = findPasswordField();
                            if (p2) {
                                clearInterval(step2Timer);
                                setNativeInputValue(p2, password);
                                lastSubmittedHash = location.origin + "|" + username + "|" + password;
                                setTimeout(function() {
                                    clickSubmitForInput(p2);
                                    password = "";
                                }, 250);
                            } else if (attempts > 25) {
                                clearInterval(step2Timer);
                                password = "";
                            }
                        }, 400);
                    }
                }
            }
        } catch (_) {}
    };

    function pauseMedia() {
        document.querySelectorAll("video,audio").forEach(function(m) {
            try { if (!m.paused) { pausedByTab.add(m); m.pause(); } } catch (_) {}
        });
    }
    function resumeMedia() {
        document.querySelectorAll("video,audio").forEach(function(m) {
            try {
                if (pausedByTab.has(m)) { pausedByTab.delete(m); m.play().catch(function(){}); }
            } catch (_) {}
        });
    }

    // Messages from the browser (WebView2 PostWebMessageAsJson). Nothing here is reachable from
    // page scripts except by posting their own messages, which can only affect their own page.
    try {
        window.chrome.webview.addEventListener("message", function(e) {
            var m = e.data;
            if (!m || typeof m !== "object") return;
            if (m.t === "fx") applyFx(m.cfg);
            else if (m.t === "fs") setBrowserFullscreen(!!m.on);
            else if (m.t === "bg") {
                allowBg = !!m.allow;
                if (m.pause) pauseMedia();
                if (m.resume) resumeMedia();
            } else if (m.t === "fill") {
                rcAutofill(m.origin, m.user, m.pass, !!m.auto);
                m.pass = "";
            }
        });
    } catch (_) {}

    window.addEventListener("error", function(e) {
        send({
            kind: "console_error",
            message: "Uncaught Error: " + (e.message || "script error") + " at " + (e.filename || "") + ":" + (e.lineno || 0)
        });
    });
    window.addEventListener("securitypolicyviolation", function(e) {
        send({
            kind: "csp",
            message: "CSP violation: blocked " + String(e.blockedURI || "inline").split(/[?#]/)[0] + " on " + (e.violatedDirective || "directive")
        });
    });
})();
"###;

/// Flood-fills exterior near-black background pixels (`max(R,G,B) <= 22`) connected to the image
/// border so the Oya baby-buffalo mascot renders with a clean transparent silhouette on the
/// Windows Taskbar and in the futuristic browser header while preserving all dark interior features
/// (eyes, hooves, nostrils).
fn cutout_exterior_black_rgba(rgba: &mut image::RgbaImage) {
    let (w, h) = rgba.dimensions();
    if w == 0 || h == 0 {
        return;
    }
    let total = (w * h) as usize;
    let mut visited = vec![false; total];
    let mut queue = std::collections::VecDeque::with_capacity((w * 2 + h * 2) as usize);

    let is_border_black = |px: &image::Rgba<u8>| -> bool {
        px[0].max(px[1]).max(px[2]) <= 22
    };

    for x in 0..w {
        for &y in &[0, h - 1] {
            let idx = (y * w + x) as usize;
            if !visited[idx] && is_border_black(rgba.get_pixel(x, y)) {
                visited[idx] = true;
                queue.push_back((x, y));
            }
        }
    }
    for y in 0..h {
        for &x in &[0, w - 1] {
            let idx = (y * w + x) as usize;
            if !visited[idx] && is_border_black(rgba.get_pixel(x, y)) {
                visited[idx] = true;
                queue.push_back((x, y));
            }
        }
    }

    while let Some((x, y)) = queue.pop_front() {
        rgba.put_pixel(x, y, image::Rgba([0, 0, 0, 0]));
        let neighbors = [
            (x.wrapping_sub(1), y),
            (x + 1, y),
            (x, y.wrapping_sub(1)),
            (x, y + 1),
        ];
        for (nx, ny) in neighbors {
            if nx < w && ny < h {
                let nidx = (ny * w + nx) as usize;
                if !visited[nidx] {
                    let p = rgba.get_pixel(nx, ny);
                    if is_border_black(p) {
                        visited[nidx] = true;
                        queue.push_back((nx, ny));
                    } else if p[0].max(p[1]).max(p[2]) <= 40 {
                        // Soft anti-aliased edge feathering
                        let mut feathered = *p;
                        feathered[3] = 160;
                        rgba.put_pixel(nx, ny, feathered);
                    }
                }
            }
        }
    }
}

/// Fast decoding of the Oya Browser logo (`assets/oya_logo.jpg`) using `FilterType::Triangle`
/// and exterior alpha cutout so the Windows Taskbar and window titlebar show the new mascot cleanly.
pub fn load_oya_window_icon() -> Option<egui::IconData> {
    let img = image::load_from_memory(OYA_LOGO_BYTES).ok()?;
    let resized = img.resize_exact(64, 64, image::imageops::FilterType::Triangle);
    let mut rgba = resized.to_rgba8();
    cutout_exterior_black_rgba(&mut rgba);
    let (width, height) = rgba.dimensions();
    Some(egui::IconData {
        rgba: rgba.into_raw(),
        width,
        height,
    })
}

enum WebViewEvent {
    UrlChanged {
        tab_id: u64,
        url: String,
        title: String,
    },
    TitleChanged {
        tab_id: u64,
        title: String,
    },
    FullscreenChanged {
        tab_id: u64,
        fullscreen: bool,
    },
    ToggleFullscreen {
        tab_id: u64,
    },
    ConsoleLog {
        tab_id: u64,
        message: String,
    },
    ConsoleError {
        tab_id: u64,
        message: String,
    },
    CspViolation {
        tab_id: u64,
        message: String,
    },
    LoginFormDetected {
        tab_id: u64,
        origin: String,
    },
    LoginSubmitted {
        tab_id: u64,
        origin: String,
        username: String,
        password: String,
    },
    /// Navigation committed (`true`) or finished (`false`); URL comes from WebView2 itself.
    LoadState {
        tab_id: u64,
        loading: bool,
        url: String,
    },
    /// `window.open` / `target=_blank`: opened as a normal tab instead of an unmanaged pop-up.
    OpenInNewTab {
        url: String,
    },
    /// HTTPS-First: the page tried to load an `http://` URL; load this `https://` URL instead.
    UpgradeToHttps {
        tab_id: u64,
        url: String,
    },
    NavigationBlocked {
        tab_id: u64,
        url: String,
    },
    /// A risky file type is waiting for the user's Keep/Discard decision.
    DownloadBlocked {
        tab_id: u64,
        url: String,
        file_name: String,
    },
    /// A download started and was allowed into WebView2.
    DownloadStarted {
        tab_id: u64,
        url: String,
        file_name: String,
        path: PathBuf,
        confirmed_risky: bool,
    },
    /// A WebView2 download finished (successfully or not).
    DownloadCompleted {
        url: String,
        path: Option<PathBuf>,
        succeeded: bool,
    },
    /// A page received keyboard focus (the user clicked into it).
    WebViewFocused {
        tab_id: u64,
    },
    /// Result of checking that a page's full-screen request came from a real user gesture.
    FullscreenVerified {
        tab_id: u64,
        ok: bool,
    },
}

/// Menus drawn in their own small borderless OS window, so they float above the WebView2 page
/// (an egui popup inside the main window would be hidden behind the native page surface).
#[derive(Clone, Copy, PartialEq)]
enum OverlayKind {
    MainMenu,
    PaneMenu,
    Downloads,
    TabMenu(u64),
    SiteInfo,
}

#[derive(Clone, Copy)]
struct Overlay {
    kind: OverlayKind,
    /// Top-left corner in screen points.
    pos: egui::Pos2,
    width: f32,
    opened_at: Instant,
}

/// Non-intrusive top bar shown AFTER the user logs in manually on a site,
/// offering to encrypt & save their credentials into the Vault.
#[derive(Clone)]
struct PendingSaveOffer {
    origin: String,
    username: String,
    password: String,
}

/// Settings page sections (left navigation of `oya://settings`).
#[derive(Clone, Copy, PartialEq, Eq)]
enum OptionsSection {
    YouAndOya,
    AutofillAndPasswords,
    PrivacyAndSecurity,
    Performance,
    Appearance,
    SearchEngine,
    OnStartup,
    Languages,
    Downloads,
    SystemAndDeveloper,
    ResetSettings,
    AboutOya,
}

impl OptionsSection {
    fn all() -> &'static [OptionsSection] {
        &[
            OptionsSection::YouAndOya,
            OptionsSection::AutofillAndPasswords,
            OptionsSection::PrivacyAndSecurity,
            OptionsSection::Performance,
            OptionsSection::Appearance,
            OptionsSection::SearchEngine,
            OptionsSection::OnStartup,
            OptionsSection::Languages,
            OptionsSection::Downloads,
            OptionsSection::SystemAndDeveloper,
            OptionsSection::ResetSettings,
            OptionsSection::AboutOya,
        ]
    }

    fn label(&self) -> &'static str {
        match self {
            OptionsSection::YouAndOya => "Bookmarks and import",
            OptionsSection::AutofillAndPasswords => "Passwords and autofill",
            OptionsSection::PrivacyAndSecurity => "Privacy and security",
            OptionsSection::Performance => "Performance and media",
            OptionsSection::Appearance => "Appearance",
            OptionsSection::SearchEngine => "Search engine",
            OptionsSection::OnStartup => "On startup",
            OptionsSection::Languages => "Languages",
            OptionsSection::Downloads => "Downloads",
            OptionsSection::SystemAndDeveloper => "System and developer",
            OptionsSection::ResetSettings => "Reset settings",
            OptionsSection::AboutOya => "About Oya",
        }
    }

    /// Words matched by the settings search box.
    fn keywords(&self) -> &'static str {
        match self {
            OptionsSection::YouAndOya => "bookmarks import chrome edge firefox folders favorites",
            OptionsSection::AutofillAndPasswords => {
                "autofill passwords passkeys windows hello pin vault encryption login sign in"
            }
            OptionsSection::PrivacyAndSecurity => {
                "privacy security cookies trackers https gpc do not track clear browsing data sandbox"
            }
            OptionsSection::Performance => {
                "performance memory saver background media audio video equalizer eq upscaler 4k"
            }
            OptionsSection::Appearance => {
                "appearance theme day night dark light font size zoom home button bookmarks bar"
            }
            OptionsSection::SearchEngine => "search engine address bar google duckduckgo bing brave",
            OptionsSection::OnStartup => "on startup new tab specific page",
            OptionsSection::Languages => "languages language locale",
            OptionsSection::Downloads => "downloads location save folder",
            OptionsSection::SystemAndDeveloper => {
                "system developer logs console javascript processes hardware acceleration gpu"
            }
            OptionsSection::ResetSettings => "reset settings restore defaults",
            OptionsSection::AboutOya => "about oya browser version",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DevToolsTab {
    LogsAndLowLevel,
    Console,
    Processes,
}

struct TabWebView {
    webview: WebView,
    loaded_url: String,
    visible: bool,
    last_bounds: (i32, i32, u32, u32, bool),
    media_paused_in_bg: bool,
    last_allow_bg_synced: Option<bool>,
    last_fx_hash: u64,
    last_zoom_pct: u32,
    last_tracking_strict: Option<bool>,
    last_dark_mode: Option<bool>,
    low_memory: bool,
    /// When the tab was last moved out of the foreground (Memory Saver discards it after a while).
    hidden_since: Option<Instant>,
}

/// Background tabs hidden longer than this are discarded by Memory Saver (reloaded on return).
const MEMORY_SAVER_DISCARD_AFTER: Duration = Duration::from_secs(15 * 60);

pub struct RustChromeApp {
    // IMPORTANT: `webviews` MUST be declared BEFORE `_web_context` so all `WebView` instances drop before `WebContext`!
    webviews: HashMap<u64, TabWebView>,
    _web_context: Option<WebContext>,
    controller: BrowserController,
    vault: SecurityVault,
    address_bar: String,
    last_synced_url: String,
    addr_editing: bool,
    focus_address_bar: bool,
    show_media_fx_bar: bool,
    options_section: OptionsSection,
    options_search_query: String,
    overlay: Option<Overlay>,
    loading_tabs: HashSet<u64>,
    /// Shared with each WebView's navigation handler so HTTPS-First applies immediately.
    https_first: Arc<AtomicBool>,
    fonts_installed: bool,
    overlay_height: f32,
    last_active_tab_id: Option<u64>,
    select_all_address: bool,
    pending_fullscreen: bool,
    settings_status: String,
    // Security state (see gui_security.rs)
    task_tx: Sender<TaskResult>,
    task_rx: Receiver<TaskResult>,
    busy: Option<String>,
    approval: Option<security::PendingApproval>,
    startup: crate::StartupSecurity,
    dismissed_location_warning: bool,
    dismissed_override_notice: bool,
    webview_blocked: Option<String>,
    cdp_handle: Option<rc_cdp::CdpServerHandle>,
    outside_changes: Vec<crate::integrity::TamperReport>,
    staged: StagedText,
    approved_downloads: Rc<RefCell<HashSet<String>>>,
    pending_downloads: Vec<BlockedDownload>,
    downloads: crate::downloads::DownloadStore,
    pending_open_download_id: Option<u64>,
    download_alert_id: Option<u64>,
    unseen_download_badge: bool,
    allow_notifications: Arc<AtomicBool>,
    permission_list: PermissionSink,
    last_lock_poll: Instant,
    last_wall_clock: std::time::SystemTime,
    fullscreen_notice: Option<(String, Instant)>,
    panes: panes::Panes,
    popup_times: Vec<Instant>,
    is_fullscreen: bool,
    fs_sync_frames: u8,
    last_style_key: Option<(ThemeMode, UiFontFamily, u32)>,
    last_dwm_dark: Option<bool>,
    dwm_sync_frames: u8,
    last_window_title: String,
    pending_save_offer: Option<PendingSaveOffer>,
    active_validation_origin: Option<String>,
    validation_pin_input: String,
    validation_status_msg: String,
    save_offer_pin_input: String,
    save_offer_status_msg: String,
    vault_current_pin: String,
    // Vault form state inside Options -> Autofill and passwords
    vault_new_origin: String,
    vault_new_username: String,
    vault_new_password: String,
    vault_new_auto_submit: bool,
    vault_new_pin: String,
    vault_status_banner: String,
    // Bookmarks state inside Options -> You and Oya
    bookmark_search_query: String,
    bookmark_selected_folder: Option<String>,
    bookmark_new_folder_input: String,
    bookmark_new_description: String,
    editing_bookmark: Option<u64>,
    bookmark_new_title: String,
    bookmark_new_url: String,
    bookmark_target_folder: String,
    bookmark_import_file_path: String,
    bookmark_status_banner: String,
    // System & Developer state
    devtools_tab: DevToolsTab,
    log_filter_query: String,
    js_input: String,
    js_output: String,
    oya_logo_texture: Option<egui::TextureHandle>,
    textures: HashMap<u64, egui::TextureHandle>,
    cdp_rx: Option<Receiver<CdpRequest>>,
    wv_tx: Sender<WebViewEvent>,
    wv_rx: Receiver<WebViewEvent>,
}

impl Drop for RustChromeApp {
    fn drop(&mut self) {
        for (_, twv) in self.webviews.drain() {
            let _ = twv.webview.set_visible(false);
            drop(twv.webview);
        }
        write_emergency_event_to_disk(&DiagnosticEvent::new(
            Severity::LowLevel,
            LogCategory::Lifecycle,
            "browser-ui",
            std::process::id(),
            format!(
                "Oya Browser exited cleanly (active_tab_url={}, open_tabs={})",
                self.controller.tab().current_url,
                self.controller.tabs.len()
            ),
        ));
    }
}

impl RustChromeApp {
    pub fn new(initial_url: &str, startup: crate::StartupSecurity) -> Self {
        let mut app = Self::new_inner(initial_url);
        app.init_security(startup);
        app
    }

    fn new_inner(initial_url: &str) -> Self {
        let cdp_rx: Option<Receiver<CdpRequest>> = None;
        let mut controller = BrowserController::new_gui();
        controller
            .log_store
            .record_low_level("browser-init", "Initializing Oya Browser");
        let start_target = if initial_url == "rustchrome://newtab" || initial_url == "oya://newtab"
        {
            match controller.settings.startup_behavior {
                StartupBehavior::OpenNewTab | StartupBehavior::ContinueWhereLeftOff => {
                    controller.settings.blank_tab_url()
                }
                StartupBehavior::OpenSpecificUrl => {
                    let custom = controller.settings.startup_custom_url.trim().to_string();
                    if custom.is_empty() {
                        controller.settings.blank_tab_url()
                    } else {
                        custom
                    }
                }
            }
        } else {
            initial_url.to_string()
        };
        controller.navigate_or_record_error(&start_target, false);
        let current_url = controller.tab().current_url.clone();
        let current_origin = controller.tab().current_origin.clone();
        let current_title = controller.tab().title.clone();
        let (wv_tx, wv_rx) = mpsc::channel();
        let https_first = controller.settings.https_first_mode;
        let allow_notifications = controller.settings.allow_notifications;
        let (task_tx, task_rx) = mpsc::channel();
        Self {
            webviews: HashMap::new(),
            _web_context: None,
            controller,
            vault: SecurityVault::load_or_init(),
            address_bar: current_url.clone(),
            last_synced_url: current_url.clone(),
            addr_editing: false,
            focus_address_bar: false,
            show_media_fx_bar: false,
            options_section: OptionsSection::AutofillAndPasswords,
            options_search_query: String::new(),
            overlay: None,
            loading_tabs: HashSet::new(),
            https_first: Arc::new(AtomicBool::new(https_first)),
            fonts_installed: false,
            overlay_height: 0.0,
            last_active_tab_id: None,
            select_all_address: false,
            pending_fullscreen: false,
            settings_status: String::new(),
            task_tx,
            task_rx,
            busy: None,
            approval: None,
            startup: crate::StartupSecurity {
                hardening: Default::default(),
                webview2_overrides: Vec::new(),
                planted_dlls: Vec::new(),
                program_folder_writers: Vec::new(),
                profile_folder_writers: Vec::new(),
                debug_port: None,
            },
            dismissed_location_warning: false,
            dismissed_override_notice: false,
            webview_blocked: None,
            cdp_handle: None,
            outside_changes: Vec::new(),
            staged: StagedText::default(),
            approved_downloads: Rc::default(),
            pending_downloads: Vec::new(),
            downloads: crate::downloads::DownloadStore::load(),
            pending_open_download_id: None,
            download_alert_id: None,
            unseen_download_badge: false,
            allow_notifications: Arc::new(AtomicBool::new(allow_notifications)),
            permission_list: Arc::default(),
            last_lock_poll: Instant::now(),
            last_wall_clock: std::time::SystemTime::now(),
            fullscreen_notice: None,
            panes: panes::Panes::default(),
            popup_times: Vec::new(),
            is_fullscreen: false,
            fs_sync_frames: 0,
            last_style_key: None,
            last_dwm_dark: None,
            dwm_sync_frames: 6,
            last_window_title: String::new(),
            pending_save_offer: None,
            active_validation_origin: None,
            validation_pin_input: String::new(),
            validation_status_msg: String::new(),
            save_offer_pin_input: String::new(),
            save_offer_status_msg: String::new(),
            vault_current_pin: String::new(),
            vault_new_origin: current_origin,
            vault_new_username: String::new(),
            vault_new_password: String::new(),
            vault_new_auto_submit: true,
            vault_new_pin: String::new(),
            vault_status_banner: String::new(),
            bookmark_search_query: String::new(),
            bookmark_selected_folder: None,
            bookmark_new_folder_input: String::new(),
            bookmark_new_description: String::new(),
            editing_bookmark: None,
            bookmark_new_title: current_title,
            bookmark_new_url: current_url,
            bookmark_target_folder: "Bookmarks Bar".to_string(),
            bookmark_import_file_path: String::new(),
            bookmark_status_banner: String::new(),
            devtools_tab: DevToolsTab::LogsAndLowLevel,
            log_filter_query: String::new(),
            js_input: "document.title".to_string(),
            js_output: String::new(),
            oya_logo_texture: None,
            textures: HashMap::new(),
            cdp_rx,
            wv_tx,
            wv_rx,
        }
    }

    fn ensure_oya_logo_texture(&mut self, ctx: &egui::Context) {
        if self.oya_logo_texture.is_some() {
            return;
        }
        if let Ok(img) = image::load_from_memory(OYA_LOGO_BYTES) {
            let resized = img.resize_exact(96, 96, image::imageops::FilterType::Triangle);
            let mut rgba = resized.to_rgba8();
            cutout_exterior_black_rgba(&mut rgba);
            let (w, h) = rgba.dimensions();
            let color_img =
                egui::ColorImage::from_rgba_unmultiplied([w as usize, h as usize], rgba.as_raw());
            let tex = ctx.load_texture("oya-logo-tex", color_img, egui::TextureOptions::LINEAR);
            self.oya_logo_texture = Some(tex);
        }
    }

    fn sync_address_bar_from_tab(&mut self) {
        let cur = self.controller.tab().current_url.clone();
        self.address_bar = cur.clone();
        self.last_synced_url = cur.clone();
        self.addr_editing = false;
        let origin = self.controller.tab().current_origin.clone();
        // Pre-fill the "add" forms with the current site, but only for real web pages and never
        // while a bookmark is being edited.
        if cur.starts_with("https://") || cur.starts_with("http://") {
            self.vault_new_origin = if origin.starts_with("https://") { origin.clone() } else { String::new() };
            if self.editing_bookmark.is_none() {
                self.bookmark_new_url = cur;
                self.bookmark_new_title = self.controller.tab().title.clone();
            }
        }
        if !self.vault.has_credential_for_origin(&origin) {
            self.active_validation_origin = None;
        }
    }

    fn palette(&self) -> Palette {
        palette_for(self.controller.settings.theme_mode == ThemeMode::Night)
    }

    /// Uses the Windows UI font (Segoe UI) when present; egui's bundled fonts stay as fallback
    /// for any glyph Segoe UI lacks.
    fn install_system_fonts(&mut self, ctx: &egui::Context) {
        if self.fonts_installed {
            return;
        }
        self.fonts_installed = true;
        let windir = std::env::var_os("WINDIR").unwrap_or_else(|| "C:\\Windows".into());
        let fonts = PathBuf::from(windir).join("Fonts");
        let add = |name: &str, file: &str, family: egui::FontFamily| {
            if let Ok(bytes) = std::fs::read(fonts.join(file)) {
                ctx.add_font(egui::epaint::text::FontInsert {
                    name: name.to_string(),
                    data: egui::FontData::from_owned(bytes),
                    families: vec![egui::epaint::text::InsertFontFamily {
                        family,
                        priority: egui::epaint::text::FontPriority::Highest,
                    }],
                });
            }
        };
        add("segoe-ui", "segoeui.ttf", egui::FontFamily::Proportional);
        add("cascadia-mono", "CascadiaMono.ttf", egui::FontFamily::Monospace);
    }

    fn apply_theme_and_typography(&mut self, ctx: &egui::Context, parent_hwnd: isize) {
        self.install_system_fonts(ctx);
        let is_night = self.controller.settings.theme_mode == ThemeMode::Night;
        if parent_hwnd != 0 && (self.last_dwm_dark != Some(is_night) || self.dwm_sync_frames > 0) {
            rc_sandbox::set_window_dark_mode(parent_hwnd, is_night);
            if self.last_dwm_dark != Some(is_night) {
                self.last_dwm_dark = Some(is_night);
                self.dwm_sync_frames = 5;
            } else {
                self.dwm_sync_frames = self.dwm_sync_frames.saturating_sub(1);
            }
        }
        let style_key = (
            self.controller.settings.theme_mode,
            self.controller.settings.font_family,
            (self.controller.settings.font_size_pt * 10.0) as u32,
        );
        if self.last_style_key == Some(style_key) {
            return;
        }
        self.last_style_key = Some(style_key);
        let p = palette_for(is_night);
        let mut v = if is_night {
            egui::Visuals::dark()
        } else {
            egui::Visuals::light()
        };

        v.panel_fill = p.surface;
        v.window_fill = p.surface;
        v.extreme_bg_color = p.field;
        v.faint_bg_color = p.frame;
        v.code_bg_color = p.field;
        v.hyperlink_color = p.accent;
        v.error_fg_color = p.danger;
        v.warn_fg_color = p.warn;
        v.window_stroke = egui::Stroke::new(1.0, p.divider);
        v.window_corner_radius = egui::CornerRadius::same(12);
        v.menu_corner_radius = egui::CornerRadius::same(12);
        v.window_shadow = egui::Shadow::NONE;
        v.popup_shadow = egui::Shadow::NONE;
        // FIX (unreadable selected tabs/buttons): egui draws the text of every *selected* widget
        // with `selection.stroke`. It used to be `Stroke::NONE`, i.e. invisible text on blue.
        // Selected items now use a tonal fill with a high-contrast foreground (>= 7:1).
        v.selection.bg_fill = p.tonal;
        v.selection.stroke = egui::Stroke::new(1.0, p.on_tonal);

        let radius = egui::CornerRadius::same(8);
        let style_widget = |w: &mut egui::style::WidgetVisuals,
                            fill: egui::Color32,
                            stroke: egui::Stroke,
                            fg: egui::Color32| {
            w.bg_fill = fill;
            w.weak_bg_fill = fill;
            w.bg_stroke = stroke;
            w.fg_stroke = egui::Stroke::new(1.0, fg);
            w.corner_radius = radius;
            w.expansion = 0.0;
        };
        let hairline = egui::Stroke::new(1.0, p.divider);
        style_widget(&mut v.widgets.noninteractive, p.surface, hairline, p.text);
        style_widget(&mut v.widgets.inactive, p.control, hairline, p.text);
        style_widget(&mut v.widgets.hovered, p.control_hover, hairline, p.text);
        style_widget(&mut v.widgets.active, p.tonal, egui::Stroke::NONE, p.on_tonal);
        style_widget(&mut v.widgets.open, p.control_hover, hairline, p.text);
        ctx.set_visuals(v);

        let base_pt = self.controller.settings.font_size_pt.clamp(11.0, 22.0);
        let family = match self.controller.settings.font_family {
            UiFontFamily::SystemProportional | UiFontFamily::ModernReadable => {
                egui::FontFamily::Proportional
            }
            UiFontFamily::MonospaceCode => egui::FontFamily::Monospace,
        };

        ctx.all_styles_mut(|style| {
            style.spacing.button_padding = egui::vec2(12.0, 6.0);
            style.spacing.item_spacing = egui::vec2(8.0, 6.0);
            style.spacing.interact_size.y = 28.0;
            style.spacing.text_edit_width = 260.0;
            style.spacing.menu_margin = egui::Margin::same(6);
            style.text_styles.insert(
                egui::TextStyle::Small,
                egui::FontId::new((base_pt - 2.0).max(10.0), family.clone()),
            );
            style
                .text_styles
                .insert(egui::TextStyle::Body, egui::FontId::new(base_pt, family.clone()));
            style.text_styles.insert(
                egui::TextStyle::Button,
                egui::FontId::new(base_pt, family.clone()),
            );
            style.text_styles.insert(
                egui::TextStyle::Heading,
                egui::FontId::new(base_pt + 7.0, family.clone()),
            );
            style.text_styles.insert(
                egui::TextStyle::Monospace,
                egui::FontId::new((base_pt - 1.0).max(10.0), egui::FontFamily::Monospace),
            );
        });
    }

    fn set_fullscreen_state(
        &mut self,
        ctx: &egui::Context,
        parent_hwnd: isize,
        target_fs: bool,
    ) {
        self.fs_sync_frames = 15;
        if self.is_fullscreen == target_fs {
            if !target_fs {
                for twv in self.webviews.values_mut() {
                    twv.last_bounds = (0, 0, 0, 0, false);
                }
                ctx.request_repaint();
            }
            return;
        }
        self.is_fullscreen = target_fs;
        if target_fs {
            self.overlay = None;
            self.show_media_fx_bar = false;
            let url = self.controller.tab().current_url.clone();
            self.fullscreen_notice = Some((host_of(&url), Instant::now()));
        }
        self.controller.log_store.record_low_level(
            "window-fullscreen",
            format!("Transitioned fullscreen state to fullscreen={target_fs}"),
        );

        // Apply true monitor-spanning Win32 borderless fullscreen (`rcMonitor`)
        let _ = set_win32_fullscreen(parent_hwnd, target_fs);
        // Only Oya's Win32 code changes the window here. Also sending egui's own Fullscreen /
        // Decorations commands made two mechanisms fight over the window, which could leave it
        // still "maximized" with a strip of frame below the page.
        ctx.request_repaint();

        // Force bounds recalculation and expand/restore HTML5 video container to fill 100% of screen
        let active_id = self.controller.tab().id;
        for (&tid, twv) in self.webviews.iter_mut() {
            twv.last_bounds = (0, 0, 0, 0, false);
            if tid == active_id {
                post_to_page(&twv.webview, &serde_json::json!({ "t": "fs", "on": target_fs }));
            }
        }
    }

    fn compute_fx_hash(&self) -> u64 {
        let s = &self.controller.settings;
        let mut h: u64 = 1469598103934665603;
        h = (h ^ (s.eq_enabled as u64)).wrapping_mul(1099511628211);
        h = (h ^ ((s.eq_preamp_db * 10.0) as i32 as u64)).wrapping_mul(1099511628211);
        for &b in &s.eq_bands_db {
            h = (h ^ ((b * 10.0) as i32 as u64)).wrapping_mul(1099511628211);
        }
        h = (h ^ (s.upscaler_mode as u64)).wrapping_mul(1099511628211);
        h = (h ^ ((s.upscaler_sharpness * 10.0) as u64)).wrapping_mul(1099511628211);
        h = (h ^ ((s.upscaler_vibrance * 10.0) as u64)).wrapping_mul(1099511628211);
        h = (h ^ (s.optimize_4k_playback as u64)).wrapping_mul(1099511628211);
        h
    }

    fn build_fx_message(&self) -> serde_json::Value {
        let s = &self.controller.settings;
        serde_json::json!({
            "t": "fx",
            "cfg": {
                "eqEnabled": s.eq_enabled,
                "preampDb": s.eq_preamp_db,
                "bandsDb": s.eq_bands_db,
                "upscaleMode": s.upscaler_mode.code(),
                "sharpness": s.upscaler_sharpness,
                "vibrance": s.upscaler_vibrance,
                "optimize4k": s.optimize_4k_playback,
            }
        })
    }

    fn ensure_tab_webview(
        &mut self,
        tab_id: u64,
        initial_url: &str,
        frame: &mut eframe::Frame,
        egui_ctx: &egui::Context,
        initial_rect: egui::Rect,
    ) {
        if self.webviews.contains_key(&tab_id) {
            return;
        }

        if self.webview_blocked.is_some() {
            return;
        }

        let Ok(win_handle) = frame.window_handle() else {
            self.controller.log_store.record(DiagnosticEvent::new(
                Severity::Error,
                LogCategory::LowLevel,
                "webview-init",
                std::process::id(),
                "Failed to acquire parent OS window handle for child WebView",
            ));
            return;
        };

        if self._web_context.is_none() {
            // %LOCALAPPDATA%\OyaBrowser\WebView2 (absolute), unless main() found an existing profile
            // from an older build to keep using.
            let data_dir = crate::webview2_profile_dir();
            let _ = std::fs::create_dir_all(&data_dir);
            self._web_context = Some(WebContext::new(Some(data_dir)));
        }
        let browser_args = webview2_browser_args(&self.controller.settings);
        let gpc_script = if self.controller.settings.do_not_track {
            GPC_SCRIPT
        } else {
            ""
        };
        let download_dir = self.controller.settings.download_directory.clone();
        let tx_dl_done = self.wv_tx.clone();
        let ctx_dl_done = egui_ctx.clone();
        let approved_downloads = Rc::clone(&self.approved_downloads);
        let tx_dl = self.wv_tx.clone();
        let ctx_dl = egui_ctx.clone();
        let allow_notifications = Arc::clone(&self.allow_notifications);
        let Some(web_ctx) = self._web_context.as_mut() else {
            return;
        };

        let tx_ipc = self.wv_tx.clone();
        let tx_title = self.wv_tx.clone();
        let tx_nav = self.wv_tx.clone();
        let tx_load = self.wv_tx.clone();
        let tx_popup = self.wv_tx.clone();
        let ctx_ipc = egui_ctx.clone();
        let ctx_title = egui_ctx.clone();
        let ctx_nav = egui_ctx.clone();
        let ctx_load = egui_ctx.clone();
        let ctx_popup = egui_ctx.clone();
        let https_first = Arc::clone(&self.https_first);
        // Hosts recently upgraded to HTTPS; if such a host sends us straight back to http://
        // (it has no working HTTPS), the second attempt is allowed instead of looping.
        let upgraded_hosts: Rc<RefCell<HashMap<String, Instant>>> = Rc::default();

        let initial_web_url =
            if initial_url.starts_with("https://") || initial_url.starts_with("http://") {
                initial_url.to_string()
            } else {
                self.controller.settings.blank_tab_url()
            };

        let bounds = WryRect {
            position: Position::Logical(LogicalPosition::new(
                initial_rect.min.x as f64,
                initial_rect.min.y as f64,
            )),
            size: Size::Logical(LogicalSize::new(
                initial_rect.width().max(100.0) as f64,
                initial_rect.height().max(100.0) as f64,
            )),
        };

        let builder = WebViewBuilder::new_with_web_context(web_ctx)
            .with_url(&initial_web_url)
            .with_user_agent(CHROME_USER_AGENT)
            .with_bounds(bounds)
            .with_autoplay(true)
            // Oya's own vault handles passwords; keep WebView2 from storing form data itself.
            .with_general_autofill_enabled(false)
            .with_initialization_script_for_main_only(WEBVIEW_DIAG_BRIDGE, true)
            .with_initialization_script_for_main_only(gpc_script, false)
            .with_additional_browser_args(browser_args)
            .with_document_title_changed_handler(move |title| {
                let _ = tx_title.send(WebViewEvent::TitleChanged { tab_id, title });
                ctx_title.request_repaint();
            })
            .with_navigation_handler(move |url| {
                let decision = classify_navigation(&url);
                match decision {
                    NavDecision::Allow => true,
                    NavDecision::Http(host) => {
                        if !https_first.load(Ordering::Relaxed) || is_local_host(&host) {
                            return true;
                        }
                        let mut recent = upgraded_hosts.borrow_mut();
                        recent.retain(|_, t| t.elapsed() < Duration::from_secs(20));
                        if recent.contains_key(&host) {
                            return true;
                        }
                        recent.insert(host, Instant::now());
                        let https = format!("https://{}", &url["http://".len()..]);
                        let _ = tx_nav.send(WebViewEvent::UpgradeToHttps { tab_id, url: https });
                        ctx_nav.request_repaint();
                        false
                    }
                    NavDecision::Block => {
                        let _ = tx_nav.send(WebViewEvent::NavigationBlocked { tab_id, url });
                        ctx_nav.request_repaint();
                        false
                    }
                }
            })
            // The address bar follows only navigations WebView2 has committed, never a page
            // message or a navigation that has merely started.
            .with_on_page_load_handler(move |event, url| {
                let loading = matches!(event, PageLoadEvent::Started);
                let _ = tx_load.send(WebViewEvent::LoadState {
                    tab_id,
                    loading,
                    url,
                });
                ctx_load.request_repaint();
            })
            // Pop-ups become normal tabs (with an address bar) instead of chrome-less windows.
            .with_new_window_req_handler(move |url, _features| {
                if url.starts_with("https://") || url.starts_with("http://") {
                    let _ = tx_popup.send(WebViewEvent::OpenInNewTab { url });
                    ctx_popup.request_repaint();
                }
                NewWindowResponse::Deny
            })
            // Notifications are refused unless the user enabled them; everything else uses
            // WebView2's own prompt.
            .with_permission_handler(move |kind| {
                if matches!(kind, PermissionKind::Notifications)
                    && !allow_notifications.load(Ordering::Relaxed)
                {
                    PermissionResponse::Deny
                } else {
                    PermissionResponse::Default
                }
            })
            .with_download_started_handler(move |url, path| {
                let file_name = path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                let was_approved = approved_downloads.borrow_mut().remove(&url);
                // Programs and scripts wait for the user's decision (approved URLs pass once).
                if is_risky_download(&file_name) && !was_approved {
                    let _ = tx_dl.send(WebViewEvent::DownloadBlocked {
                        tab_id,
                        url,
                        file_name,
                    });
                    ctx_dl.request_repaint();
                    return false;
                }
                let dir = PathBuf::from(download_dir.trim());
                if dir.is_absolute()
                    && dir.is_dir()
                    && let Some(name) = path.file_name()
                {
                    *path = dir.join(name);
                }
                let _ = tx_dl.send(WebViewEvent::DownloadStarted {
                    tab_id,
                    url,
                    file_name,
                    path: path.clone(),
                    confirmed_risky: was_approved,
                });
                ctx_dl.request_repaint();
                true
            })
            .with_download_completed_handler(move |url, path, succeeded| {
                let _ = tx_dl_done.send(WebViewEvent::DownloadCompleted {
                    url,
                    path,
                    succeeded,
                });
                ctx_dl_done.request_repaint();
            })
            .with_ipc_handler(move |req| {
                let body = req.body();
                // SECURITY: the message body is written by the page and must never be trusted for
                // identity. The request URI is filled in by WebView2 with the real URL of the
                // document that sent the message, so URL and origin are taken from there only.
                let source_url = req.uri().to_string();
                let source_origin = if source_url.starts_with("https://")
                    || source_url.starts_with("http://")
                {
                    validate_and_extract_origin(&source_url)
                        .map(|o| o.to_string())
                        .ok()
                        .filter(|o| o != "null")
                } else {
                    None
                };
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(body) {
                    let kind = val.get("kind").and_then(|v| v.as_str()).unwrap_or("");
                    match kind {
                        "url" => {
                            if source_origin.is_some() {
                                let t = val
                                    .get("title")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .to_string();
                                let _ = tx_ipc.send(WebViewEvent::UrlChanged {
                                    tab_id,
                                    url: source_url.clone(),
                                    title: t,
                                });
                                ctx_ipc.request_repaint();
                            }
                        }
                        "fullscreen" => {
                            let is_fs = val
                                .get("fullscreen")
                                .and_then(|v| v.as_bool())
                                .unwrap_or(false);
                            let _ = tx_ipc.send(WebViewEvent::FullscreenChanged {
                                tab_id,
                                fullscreen: is_fs,
                            });
                            ctx_ipc.request_repaint();
                        }
                        "toggle_fullscreen" => {
                            let _ = tx_ipc.send(WebViewEvent::ToggleFullscreen { tab_id });
                            ctx_ipc.request_repaint();
                        }
                        "login_form_detected" => {
                            if let Some(origin) = source_origin.clone() {
                                let _ = tx_ipc
                                    .send(WebViewEvent::LoginFormDetected { tab_id, origin });
                                ctx_ipc.request_repaint();
                            }
                        }
                        "login_submitted" => {
                            let origin = source_origin.clone().unwrap_or_default();
                            let username = val
                                .get("username")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            let password = val
                                .get("password")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            if !origin.is_empty() && !password.is_empty() {
                                let _ = tx_ipc.send(WebViewEvent::LoginSubmitted {
                                    tab_id,
                                    origin,
                                    username,
                                    password,
                                });
                                ctx_ipc.request_repaint();
                            }
                        }
                        "console_log" => {
                            if let Some(m) = val.get("message").and_then(|v| v.as_str()) {
                                let _ = tx_ipc.send(WebViewEvent::ConsoleLog {
                                    tab_id,
                                    message: m.to_string(),
                                });
                                ctx_ipc.request_repaint();
                            }
                        }
                        "console_error" => {
                            if let Some(m) = val.get("message").and_then(|v| v.as_str()) {
                                let _ = tx_ipc.send(WebViewEvent::ConsoleError {
                                    tab_id,
                                    message: m.to_string(),
                                });
                                ctx_ipc.request_repaint();
                            }
                        }
                        "csp" => {
                            if let Some(m) = val.get("message").and_then(|v| v.as_str()) {
                                let _ = tx_ipc.send(WebViewEvent::CspViolation {
                                    tab_id,
                                    message: m.to_string(),
                                });
                                ctx_ipc.request_repaint();
                            }
                        }
                        _ => {}
                    }
                }
            });

        match builder.build_as_child(&win_handle) {
            Ok(wv) => {
                self.controller.log_store.record_low_level(
                    "webview-init",
                    format!("Child WebView2 created for tab_id={tab_id}"),
                );
                {
                    // Clicking into a page focuses its pane.
                    let tx_focus = self.wv_tx.clone();
                    let ctx_focus = egui_ctx.clone();
                    let handler = webview2_com::FocusChangedEventHandler::create(Box::new(
                        move |_, _| {
                            let _ = tx_focus.send(WebViewEvent::WebViewFocused { tab_id });
                            ctx_focus.request_repaint();
                            Ok(())
                        },
                    ));
                    let mut token = 0i64;
                    // SAFETY: COM call on the UI thread that owns this WebView2 controller.
                    unsafe {
                        let _ = wv.controller().add_GotFocus(&handler, &mut token);
                    }
                }
                if let Err(e) = enforce_smartscreen(&wv) {
                    self.controller.log_store.record_low_level(
                        "webview-security",
                        format!("Could not confirm SmartScreen is on: {e}"),
                    );
                }
                self.webviews.insert(
                    tab_id,
                    TabWebView {
                        webview: wv,
                        loaded_url: initial_web_url,
                        visible: true,
                        last_bounds: (0, 0, 0, 0, false),
                        media_paused_in_bg: false,
                        last_allow_bg_synced: None,
                        last_fx_hash: 0,
                        last_zoom_pct: 100,
                        last_tracking_strict: None,
                        last_dark_mode: None,
                        low_memory: false,
                        hidden_since: None,
                    },
                );
            }
            Err(err) => {
                self.controller.log_store.record(DiagnosticEvent::new(
                    Severity::Error,
                    LogCategory::LowLevel,
                    "webview-init",
                    std::process::id(),
                    format!("Child WebView initialization failed for tab {tab_id}: {err}"),
                ));
            }
        }
    }

    fn sync_all_tab_webviews(
        &mut self,
        frame: &mut eframe::Frame,
        egui_ctx: &egui::Context,
        parent_hwnd: isize,
        viewport_rect: egui::Rect,
        screen_rect: egui::Rect,
    ) {
        let open_ids: HashSet<u64> = self.controller.tabs.iter().map(|t| t.id).collect();
        self.webviews.retain(|id, twv| {
            let keep = open_ids.contains(id);
            if !keep {
                let _ = twv.webview.set_visible(false);
            }
            keep
        });

        let active_tab_id = self.controller.tab().id;
        let active_url = self.controller.tab().current_url.clone();
        let active_is_web =
            active_url.starts_with("https://") || active_url.starts_with("http://");

        // With no multi-window support the overlay menus would be drawn under the page, so the
        // page is hidden while one is open.
        let overlay_needs_space = self.overlay.is_some() && egui_ctx.embed_viewports();

        // Where each visible web page goes: one page, or one per pane.
        let placements: HashMap<u64, egui::Rect> = if self.panes.is_multi() && !self.is_fullscreen {
            self.panes.web_bodies.clone()
        } else if active_is_web {
            HashMap::from([(active_tab_id, viewport_rect)])
        } else {
            HashMap::new()
        };
        let mut to_create: Vec<(u64, String, egui::Rect)> = Vec::new();
        for (id, rect) in &placements {
            if let Some(t) = self.controller.tabs.iter().find(|t| t.id == *id) {
                to_create.push((*id, t.current_url.clone(), *rect));
            }
        }
        for (id, url, rect) in to_create {
            self.ensure_tab_webview(id, &url, frame, egui_ctx, rect);
        }
        self.https_first
            .store(self.controller.settings.https_first_mode, Ordering::Relaxed);
        self.allow_notifications
            .store(self.controller.settings.allow_notifications, Ordering::Relaxed);
        let zoom_pct = self.controller.settings.page_zoom_pct.clamp(25, 500);
        let tracking_strict = self.controller.settings.block_third_party_cookies;
        let memory_saver = self.controller.settings.memory_saver_enabled;

        let force_resync_bounds = if self.fs_sync_frames > 0 {
            self.fs_sync_frames -= 1;
            egui_ctx.request_repaint();
            true
        } else {
            false
        };


        let fx_hash = self.compute_fx_hash();
        let fx_message = self.build_fx_message();

        let tab_configs: Vec<(u64, String, bool)> = self
            .controller
            .tabs
            .iter()
            .map(|t| (t.id, t.current_url.clone(), t.allow_in_background))
            .collect();

        for (tab_id, tab_url, allow_bg) in tab_configs {
            let Some(twv) = self.webviews.get_mut(&tab_id) else {
                continue;
            };

            if force_resync_bounds {
                twv.last_bounds = (0, 0, 0, 0, false);
            }

            if twv.last_allow_bg_synced != Some(allow_bg) {
                twv.last_allow_bg_synced = Some(allow_bg);
                post_to_page(&twv.webview, &serde_json::json!({ "t": "bg", "allow": allow_bg }));
            }

            if twv.last_fx_hash != fx_hash {
                twv.last_fx_hash = fx_hash;
                post_to_page(&twv.webview, &fx_message);
            }
            if twv.last_zoom_pct != zoom_pct {
                twv.last_zoom_pct = zoom_pct;
                let _ = twv.webview.zoom(zoom_pct as f64 / 100.0);
            }
            if twv.last_tracking_strict != Some(tracking_strict) {
                twv.last_tracking_strict = Some(tracking_strict);
                if let Err(e) = set_tracking_prevention(&twv.webview, tracking_strict) {
                    self.controller.log_store.record_low_level(
                        "webview-privacy",
                        format!("Tracking prevention could not be set: {e}"),
                    );
                }
            }
            let is_night = self.controller.settings.theme_mode == ThemeMode::Night;
            if twv.last_dark_mode != Some(is_night) {
                twv.last_dark_mode = Some(is_night);
                if let Err(e) = set_preferred_color_scheme(&twv.webview, is_night) {
                    self.controller.log_store.record_low_level(
                        "webview-theme",
                        format!("Preferred color scheme could not be set: {e}"),
                    );
                }
            }

            let placement = placements.get(&tab_id).copied();
            let is_foreground = placement.is_some() && !overlay_needs_space;
            if is_foreground {
                twv.hidden_since = None;
            } else if twv.hidden_since.is_none() {
                twv.hidden_since = Some(Instant::now());
            }
            // Memory Saver: background tabs tell WebView2 to trim memory.
            let want_low = memory_saver && !is_foreground && !allow_bg;
            if twv.low_memory != want_low {
                twv.low_memory = want_low;
                let _ = twv.webview.set_memory_usage_level(if want_low {
                    MemoryUsageLevel::Low
                } else {
                    MemoryUsageLevel::Normal
                });
            }

            if is_foreground {
                let is_web = tab_url.starts_with("https://") || tab_url.starts_with("http://");
                if is_web && twv.loaded_url != tab_url {
                    let _ = twv.webview.load_url(&tab_url);
                    twv.loaded_url = tab_url;
                    twv.last_fx_hash = 0;
                }
                if !twv.visible {
                    let _ = twv.webview.set_visible(true);
                    twv.visible = true;
                }

                if self.is_fullscreen {
                    // Use exact Win32 physical client dimensions so Full Screen fills 100% of the monitor!
                    let (phys_w, phys_h) = get_win32_client_physical_size(parent_hwnd).unwrap_or((
                        screen_rect.width().max(100.0) as u32,
                        screen_rect.height().max(100.0) as u32,
                    ));
                    let target_bounds = (0, 0, phys_w, phys_h, true);
                    if twv.last_bounds != target_bounds {
                        twv.last_bounds = target_bounds;
                        let _ = twv.webview.set_bounds(WryRect {
                            position: Position::Physical(PhysicalPosition::new(0, 0)),
                            size: Size::Physical(PhysicalSize::new(phys_w, phys_h)),
                        });
                    }
                } else {
                    let area = placement.unwrap_or(viewport_rect);
                    let fg_x = area.min.x.max(0.0) as i32;
                    let fg_y = area.min.y.max(0.0) as i32;
                    let fg_w = area.width().max(40.0) as u32;
                    let fg_h = area.height().max(40.0) as u32;
                    let target_bounds = (fg_x, fg_y, fg_w, fg_h, false);
                    if twv.last_bounds != target_bounds {
                        twv.last_bounds = target_bounds;
                        let _ = twv.webview.set_bounds(WryRect {
                            position: Position::Logical(LogicalPosition::new(
                                fg_x as f64,
                                fg_y as f64,
                            )),
                            size: Size::Logical(LogicalSize::new(fg_w as f64, fg_h as f64)),
                        });
                    }
                }

                if twv.media_paused_in_bg {
                    twv.media_paused_in_bg = false;
                    post_to_page(
                        &twv.webview,
                        &serde_json::json!({ "t": "bg", "allow": allow_bg, "resume": true }),
                    );
                }
            } else if allow_bg {
                if !twv.visible {
                    let _ = twv.webview.set_visible(true);
                    twv.visible = true;
                }
                let bg_bounds = (-15000, -15000, 800, 600, false);
                if twv.last_bounds != bg_bounds {
                    twv.last_bounds = bg_bounds;
                    let _ = twv.webview.set_bounds(WryRect {
                        position: Position::Logical(LogicalPosition::new(-15000.0, -15000.0)),
                        size: Size::Logical(LogicalSize::new(800.0, 600.0)),
                    });
                }
                if twv.media_paused_in_bg {
                    twv.media_paused_in_bg = false;
                    post_to_page(
                        &twv.webview,
                        &serde_json::json!({ "t": "bg", "allow": true, "resume": true }),
                    );
                }
            } else {
                if !twv.media_paused_in_bg {
                    twv.media_paused_in_bg = true;
                    post_to_page(
                        &twv.webview,
                        &serde_json::json!({ "t": "bg", "allow": false, "pause": true }),
                    );
                }
                if twv.visible {
                    let _ = twv.webview.set_visible(false);
                    twv.visible = false;
                }
            }
        }

        // Memory Saver: discard WebViews of tabs hidden for a long time. The tab keeps its URL
        // and reloads when selected again.
        if memory_saver {
            let bg_allowed: HashSet<u64> = self
                .controller
                .tabs
                .iter()
                .filter(|t| t.allow_in_background)
                .map(|t| t.id)
                .collect();
            self.webviews.retain(|id, twv| {
                let discard = *id != active_tab_id
                    && !bg_allowed.contains(id)
                    && twv
                        .hidden_since
                        .is_some_and(|t| t.elapsed() > MEMORY_SAVER_DISCARD_AFTER);
                if discard {
                    let _ = twv.webview.set_visible(false);
                }
                !discard
            });
        }
    }

    fn verify_fullscreen_request(&mut self, tab_id: u64, check_js: &str, ctx: &egui::Context) {
        let Some(twv) = self.webviews.get(&tab_id) else {
            return;
        };
        let tx = self.wv_tx.clone();
        let ctx = ctx.clone();
        let _ = twv.webview.evaluate_script_with_callback(check_js, move |result| {
            let _ = tx.send(WebViewEvent::FullscreenVerified {
                tab_id,
                ok: result.trim() == "true",
            });
            ctx.request_repaint();
        });
    }

    /// Records a URL that WebView2 reports as committed for `tab_id`.
    fn apply_committed_url(&mut self, tab_id: u64, url: String, title: String, active_tab_id: u64) {
        if let Some(twv) = self.webviews.get_mut(&tab_id) {
            twv.loaded_url = url.clone();
            twv.last_fx_hash = 0;
        }
        let Some(tab_idx) = self.controller.tabs.iter().position(|t| t.id == tab_id) else {
            return;
        };
        let cur_url = self.controller.tabs[tab_idx].current_url.clone();
        let is_internal = cur_url.starts_with("rustchrome://") || cur_url.starts_with("oya://");
        if is_internal || url == cur_url {
            return;
        }
        self.controller.bookmarks.record_visit(&url);
        if cur_url != "about:blank"
            && !cur_url.is_empty()
            && self.controller.tabs[tab_idx].back_stack.last() != Some(&cur_url)
        {
            self.controller.tabs[tab_idx].back_stack.push(cur_url);
        }
        let origin = validate_and_extract_origin(&url)
            .map(|o| o.to_string())
            .unwrap_or_else(|_| "null".to_string());
        let tab = &mut self.controller.tabs[tab_idx];
        tab.current_url = url.clone();
        tab.current_origin = origin.clone();
        if !title.is_empty() {
            tab.title = title.clone();
        }
        if tab_id == active_tab_id {
            if self.editing_bookmark.is_none() {
                if !title.is_empty() {
                    self.bookmark_new_title = title;
                }
                self.bookmark_new_url = url.clone();
            }
            if origin.starts_with("https://") {
                self.vault_new_origin = origin.clone();
            }
            if self.active_validation_origin.as_deref() != Some(origin.as_str()) {
                self.active_validation_origin = None;
            }
            if !self.addr_editing {
                self.address_bar = url.clone();
                self.last_synced_url = url;
            }
        }
    }

    fn drain_webview_events(&mut self, ctx: &egui::Context, parent_hwnd: isize) {
        let active_tab_id = self.controller.tab().id;
        while let Ok(ev) = self.wv_rx.try_recv() {
            match ev {
                WebViewEvent::UrlChanged {
                    tab_id,
                    url,
                    title,
                } => {
                    self.apply_committed_url(tab_id, url, title, active_tab_id);
                }
                WebViewEvent::TitleChanged { tab_id, title } => {
                    if !title.is_empty()
                        && let Some(tab) = self.controller.tabs.iter_mut().find(|t| t.id == tab_id)
                        && !tab.current_url.starts_with("rustchrome://")
                        && !tab.current_url.starts_with("oya://")
                    {
                        tab.title = title.clone();
                        if tab_id == active_tab_id && self.editing_bookmark.is_none() {
                            self.bookmark_new_title = title;
                        }
                    }
                }
                WebViewEvent::FullscreenChanged {
                    tab_id,
                    fullscreen,
                } => {
                    if tab_id == active_tab_id {
                        if fullscreen {
                            // A page message alone is not trusted: check that the page really
                            // is in HTML full screen (which browsers grant only after a click).
                            self.verify_fullscreen_request(
                                tab_id,
                                "!!(document.fullscreenElement || document.webkitFullscreenElement)",
                                ctx,
                            );
                        } else {
                            self.set_fullscreen_state(ctx, parent_hwnd, false);
                        }
                    }
                }
                WebViewEvent::ToggleFullscreen { tab_id } => {
                    if tab_id == active_tab_id {
                        if self.is_fullscreen {
                            self.set_fullscreen_state(ctx, parent_hwnd, false);
                        } else {
                            // Only honour F11 forwarded by the page if a real key press or click
                            // just happened in it.
                            self.verify_fullscreen_request(
                                tab_id,
                                "!!(navigator.userActivation && navigator.userActivation.isActive)",
                                ctx,
                            );
                        }
                    }
                }
                WebViewEvent::WebViewFocused { tab_id } => {
                    if let Some(i) = self.panes.slot_of(tab_id)
                        && self.panes.is_multi()
                        && i != self.panes.focused
                    {
                        self.focus_pane(i);
                    }
                }
                WebViewEvent::FullscreenVerified { tab_id, ok } => {
                    if ok && tab_id == self.controller.tab().id {
                        self.set_fullscreen_state(ctx, parent_hwnd, true);
                    } else if !ok {
                        self.controller.log_store.record(DiagnosticEvent::new(
                            Severity::Security,
                            LogCategory::Security,
                            "fullscreen",
                            0,
                            "Ignored a full-screen request that did not come from the user",
                        ));
                    }
                }
                WebViewEvent::DownloadBlocked {
                    tab_id,
                    url,
                    file_name,
                } => {
                    let host = host_of(&url);
                    self.downloads
                        .record_blocked(tab_id, url.clone(), host, file_name.clone());
                    self.unseen_download_badge = true;
                    if !self.pending_downloads.iter().any(|d| d.url == url) {
                        self.pending_downloads.push(BlockedDownload {
                            tab_id,
                            url,
                            file_name,
                        });
                    }
                }
                WebViewEvent::DownloadStarted {
                    tab_id,
                    url,
                    file_name,
                    path,
                    confirmed_risky,
                } => {
                    let host = host_of(&url);
                    self.downloads.record_started(
                        tab_id,
                        url,
                        host,
                        file_name,
                        path,
                        confirmed_risky,
                    );
                    self.unseen_download_badge = true;
                }
                WebViewEvent::DownloadCompleted {
                    url,
                    path,
                    succeeded,
                } => {
                    if let Some((download_id, scan_path)) =
                        self.downloads.mark_completed_for_scan(&url, path, succeeded)
                    {
                        let tx = self.task_tx.clone();
                        let ctx_scan = ctx.clone();
                        let url_clone = url.clone();
                        std::thread::spawn(move || {
                            let report =
                                crate::downloads::scan_downloaded_file(&scan_path, &url_clone);
                            let _ = tx.send(TaskResult::DownloadScan {
                                download_id,
                                report,
                            });
                            ctx_scan.request_repaint();
                        });
                    }
                    self.unseen_download_badge = true;
                }
                WebViewEvent::LoginFormDetected { tab_id, origin } => {
                    if tab_id == active_tab_id
                        && self.controller.settings.autofill_passwords_enabled
                        && origin.starts_with("https://")
                    {
                        if self.vault.has_credential_for_origin(&origin) {
                            self.validation_status_msg.clear();
                            self.active_validation_origin = Some(origin);
                        } else {
                            self.active_validation_origin = None;
                        }
                    }
                }
                WebViewEvent::LoginSubmitted {
                    tab_id,
                    origin,
                    username,
                    mut password,
                } => {
                    // Passwords are only offered for saving on HTTPS pages.
                    if !self.controller.settings.offer_to_save_passwords
                        || !origin.starts_with("https://")
                    {
                        password.zeroize();
                    } else {
                        self.controller.log_store.record_low_level(
                            &origin,
                            format!("Detected manual login submission on tab {tab_id} on {origin}"),
                        );
                        if let Some(mut old) = self.pending_save_offer.take() {
                            old.password.zeroize();
                        }
                        self.save_offer_pin_input.zeroize();
                        self.save_offer_pin_input.clear();
                        self.save_offer_status_msg.clear();
                        self.pending_save_offer = Some(PendingSaveOffer {
                            origin,
                            username,
                            password,
                        });
                    }
                }
                WebViewEvent::ConsoleLog { tab_id, message } => {
                    if let Some(tab) = self.controller.tabs.iter_mut().find(|t| t.id == tab_id)
                        && tab.console_logs.len() < 200
                    {
                        tab.console_logs.push(message);
                    }
                }
                WebViewEvent::ConsoleError { tab_id, message } => {
                    if let Some(tab) = self.controller.tabs.iter_mut().find(|t| t.id == tab_id) {
                        let origin = tab.current_origin.clone();
                        let pid = tab.active_renderer_pid;
                        if tab.script_errors.len() < 200 {
                            tab.script_errors.push(message.clone());
                        }
                        self.controller.log_store.record(DiagnosticEvent::new(
                            Severity::Warn,
                            LogCategory::JsCompat,
                            &origin,
                            pid,
                            message,
                        ));
                    }
                }
                WebViewEvent::LoadState {
                    tab_id,
                    loading,
                    url,
                } => {
                    if loading {
                        self.loading_tabs.insert(tab_id);
                    } else {
                        self.loading_tabs.remove(&tab_id);
                    }
                    if url.starts_with("https://") || url.starts_with("http://") {
                        self.apply_committed_url(tab_id, url, String::new(), active_tab_id);
                    }
                }
                WebViewEvent::OpenInNewTab { url } => {
                    // Pop-up flood guard: at most 3 page-opened tabs per 10 seconds.
                    self.popup_times.retain(|t| t.elapsed() < Duration::from_secs(10));
                    if self.popup_times.len() >= 3 {
                        self.controller.log_store.record(DiagnosticEvent::new(
                            Severity::Security,
                            LogCategory::Security,
                            "popup-blocker",
                            0,
                            "Blocked a pop-up: too many opened in a short time",
                        ));
                        continue;
                    }
                    self.popup_times.push(Instant::now());
                    let previous = self.controller.active_tab;
                    self.controller.new_tab(&url);
                    // Background-open like Chrome's middle-click; the opener stays in front.
                    self.controller.active_tab = previous;
                    self.sync_address_bar_from_tab();
                }
                WebViewEvent::UpgradeToHttps { tab_id, url } => {
                    if let Some(twv) = self.webviews.get_mut(&tab_id) {
                        let _ = twv.webview.load_url(&url);
                    }
                }
                WebViewEvent::NavigationBlocked { tab_id, url } => {
                    let scheme: String = url.chars().take_while(|c| *c != ':').take(20).collect();
                    self.controller.log_store.record(DiagnosticEvent::new(
                        Severity::Security,
                        LogCategory::Security,
                        "navigation",
                        0,
                        format!("Blocked navigation to a '{scheme}:' URL in tab {tab_id}"),
                    ));
                }
                WebViewEvent::CspViolation { tab_id, message } => {
                    if let Some(tab) = self.controller.tabs.iter_mut().find(|t| t.id == tab_id) {
                        let origin = tab.current_origin.clone();
                        let pid = tab.active_renderer_pid;
                        self.controller.log_store.record(DiagnosticEvent::new(
                            Severity::Security,
                            LogCategory::Security,
                            &origin,
                            pid,
                            message,
                        ));
                    }
                }
            }
        }
    }

}

impl eframe::App for RustChromeApp {
    fn ui(&mut self, ui: &mut egui::Ui, frame: &mut eframe::Frame) {
        self.render_ui(ui, frame);
    }
}

fn extract_parent_hwnd(frame: &eframe::Frame) -> isize {
    if let Ok(wh) = frame.window_handle()
        && let RawWindowHandle::Win32(h) = wh.as_raw()
    {
        return h.hwnd.get();
    }
    0
}

impl RustChromeApp {
    fn settings_open(&self) -> bool {
        is_settings_url(&self.controller.tab().current_url)
    }

    /// Opens Settings in its own tab (re-using an existing Settings tab), like `chrome://settings`.
    fn open_settings(&mut self, section: OptionsSection) {
        self.options_section = section;
        self.options_search_query.clear();
        self.overlay = None;
        if let Some(idx) = self
            .controller
            .tabs
            .iter()
            .position(|t| is_settings_url(&t.current_url))
        {
            self.controller.active_tab = idx;
        } else {
            self.controller.new_tab(SETTINGS_URL);
        }
        self.sync_address_bar_from_tab();
    }

    fn open_new_tab(&mut self) {
        let blank = self.controller.settings.blank_tab_url();
        self.controller.new_tab(&blank);
        self.sync_address_bar_from_tab();
        self.focus_address_bar = true;
    }

    fn close_tab_at(&mut self, idx: usize) {
        if let Some(removed_id) = self.controller.close_tab(idx) {
            if let Some(twv) = self.webviews.remove(&removed_id) {
                let _ = twv.webview.set_visible(false);
            }
            self.loading_tabs.remove(&removed_id);
        }
        self.sync_address_bar_from_tab();
    }

    fn activate_tab(&mut self, idx: usize) {
        if idx < self.controller.tabs.len() && idx != self.controller.active_tab {
            self.controller.active_tab = idx;
            self.sync_address_bar_from_tab();
        }
    }

    fn navigate_active(&mut self, target: &str) {
        self.controller.navigate_or_record_error(target, true);
        self.sync_address_bar_from_tab();
    }

    fn reload_active(&mut self) {
        let id = self.controller.tab().id;
        if let Some(twv) = self.webviews.get(&id)
            && twv.visible
        {
            let _ = twv.webview.reload();
        } else {
            self.controller.reload();
        }
    }

    fn stop_active(&mut self) {
        let id = self.controller.tab().id;
        if let Some(twv) = self.webviews.get(&id) {
            let _ = twv.webview.evaluate_script("window.stop();");
        }
        self.loading_tabs.remove(&id);
    }

    fn go_back(&mut self) {
        let id = self.controller.tab().id;
        self.controller.go_back();
        self.sync_address_bar_from_tab();
        self.load_current_into_webview(id);
    }

    fn go_forward(&mut self) {
        let id = self.controller.tab().id;
        self.controller.go_forward();
        self.sync_address_bar_from_tab();
        self.load_current_into_webview(id);
    }

    fn load_current_into_webview(&mut self, id: u64) {
        let target = self.controller.tab().current_url.clone();
        if (target.starts_with("https://") || target.starts_with("http://"))
            && let Some(twv) = self.webviews.get_mut(&id)
        {
            let _ = twv.webview.load_url(&target);
            twv.loaded_url = target;
        }
    }

    fn change_zoom(&mut self, delta: i32) {
        const STEPS: [u32; 13] = [25, 33, 50, 67, 75, 80, 90, 100, 110, 125, 150, 175, 200];
        let cur = self.controller.settings.page_zoom_pct;
        let idx = STEPS.iter().position(|&z| z >= cur).unwrap_or(STEPS.len() - 1) as i32;
        let next = (idx + delta).clamp(0, STEPS.len() as i32 - 1) as usize;
        self.controller.settings.page_zoom_pct = if delta == 0 { 100 } else { STEPS[next] };
        self.controller.settings.save();
    }

    /// Opens (or closes, if already open) a floating menu anchored at `local` window coordinates.
    fn toggle_overlay(&mut self, ctx: &egui::Context, kind: OverlayKind, local: egui::Pos2, width: f32) {
        if self.overlay.map(|o| o.kind) == Some(kind) {
            self.overlay = None;
            return;
        }
        let window_origin = ctx
            .input(|i| i.viewport().inner_rect.map(|r| r.min))
            .unwrap_or(egui::Pos2::ZERO);
        self.overlay = Some(Overlay {
            kind,
            pos: window_origin + local.to_vec2(),
            width,
            opened_at: Instant::now(),
        });
        self.overlay_height = 0.0;
    }

    fn render_ui(&mut self, ui: &mut egui::Ui, frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        let parent_hwnd = extract_parent_hwnd(frame);
        self.ensure_oya_logo_texture(&ctx);
        self.apply_theme_and_typography(&ctx, parent_hwnd);
        self.drain_webview_events(&ctx, parent_hwnd);
        self.poll_tasks(&ctx);
        self.vault_tick(&ctx);
        let p = self.palette();

        if self.addr_editing || ctx.egui_wants_keyboard_input() {
            reclaim_win32_keyboard_focus(parent_hwnd);
        }

        if ctx.input(|i| i.viewport().close_requested()) {
            self.controller.log_store.record_lifecycle(
                "window-close",
                "User requested Oya Browser window close (WM_CLOSE)",
            );
        }

        let mut pending_cdp = Vec::new();
        if let Some(rx) = &self.cdp_rx {
            while let Ok(req) = rx.try_recv() {
                pending_cdp.push(req);
            }
        }
        for req in pending_cdp {
            self.controller.handle_cdp_request(req);
            self.sync_address_bar_from_tab();
        }

        self.handle_shortcuts(ui, &ctx, parent_hwnd);
        self.reconcile_panes();

        let title = if self.settings_open() {
            "Settings".to_string()
        } else {
            self.controller.tab().title.clone()
        };
        let desired_title = format!("{title} - Oya");
        if self.last_window_title != desired_title {
            self.last_window_title = desired_title.clone();
            ctx.send_viewport_cmd(egui::ViewportCommand::Title(desired_title));
        }

        for img in &self.controller.tab().display_list.images {
            if let std::collections::hash_map::Entry::Vacant(slot) = self.textures.entry(img.id) {
                let color_img = egui::ColorImage::from_rgba_unmultiplied(
                    [img.width as usize, img.height as usize],
                    &img.rgba,
                );
                let handle = ctx.load_texture(
                    format!("rc-img-{}", img.id),
                    color_img,
                    egui::TextureOptions::LINEAR,
                );
                slot.insert(handle);
            }
        }

        if !self.is_fullscreen {
            self.render_tab_strip(ui, &ctx, &p);
            self.render_toolbar(ui, &ctx, parent_hwnd, &p);
            if self.controller.settings.show_bookmarks_bar
                && !self.controller.bookmarks.items.is_empty()
            {
                self.render_bookmarks_bar(ui, &p);
            }
            if self.show_media_fx_bar && !self.settings_open() {
                egui::Panel::top("oya_media_fx_studio_bar")
                    .frame(egui::Frame::new().fill(p.surface).inner_margin(8))
                    .show_separator_line(false)
                    .resizable(false)
                    .show(ui, |ui| {
                        self.render_compact_media_fx_panel(ui);
                    });
            }
            self.render_approval_bar(ui, &ctx, parent_hwnd, &p);
            self.render_security_bars(ui, &p);
            self.render_save_offer_bar(ui, &ctx, parent_hwnd, &p);
            self.render_auto_login_bar(ui, &ctx, parent_hwnd, &p);
        }

        let settings_open = self.settings_open();
        let central_frame = if self.is_fullscreen {
            egui::Frame::new().fill(egui::Color32::BLACK)
        } else if settings_open {
            egui::Frame::new().fill(p.frame)
        } else {
            egui::Frame::new().fill(p.surface)
        };

        egui::CentralPanel::default()
            .frame(central_frame)
            .show(ui, |ui| {
                let viewport_rect = ui.available_rect_before_wrap();
                let screen_rect = ui.ctx().content_rect();

                if self.panes.is_multi() && !self.is_fullscreen {
                    self.render_panes(ui, viewport_rect, &p);
                    self.sync_all_tab_webviews(frame, &ctx, parent_hwnd, viewport_rect, screen_rect);
                    return;
                }
                self.sync_all_tab_webviews(frame, &ctx, parent_hwnd, viewport_rect, screen_rect);

                if settings_open && !self.is_fullscreen {
                    let before = self.controller.settings.clone();
                    self.render_settings_page(ui, &p);
                    self.guard_settings_changes(before);
                    return;
                }

                let active_url = self.controller.tab().current_url.clone();
                if active_url.starts_with("https://") || active_url.starts_with("http://") {
                    return;
                }
                self.render_internal_page(ui, &p);
            });

        self.render_overlay(&ctx, &p);
        self.render_fullscreen_notice(&ctx, &p);
        if std::mem::take(&mut self.pending_fullscreen) {
            let next = !self.is_fullscreen;
            self.set_fullscreen_state(&ctx, parent_hwnd, next);
        }

        if !self.loading_tabs.is_empty() {
            ctx.request_repaint_after(Duration::from_millis(50));
        }
    }

    fn handle_shortcuts(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, parent_hwnd: isize) {
        #[derive(Default)]
        struct Keys {
            new_tab: bool,
            close_tab: bool,
            focus_addr: bool,
            reload: bool,
            devtools: bool,
            toggle_fs: bool,
            escape: bool,
            next_tab: bool,
            prev_tab: bool,
            select_tab: Option<usize>,
            zoom: Option<i32>,
            back: bool,
            forward: bool,
            focus_pane: Option<usize>,
            maximize_pane: bool,
        }
        let mut k = Keys::default();
        ui.input(|i| {
            let ctrl = i.modifiers.command;
            k.toggle_fs = i.key_pressed(egui::Key::F11);
            k.escape = i.key_pressed(egui::Key::Escape);
            k.new_tab = ctrl && i.key_pressed(egui::Key::T);
            k.close_tab = ctrl && i.key_pressed(egui::Key::W);
            k.focus_addr = (ctrl && i.key_pressed(egui::Key::L))
                || (i.modifiers.alt && i.key_pressed(egui::Key::D));
            k.reload = i.key_pressed(egui::Key::F5) || (ctrl && i.key_pressed(egui::Key::R));
            k.devtools = i.key_pressed(egui::Key::F12);
            if ctrl && i.key_pressed(egui::Key::Tab) {
                if i.modifiers.shift {
                    k.prev_tab = true;
                } else {
                    k.next_tab = true;
                }
            }
            if ctrl && i.key_pressed(egui::Key::PageDown) {
                k.next_tab = true;
            }
            if ctrl && i.key_pressed(egui::Key::PageUp) {
                k.prev_tab = true;
            }
            let digits = [
                egui::Key::Num1,
                egui::Key::Num2,
                egui::Key::Num3,
                egui::Key::Num4,
                egui::Key::Num5,
                egui::Key::Num6,
                egui::Key::Num7,
                egui::Key::Num8,
                egui::Key::Num9,
            ];
            for (n, key) in digits.iter().enumerate() {
                if ctrl && i.key_pressed(*key) {
                    k.select_tab = Some(n);
                }
            }
            if ctrl && (i.key_pressed(egui::Key::Plus) || i.key_pressed(egui::Key::Equals)) {
                k.zoom = Some(1);
            }
            if ctrl && i.key_pressed(egui::Key::Minus) {
                k.zoom = Some(-1);
            }
            if ctrl && i.key_pressed(egui::Key::Num0) {
                k.zoom = Some(0);
            }
            for (n, key) in [egui::Key::Num1, egui::Key::Num2, egui::Key::Num3, egui::Key::Num4]
                .iter()
                .enumerate()
            {
                if i.modifiers.alt && !ctrl && i.key_pressed(*key) {
                    k.focus_pane = Some(n);
                }
            }
            k.maximize_pane = ctrl && i.modifiers.shift && i.key_pressed(egui::Key::M);
            k.back = i.modifiers.alt && i.key_pressed(egui::Key::ArrowLeft);
            k.forward = i.modifiers.alt && i.key_pressed(egui::Key::ArrowRight);
        });

        if k.toggle_fs {
            let next = !self.is_fullscreen;
            self.set_fullscreen_state(ctx, parent_hwnd, next);
        } else if k.escape {
            if self.overlay.is_some() {
                self.overlay = None;
            } else if self.is_fullscreen {
                self.set_fullscreen_state(ctx, parent_hwnd, false);
            }
        }
        if k.new_tab {
            self.open_new_tab();
        }
        if k.close_tab {
            let idx = self.controller.active_tab;
            self.close_tab_at(idx);
        }
        if k.focus_addr {
            self.focus_address_bar = true;
        }
        if k.reload {
            self.reload_active();
        }
        if k.devtools {
            self.open_settings(OptionsSection::SystemAndDeveloper);
        }
        let n = self.controller.tabs.len();
        if k.next_tab {
            self.activate_tab((self.controller.active_tab + 1) % n);
        }
        if k.prev_tab {
            self.activate_tab((self.controller.active_tab + n - 1) % n);
        }
        if let Some(sel) = k.select_tab {
            // Ctrl+9 always means the last tab, as in Chrome.
            let idx = if sel == 8 { n - 1 } else { sel.min(n - 1) };
            self.activate_tab(idx);
        }
        if let Some(z) = k.zoom {
            self.change_zoom(z);
        }
        if let Some(i) = k.focus_pane {
            self.focus_pane(i);
        }
        if k.maximize_pane {
            self.toggle_maximize_pane();
        }
        if k.back {
            self.go_back();
        }
        if k.forward {
            self.go_forward();
        }
    }

    // ------------------------------------------------------------------
    // Tab strip
    // ------------------------------------------------------------------

    fn render_tab_strip(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, p: &Palette) {
        const TAB_H: f32 = 34.0;
        const TAB_MIN_W: f32 = 72.0;
        const TAB_MAX_W: f32 = 240.0;
        const NEW_TAB_W: f32 = 36.0;

        enum TabAction {
            Activate(usize),
            Close(usize),
            Menu(u64, egui::Pos2),
            Move(usize, usize),
        }

        let strip_frame = egui::Frame::new().fill(p.frame).inner_margin(egui::Margin {
            left: 8,
            right: 8,
            top: 6,
            bottom: 0,
        });
        let mut action: Option<TabAction> = None;
        let mut new_tab_clicked = false;
        let active_idx = self.controller.active_tab;
        let active_id = self.controller.tab().id;
        let scroll_to_active = self.last_active_tab_id != Some(active_id);
        self.last_active_tab_id = Some(active_id);
        let tab_count = self.controller.tabs.len();
        let logo = self.oya_logo_texture.clone();

        egui::Panel::top("oya_tab_strip")
            .frame(strip_frame)
            .show_separator_line(false)
            .resizable(false)
            .show(ui, |ui| {
                ui.spacing_mut().item_spacing = egui::vec2(0.0, 0.0);
                let avail = ui.available_width();
                let tabs_area = (avail - NEW_TAB_W - 4.0).max(TAB_MIN_W);
                let tab_w = (tabs_area / tab_count.max(1) as f32).clamp(TAB_MIN_W, TAB_MAX_W);

                ui.horizontal(|ui| {
                    let mut rects: Vec<egui::Rect> = Vec::with_capacity(tab_count);
                    let mut dragged: Option<(usize, f32)> = None;
                    egui::ScrollArea::horizontal()
                        .id_salt("oya_tab_scroll")
                        .max_width(tabs_area)
                        .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysHidden)
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.spacing_mut().item_spacing = egui::vec2(0.0, 0.0);
                                let mut prev_highlight = true;
                                for idx in 0..tab_count {
                                    let tab = &self.controller.tabs[idx];
                                    let info = TabPaint {
                                        id: tab.id,
                                        title: tab_title(tab),
                                        badge: favicon_letter(&tab.current_url),
                                        internal: !(tab.current_url.starts_with("https://")
                                            || tab.current_url.starts_with("http://")),
                                        loading: self.loading_tabs.contains(&tab.id),
                                        active: idx == active_idx,
                                        background_media: tab.allow_in_background,
                                        can_close: tab_count > 1,
                                    };
                                    let out = draw_tab(
                                        ui,
                                        p,
                                        &info,
                                        egui::vec2(tab_w, TAB_H),
                                        prev_highlight,
                                        logo.as_ref(),
                                    );
                                    prev_highlight = out.highlighted;
                                    if info.active && scroll_to_active {
                                        ui.scroll_to_rect(out.response.rect, None);
                                    }
                                    rects.push(out.response.rect);
                                    if out.close_clicked || out.response.middle_clicked() {
                                        action = Some(TabAction::Close(idx));
                                    } else if out.response.secondary_clicked() {
                                        let at = out
                                            .response
                                            .interact_pointer_pos()
                                            .unwrap_or(out.response.rect.left_bottom());
                                        action = Some(TabAction::Menu(info.id, at));
                                    } else if out.response.clicked()
                                        || out.response.drag_started()
                                    {
                                        action = Some(TabAction::Activate(idx));
                                    }
                                    if out.response.dragged()
                                        && let Some(pos) = out.response.interact_pointer_pos()
                                    {
                                        dragged = Some((idx, pos.x));
                                    }
                                }
                            });
                        });
                    if let Some((from, x)) = dragged
                        && let Some(to) = rects.iter().position(|r| r.x_range().contains(x))
                        && to != from
                    {
                        action = Some(TabAction::Move(from, to));
                    }

                    ui.add_space(4.0);
                    let (rect, resp) =
                        ui.allocate_exact_size(egui::vec2(NEW_TAB_W - 4.0, TAB_H - 4.0), egui::Sense::click());
                    let resp = resp.on_hover_text("New tab (Ctrl+T)");
                    if resp.hovered() {
                        ui.painter().circle_filled(rect.center(), 14.0, p.hover);
                    }
                    paint_icon(ui.painter(), Icon::Plus, rect.center(), p.text);
                    resp.widget_info(|| {
                        egui::WidgetInfo::labeled(egui::Role::Button, true, "New tab")
                    });
                    if resp.clicked() {
                        new_tab_clicked = true;
                    }
                });
            });

        match action {
            Some(TabAction::Activate(idx)) => self.activate_tab(idx),
            Some(TabAction::Close(idx)) => self.close_tab_at(idx),
            Some(TabAction::Menu(id, at)) => {
                self.toggle_overlay(ctx, OverlayKind::TabMenu(id), at, 240.0)
            }
            Some(TabAction::Move(from, to)) => {
                let moving = self.controller.tabs.remove(from);
                self.controller.tabs.insert(to, moving);
                if let Some(idx) = self.controller.tabs.iter().position(|t| t.id == active_id) {
                    self.controller.active_tab = idx;
                }
            }
            None => {}
        }
        if new_tab_clicked {
            self.open_new_tab();
        }
    }

    // ------------------------------------------------------------------
    // Toolbar and address bar
    // ------------------------------------------------------------------

    fn render_toolbar(
        &mut self,
        ui: &mut egui::Ui,
        ctx: &egui::Context,
        parent_hwnd: isize,
        p: &Palette,
    ) {
        let bar_frame = egui::Frame::new().fill(p.surface).inner_margin(egui::Margin {
            left: 8,
            right: 8,
            top: 5,
            bottom: 5,
        });
        egui::Panel::top("oya_toolbar")
            .frame(bar_frame)
            .show_separator_line(false)
            .resizable(false)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 2.0;
                    let active_id = self.controller.tab().id;
                    let can_back = !self.controller.tab().back_stack.is_empty();
                    let can_fwd = !self.controller.tab().forward_stack.is_empty();
                    let loading = self.loading_tabs.contains(&active_id);

                    if icon_button(ui, p, Icon::Back, can_back, false, "Back").clicked() {
                        self.go_back();
                    }
                    if icon_button(ui, p, Icon::Forward, can_fwd, false, "Forward").clicked() {
                        self.go_forward();
                    }
                    let (reload_icon, reload_label) = if loading {
                        (Icon::Close, "Stop loading")
                    } else {
                        (Icon::Reload, "Reload")
                    };
                    if icon_button(ui, p, reload_icon, true, false, reload_label).clicked() {
                        if loading {
                            self.stop_active();
                        } else {
                            self.reload_active();
                        }
                    }
                    if self.controller.settings.show_home_button
                        && icon_button(ui, p, Icon::Home, true, false, "Home").clicked()
                    {
                        let home = self.controller.settings.blank_tab_url();
                        self.navigate_active(&home);
                    }
                    ui.add_space(6.0);

                    let right_w = 4.0 * 34.0 + 14.0;
                    let omni_w = (ui.available_width() - right_w).max(160.0);
                    self.render_omnibox(ui, ctx, parent_hwnd, p, omni_w);
                    ui.add_space(6.0);

                    let dl_open = matches!(
                        self.overlay.as_ref().map(|o| o.kind),
                        Some(OverlayKind::Downloads)
                    );
                    let dl_btn = icon_button(
                        ui,
                        p,
                        Icon::Downloads,
                        true,
                        dl_open,
                        "Downloads: view downloads, sources, and hazard scan results",
                    );
                    let has_dl_hazard = self.downloads.entries.iter().any(|e| {
                        e.state == crate::downloads::DownloadState::AwaitingConfirmation
                            || (e.state == crate::downloads::DownloadState::Ready
                                && e.hazard.requires_open_confirmation())
                    });
                    let has_dl_active = self.downloads.entries.iter().any(|e| {
                        matches!(
                            e.state,
                            crate::downloads::DownloadState::Downloading
                                | crate::downloads::DownloadState::Scanning
                        )
                    });
                    if has_dl_hazard {
                        ui.painter().circle_filled(
                            dl_btn.rect.center() + egui::vec2(9.0, -9.0),
                            3.5,
                            p.danger,
                        );
                    } else if has_dl_active || self.unseen_download_badge {
                        ui.painter().circle_filled(
                            dl_btn.rect.center() + egui::vec2(9.0, -9.0),
                            3.0,
                            p.accent,
                        );
                    }
                    if dl_btn.clicked() {
                        self.unseen_download_badge = false;
                        self.download_alert_id = None;
                        let width = 420.0;
                        let anchor =
                            egui::pos2(dl_btn.rect.right() - width, dl_btn.rect.bottom() + 4.0);
                        self.toggle_overlay(ctx, OverlayKind::Downloads, anchor, width);
                    }

                    let fx_active = self.controller.settings.eq_enabled
                        || self.controller.settings.upscaler_mode != VideoUpscalerMode::Off;
                    let panes_btn = icon_button(
                        ui,
                        p,
                        Icon::Panes,
                        true,
                        self.panes.is_multi(),
                        "Panes: show several pages side by side",
                    );
                    if panes_btn.clicked() {
                        let width = 280.0;
                        let anchor =
                            egui::pos2(panes_btn.rect.right() - width, panes_btn.rect.bottom() + 4.0);
                        self.toggle_overlay(ctx, OverlayKind::PaneMenu, anchor, width);
                    }
                    let fx = icon_button(
                        ui,
                        p,
                        Icon::Equalizer,
                        true,
                        self.show_media_fx_bar,
                        "Media studio: equalizer and video enhancement",
                    );
                    if fx_active && !self.show_media_fx_bar {
                        // Small dot: effects are on even though the studio is closed.
                        ui.painter().circle_filled(
                            fx.rect.center() + egui::vec2(9.0, -9.0),
                            3.0,
                            p.accent,
                        );
                    }
                    if fx.clicked() {
                        self.show_media_fx_bar = !self.show_media_fx_bar;
                    }
                    let menu = icon_button(ui, p, Icon::Menu, true, false, "Customize and control Oya");
                    if menu.clicked() {
                        let width = 300.0;
                        let anchor = egui::pos2(menu.rect.right() - width, menu.rect.bottom() + 4.0);
                        self.toggle_overlay(ctx, OverlayKind::MainMenu, anchor, width);
                    }
                });
            });
    }

    fn render_omnibox(
        &mut self,
        ui: &mut egui::Ui,
        ctx: &egui::Context,
        parent_hwnd: isize,
        p: &Palette,
        width: f32,
    ) {
        const H: f32 = 34.0;
        let (rect, _) = ui.allocate_exact_size(egui::vec2(width, H), egui::Sense::hover());
        let edit_id = egui::Id::unique("oya_url_address_bar");
        let has_focus = ctx.memory(|m| m.has_focus(edit_id));
        let painter = ui.painter().clone();
        painter.rect_filled(rect, H / 2.0, if has_focus { p.surface } else { p.field });
        if has_focus {
            painter.rect_stroke(
                rect,
                H / 2.0,
                egui::Stroke::new(2.0, p.accent),
                egui::StrokeKind::Inside,
            );
        }

        let url = self.controller.tab().current_url.clone();
        let origin = self.controller.tab().current_origin.clone();
        let security = SiteSecurity::of(&url);

        // Site-information chip (padlock / "Not secure" / Oya page).
        let chip_w = if security == SiteSecurity::Insecure { 104.0 } else { 30.0 };
        let chip_rect = egui::Rect::from_min_size(rect.min + egui::vec2(3.0, 3.0), egui::vec2(chip_w, H - 6.0));
        let chip = ui.interact(chip_rect, egui::Id::unique("oya_site_chip"), egui::Sense::click());
        if chip.hovered() {
            painter.rect_filled(chip_rect, (H - 6.0) / 2.0, p.hover);
        }
        let icon_c = egui::pos2(chip_rect.left() + 15.0, chip_rect.center().y);
        match security {
            SiteSecurity::Secure => paint_icon(&painter, Icon::Lock, icon_c, p.text_weak),
            SiteSecurity::Insecure => {
                paint_icon(&painter, Icon::Warning, icon_c, p.danger);
                painter.text(
                    egui::pos2(icon_c.x + 12.0, icon_c.y),
                    egui::Align2::LEFT_CENTER,
                    "Not secure",
                    egui::FontId::proportional(12.5),
                    p.danger,
                );
            }
            SiteSecurity::Internal => {
                if let Some(logo) = &self.oya_logo_texture {
                    painter.image(
                        logo.id(),
                        egui::Rect::from_center_size(icon_c, egui::vec2(16.0, 16.0)),
                        egui::Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(1.0, 1.0)),
                        egui::Color32::WHITE,
                    );
                }
            }
            SiteSecurity::Other => paint_icon(&painter, Icon::Search, icon_c, p.text_weak),
        }
        chip.widget_info(|| egui::WidgetInfo::labeled(egui::Role::Button, true, "View site information"));
        if chip.clicked() {
            self.toggle_overlay(ctx, OverlayKind::SiteInfo, chip_rect.left_bottom() + egui::vec2(0.0, 6.0), 340.0);
        }

        // Right-hand icons inside the pill: saved sign-in (key) and bookmark (star).
        let is_web = url.starts_with("https://") || url.starts_with("http://");
        let star_c = egui::pos2(rect.right() - 19.0, rect.center().y);
        let mut right_edge = star_c.x - 16.0;
        if is_web {
            let star_rect = egui::Rect::from_center_size(star_c, egui::vec2(28.0, 28.0));
            let star = ui.interact(star_rect, egui::Id::unique("oya_star"), egui::Sense::click());
            let is_bm = self.controller.bookmarks.is_bookmarked(&url);
            if star.hovered() {
                painter.circle_filled(star_c, 14.0, p.hover);
            }
            paint_icon(
                &painter,
                if is_bm { Icon::StarFilled } else { Icon::Star },
                star_c,
                if is_bm { p.accent } else { p.text_weak },
            );
            star.widget_info(|| {
                egui::WidgetInfo::selected(egui::Role::CheckBox, true, is_bm, "Bookmark this tab")
            });
            if star.clicked() {
                if is_bm {
                    let id = self
                        .controller
                        .bookmarks
                        .items
                        .iter()
                        .find(|b| b.url == url)
                        .map(|b| b.id);
                    if let Some(id) = id {
                        self.controller.bookmarks.remove(id);
                    }
                } else {
                    let title = self.controller.tab().title.clone();
                    let folder = self.bookmark_target_folder.clone();
                    self.controller.bookmarks.add_or_update(&title, &url, &folder);
                }
            }
            if self.vault.has_credential_for_origin(&origin) && origin.starts_with("https://") {
                let key_c = egui::pos2(star_c.x - 30.0, star_c.y);
                let key_rect = egui::Rect::from_center_size(key_c, egui::vec2(28.0, 28.0));
                let key = ui.interact(key_rect, egui::Id::unique("oya_key"), egui::Sense::click());
                if key.hovered() {
                    painter.circle_filled(key_c, 14.0, p.hover);
                }
                paint_icon(&painter, Icon::Key, key_c, p.accent);
                key.widget_info(|| {
                    egui::WidgetInfo::labeled(egui::Role::Button, true, "Sign in with saved password")
                });
                if key.clicked() {
                    self.validation_status_msg.clear();
                    self.active_validation_origin = Some(origin.clone());
                }
                right_edge = key_c.x - 16.0;
            }
        }

        // The editable text.
        let text_rect = egui::Rect::from_min_max(
            egui::pos2(chip_rect.right() + 6.0, rect.top()),
            egui::pos2(right_edge.max(chip_rect.right() + 40.0), rect.bottom()),
        );
        let text_color = p.text;
        let weak_color = p.text_weak;
        let mut layouter = |ui: &egui::Ui, buf: &dyn egui::TextBuffer, _wrap: f32| {
            let job = url_layout_job(buf.as_str(), !has_focus, text_color, weak_color, ui);
            ui.painter().layout_job(job)
        };
        let search_hint = format!(
            "Search {} or type a URL",
            self.controller.settings.search_engine.label()
        );
        // A detached child UI: placing the field inside the already-allocated pill must not move
        // the toolbar's layout cursor (that made the next buttons overlap the pill).
        let mut field_ui = ui.new_child(
            egui::UiBuilder::new()
                .max_rect(text_rect)
                .layout(egui::Layout::left_to_right(egui::Align::Center)),
        );
        let output = egui::TextEdit::singleline(&mut self.address_bar)
            .id(edit_id)
            .frame(egui::Frame::new())
            .hint_text(search_hint)
            .desired_width(text_rect.width())
            .align(egui::Align2::LEFT_CENTER)
            .layouter(&mut layouter)
            .show(&mut field_ui);
        let resp = &output.response;

        if self.focus_address_bar {
            self.focus_address_bar = false;
            resp.request_focus();
            self.select_all_address = true;
        }
        if resp.gained_focus() {
            self.select_all_address = true;
        }
        if self.select_all_address && resp.has_focus() {
            self.select_all_address = false;
            let mut state = output.state.clone();
            state
                .cursor
                .set_char_range(Some(egui::text::CCursorRange::select_all_str(&self.address_bar)));
            state.store(ctx, edit_id);
        }
        if resp.has_focus() || resp.clicked() {
            reclaim_win32_keyboard_focus(parent_hwnd);
        }
        self.addr_editing = resp.has_focus();

        if resp.lost_focus() {
            let (enter, escape) =
                ui.input(|i| (i.key_pressed(egui::Key::Enter), i.key_pressed(egui::Key::Escape)));
            if enter && !self.address_bar.trim().is_empty() {
                let target = self.address_bar.trim().to_string();
                self.navigate_active(&target);
            } else if escape || self.address_bar.trim().is_empty() {
                self.address_bar = self.controller.tab().current_url.clone();
                self.last_synced_url = self.address_bar.clone();
            }
        }
    }

    fn render_bookmarks_bar(&mut self, ui: &mut egui::Ui, p: &Palette) {
        let mut nav_to = None;
        let mut open_manager = false;
        egui::Panel::top("oya_bookmarks_bar")
            .frame(egui::Frame::new().fill(p.surface).inner_margin(egui::Margin {
                left: 10,
                right: 10,
                top: 0,
                bottom: 4,
            }))
            .show_separator_line(false)
            .resizable(false)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 2.0;
                    let all_w = 110.0;
                    let mut used = 0.0;
                    let limit = ui.available_width() - all_w;
                    for bm in self.controller.bookmarks.items.iter().take(20) {
                        let title = if bm.title.trim().is_empty() {
                            bm.url.clone()
                        } else {
                            bm.title.clone()
                        };
                        let short: String = title.chars().take(24).collect();
                        let resp = bar_chip(ui, p, &short, p.text, limit - used);
                        let Some(resp) = resp else { break };
                        used += resp.rect.width() + 2.0;
                        if resp.clicked() {
                            nav_to = Some(bm.url.clone());
                        }
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if bar_chip(ui, p, "All bookmarks", p.text_weak, all_w)
                            .is_some_and(|r| r.clicked())
                        {
                            open_manager = true;
                        }
                    });
                });
            });
        if let Some(target) = nav_to {
            self.navigate_active(&target);
        }
        if open_manager {
            self.open_settings(OptionsSection::YouAndOya);
        }
    }

    fn render_internal_page(&mut self, ui: &mut egui::Ui, p: &Palette) {
        let avail = ui.available_size();
        self.controller.resize(avail.x, avail.y);

        if let Some(err) = &self.controller.tab().last_error {
            ui.add_space(12.0);
            ui.horizontal_wrapped(|ui| {
                ui.add_space(16.0);
                ui.colored_label(p.danger, format!("This page could not be loaded: {err}"));
            });
            ui.add_space(8.0);
        }

        let bg = self
            .controller
            .tab()
            .display_list
            .background
            .map(to_egui_color)
            .unwrap_or(egui::Color32::WHITE);

        egui::Frame::new().fill(bg).show(ui, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                let desired_h = self
                    .controller
                    .tab()
                    .display_list
                    .content_height
                    .max(avail.y);
                let (rect, response) =
                    ui.allocate_exact_size(egui::vec2(avail.x, desired_h), egui::Sense::click());
                let painter = ui.painter_at(rect);

                for cmd in &self.controller.tab().display_list.commands {
                    match cmd {
                        DrawCommand::FillRect { x, y, w, h, color } => {
                            let r = egui::Rect::from_min_size(
                                rect.min + egui::vec2(*x, *y),
                                egui::vec2(*w, *h),
                            );
                            painter.rect_filled(r, 0.0, to_egui_color(*color));
                        }
                        DrawCommand::StrokeRect {
                            x,
                            y,
                            w,
                            h,
                            width,
                            color,
                        } => {
                            let r = egui::Rect::from_min_size(
                                rect.min + egui::vec2(*x, *y),
                                egui::vec2(*w, *h),
                            );
                            painter.rect_stroke(
                                r,
                                0.0,
                                egui::Stroke::new(*width, to_egui_color(*color)),
                                egui::StrokeKind::Inside,
                            );
                        }
                        DrawCommand::DrawText {
                            x,
                            y,
                            text,
                            font_size,
                            color,
                            bold: _,
                        } => {
                            painter.text(
                                rect.min + egui::vec2(*x, *y),
                                egui::Align2::LEFT_TOP,
                                text,
                                egui::FontId::proportional(*font_size),
                                to_egui_color(*color),
                            );
                        }
                        DrawCommand::DrawImage {
                            x,
                            y,
                            w,
                            h,
                            image_id,
                        } => {
                            if let Some(tex) = self.textures.get(image_id) {
                                let r = egui::Rect::from_min_size(
                                    rect.min + egui::vec2(*x, *y),
                                    egui::vec2(*w, *h),
                                );
                                painter.image(
                                    tex.id(),
                                    r,
                                    egui::Rect::from_min_max(
                                        egui::pos2(0.0, 0.0),
                                        egui::pos2(1.0, 1.0),
                                    ),
                                    egui::Color32::WHITE,
                                );
                            }
                        }
                    }
                }

                if let Some(hover_pos) = response.hover_pos() {
                    let local = hover_pos - rect.min;
                    if self.controller.is_hovering_interactive(local.x, local.y) {
                        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
                    }
                }

                if response.clicked()
                    && let Some(pos) = response.interact_pointer_pos()
                {
                    let local = pos - rect.min;
                    match self.controller.click_at(local.x, local.y) {
                        ClickOutcome::Navigate(target) => {
                            self.navigate_active(&target);
                        }
                        ClickOutcome::Updated | ClickOutcome::None => {}
                    }
                }
            });
        });
    }

    // ------------------------------------------------------------------
    // Floating menus (own OS window, above the WebView2 page)
    // ------------------------------------------------------------------

    fn render_overlay(&mut self, ctx: &egui::Context, p: &Palette) {
        let Some(ov) = self.overlay else {
            return;
        };
        if let OverlayKind::TabMenu(id) = ov.kind
            && !self.controller.tabs.iter().any(|t| t.id == id)
        {
            self.overlay = None;
            return;
        }
        let height = if self.overlay_height > 0.0 {
            self.overlay_height
        } else {
            320.0
        };
        let builder = egui::ViewportBuilder::default()
            .with_title("Oya menu")
            .with_decorations(false)
            .with_resizable(false)
            .with_taskbar(false)
            .with_always_on_top()
            .with_position(ov.pos)
            .with_inner_size(egui::vec2(ov.width, height))
            .with_active(true);
        let p = *p;
        let mut close = false;
        let mut measured = height;
        ctx.show_viewport_immediate(
            egui::ViewportId::from_hash_of("oya_overlay_menu"),
            builder,
            |ui, _class| {
                let vctx = ui.ctx().clone();
                let (focused, close_req, esc) = vctx.input(|i| {
                    (
                        i.viewport().focused,
                        i.viewport().close_requested(),
                        i.key_pressed(egui::Key::Escape),
                    )
                });
                // Close when the user clicks anywhere else (the menu window loses focus).
                if (focused == Some(false) && ov.opened_at.elapsed() > Duration::from_millis(300))
                    || close_req
                    || esc
                {
                    close = true;
                }
                let frame = egui::Frame::new()
                    .fill(p.surface)
                    .stroke(egui::Stroke::new(1.0, p.divider))
                    .inner_margin(egui::Margin::symmetric(6, 8));
                let inner = frame.show(ui, |ui| {
                    ui.set_width(ov.width - 14.0);
                    match ov.kind {
                        OverlayKind::MainMenu => self.main_menu_contents(ui, &vctx, &p),
                        OverlayKind::TabMenu(id) => self.tab_menu_contents(ui, id, &p),
                        OverlayKind::SiteInfo => self.site_info_contents(ui, &p),
                        OverlayKind::PaneMenu => self.pane_menu_contents(ui, &p),
                        OverlayKind::Downloads => self.downloads_overlay_contents(ui, &p),
                    }
                });
                if inner.inner {
                    close = true;
                }
                measured = inner.response.rect.height().ceil();
            },
        );
        if close {
            self.overlay = None;
        } else if (measured - self.overlay_height).abs() > 0.5 {
            self.overlay_height = measured;
            ctx.request_repaint();
        }
    }

    /// Returns `true` when the downloads overlay should close.
    fn downloads_overlay_contents(&mut self, ui: &mut egui::Ui, p: &Palette) -> bool {
        use crate::downloads::{
            DownloadState, HazardLevel, format_bytes, format_timestamp_ms,
        };
        let mut close = false;
        let mut open_path: Option<(u64, PathBuf, bool)> = None;
        let mut reveal_path: Option<PathBuf> = None;
        let mut remove_id: Option<u64> = None;
        let mut delete_entry: Option<(u64, PathBuf)> = None;
        let mut clear_finished = false;
        let mut open_folder = false;

        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("Downloads").color(p.text).strong().size(15.0));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.small_button("Clear finished").clicked() {
                    clear_finished = true;
                }
                if ui.small_button("Open folder").clicked() {
                    open_folder = true;
                }
            });
        });
        menu_divider(ui, p);

        if let Some(confirm_id) = self.pending_open_download_id {
            if let Some(entry) = self.downloads.by_id(confirm_id).cloned() {
                let is_hazard = entry.hazard.is_hazardous();
                let reason = entry
                    .hazard
                    .reason()
                    .unwrap_or("This file is an executable, script, or archive.");
                egui::Frame::new()
                    .fill(if is_hazard {
                        p.danger.gamma_multiply(0.16)
                    } else {
                        p.warn.gamma_multiply(0.16)
                    })
                    .corner_radius(egui::CornerRadius::same(8))
                    .stroke(egui::Stroke::new(
                        1.0,
                        if is_hazard { p.danger } else { p.warn },
                    ))
                    .inner_margin(egui::Margin::same(10))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            paint_inline_icon(
                                ui,
                                Icon::Warning,
                                if is_hazard { p.danger } else { p.warn },
                            );
                            ui.label(
                                egui::RichText::new(if is_hazard {
                                    "Confirm Opening Hazardous File"
                                } else {
                                    "Confirm Opening Questionable File"
                                })
                                .color(p.text)
                                .strong(),
                            );
                        });
                        ui.add_space(4.0);
                        ui.label(
                            egui::RichText::new(format!(
                                "“{}” (from {})",
                                entry.file_name, entry.source_host
                            ))
                            .color(p.text),
                        );
                        ui.label(egui::RichText::new(reason).color(p.text_weak).small());
                        ui.add_space(6.0);
                        ui.horizontal_wrapped(|ui| {
                            if ui.button("Open Anyway").clicked()
                                && let Some(path) = entry.local_path.clone()
                            {
                                open_path = Some((entry.id, path, true));
                            }
                            if let Some(path) = entry.local_path.clone()
                                && ui.button("Show in Folder").clicked()
                            {
                                reveal_path = Some(path);
                            }
                            if let Some(path) = entry.local_path.clone()
                                && ui.button("Delete File").clicked()
                            {
                                delete_entry = Some((entry.id, path));
                            }
                            if ui.add(security::primary_button("Cancel", p)).clicked() {
                                self.pending_open_download_id = None;
                            }
                        });
                    });
                ui.add_space(6.0);
            } else {
                self.pending_open_download_id = None;
            }
        }

        if self.downloads.entries.is_empty() {
            ui.add_space(12.0);
            ui.label(
                egui::RichText::new("No downloads yet. Files you download will appear here with their source, time, and hazard scan status.")
                    .color(p.text_weak),
            );
            ui.add_space(12.0);
        } else {
            egui::ScrollArea::vertical()
                .max_height(380.0)
                .show(ui, |ui| {
                    for entry in &self.downloads.entries {
                        let is_ready = entry.state == DownloadState::Ready
                            && entry.local_path.as_ref().is_some_and(|p| p.exists());
                        let (status_label, status_color) = match &entry.state {
                            DownloadState::AwaitingConfirmation => ("Confirm download", p.warn),
                            DownloadState::Downloading => ("Downloading…", p.accent),
                            DownloadState::Scanning => ("Scanning for hazards…", p.accent),
                            DownloadState::Ready => match &entry.hazard {
                                HazardLevel::Clean => ("Ready · Clean", p.success),
                                HazardLevel::Pending => ("Ready", p.text_weak),
                                HazardLevel::Questionable(_) => ("Questionable", p.warn),
                                HazardLevel::Hazardous(_) => ("Hazard detected", p.danger),
                            },
                            DownloadState::Failed(why) => (why.as_str(), p.danger),
                            DownloadState::Discarded => ("Discarded", p.text_weak),
                        };

                        egui::Frame::new()
                            .fill(p.frame)
                            .corner_radius(egui::CornerRadius::same(8))
                            .stroke(egui::Stroke::new(1.0, p.divider))
                            .inner_margin(egui::Margin::same(8))
                            .show(ui, |ui| {
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        if ui.small_button("×").clicked() {
                                            remove_id = Some(entry.id);
                                        }
                                        if entry.local_path.is_some()
                                            && ui.small_button("Folder").clicked()
                                        {
                                            reveal_path = entry.local_path.clone();
                                        }
                                        let avail = ui.available_width().max(40.0);
                                        ui.allocate_ui_with_layout(
                                            egui::vec2(avail, 20.0),
                                            egui::Layout::left_to_right(egui::Align::Center),
                                            |ui| {
                                                let title_btn = ui.add_enabled(
                                                    is_ready,
                                                    egui::Button::new(
                                                        egui::RichText::new(&entry.file_name)
                                                            .color(if is_ready {
                                                                p.text
                                                            } else {
                                                                p.text_weak
                                                            })
                                                            .strong(),
                                                    )
                                                    .truncate()
                                                    .frame(false),
                                                );
                                                if title_btn.clicked()
                                                    && let Some(path) = entry.local_path.clone()
                                                {
                                                    if entry.is_questionable_or_hazardous() {
                                                        self.pending_open_download_id =
                                                            Some(entry.id);
                                                    } else {
                                                        open_path = Some((entry.id, path, false));
                                                    }
                                                }
                                            },
                                        );
                                    },
                                );
                                let when = format_timestamp_ms(
                                    entry.completed_at_ms.unwrap_or(entry.started_at_ms),
                                );
                                let size_str = entry
                                    .file_size_bytes
                                    .map(|b| format!(" · {}", format_bytes(b)))
                                    .unwrap_or_default();
                                ui.label(
                                    egui::RichText::new(format!(
                                        "{status_label}{size_str} · {when}"
                                    ))
                                    .color(status_color)
                                    .small(),
                                );
                                ui.label(
                                    egui::RichText::new(format!("From: {}", entry.source_url))
                                        .color(p.text_weak)
                                        .small(),
                                );
                                if !entry.scan_summary.is_empty() {
                                    ui.label(
                                        egui::RichText::new(&entry.scan_summary)
                                            .color(p.text_weak)
                                            .small(),
                                    );
                                }
                            });
                        ui.add_space(4.0);
                    }
                });
        }

        if let Some((id, path, confirmed)) = open_path {
            self.pending_open_download_id = None;
            if let Err(e) = rc_sandbox::open_file_with_shell(&path) {
                self.controller.log_store.record_low_level(
                    "downloads",
                    format!("Could not open {}: {e}", path.display()),
                );
            } else {
                self.controller.log_store.record(DiagnosticEvent::new(
                    Severity::Security,
                    LogCategory::Security,
                    "downloads",
                    0,
                    format!(
                        "{} download id={} ({})",
                        if confirmed { "Opened questionable" } else { "Opened" },
                        id,
                        path.display()
                    ),
                ));
                close = true;
            }
        }
        if let Some(path) = reveal_path {
            rc_sandbox::reveal_file_in_explorer(&path);
        }
        if let Some((id, path)) = delete_entry {
            let _ = std::fs::remove_file(&path);
            self.downloads.remove(id);
            self.pending_open_download_id = None;
        }
        if let Some(id) = remove_id {
            self.downloads.remove(id);
            if self.pending_open_download_id == Some(id) {
                self.pending_open_download_id = None;
            }
        }
        if clear_finished {
            self.downloads.clear_finished();
        }
        if open_folder {
            let dir = PathBuf::from(self.controller.settings.download_directory.trim());
            rc_sandbox::reveal_file_in_explorer(&dir);
        }

        close
    }

    /// Returns `true` when the menu should close.
    fn main_menu_contents(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, p: &Palette) -> bool {
        let mut close = false;
        if menu_item(ui, p, "New tab", "Ctrl+T", None).clicked() {
            self.open_new_tab();
            close = true;
        }
        if self.controller.tabs.len() > 1 && menu_item(ui, p, "Close tab", "Ctrl+W", None).clicked() {
            let idx = self.controller.active_tab;
            self.close_tab_at(idx);
            close = true;
        }
        menu_divider(ui, p);

        // Zoom row: label, − value +, full screen
        ui.horizontal(|ui| {
            ui.add_space(12.0);
            ui.label(egui::RichText::new("Zoom").color(p.text));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.add_space(4.0);
                if icon_button(ui, p, Icon::Fullscreen, true, false, "Full screen (F11)").clicked() {
                    self.pending_fullscreen = true;
                    close = true;
                }
                ui.add_space(8.0);
                if icon_button(ui, p, Icon::Plus, true, false, "Zoom in (Ctrl +)").clicked() {
                    self.change_zoom(1);
                }
                ui.label(
                    egui::RichText::new(format!("{}%", self.controller.settings.page_zoom_pct))
                        .color(p.text)
                        .monospace(),
                );
                if icon_button(ui, p, Icon::Minus, true, false, "Zoom out (Ctrl -)").clicked() {
                    self.change_zoom(-1);
                }
            });
        });
        menu_divider(ui, p);

        if menu_item(ui, p, "Passwords and autofill", "", None).clicked() {
            self.open_settings(OptionsSection::AutofillAndPasswords);
            close = true;
        }
        if menu_item(ui, p, "Bookmarks", "", None).clicked() {
            self.open_settings(OptionsSection::YouAndOya);
            close = true;
        }
        let bar = self.controller.settings.show_bookmarks_bar;
        if menu_item(ui, p, "Show bookmarks bar", "", Some(bar)).clicked() {
            self.controller.settings.show_bookmarks_bar = !bar;
            self.controller.settings.save();
        }
        let studio = self.show_media_fx_bar;
        if menu_item(ui, p, "Media studio", "", Some(studio)).clicked() {
            self.show_media_fx_bar = !studio;
            close = true;
        }
        menu_divider(ui, p);
        if menu_item(ui, p, "Full screen", "F11", None).clicked() {
            self.pending_fullscreen = true;
            close = true;
        }
        if menu_item(ui, p, "Developer tools", "F12", None).clicked() {
            self.open_settings(OptionsSection::SystemAndDeveloper);
            close = true;
        }
        if self.vault.is_unlocked() && menu_item(ui, p, "Lock password vault", "", None).clicked() {
            self.vault.lock();
            close = true;
        }
        menu_divider(ui, p);
        if menu_item(ui, p, "Settings", "", None).clicked() {
            let section = self.options_section;
            self.open_settings(section);
            close = true;
        }
        if menu_item(ui, p, "About Oya", "", None).clicked() {
            self.open_settings(OptionsSection::AboutOya);
            close = true;
        }
        let _ = ctx;
        close
    }

    fn tab_menu_contents(&mut self, ui: &mut egui::Ui, tab_id: u64, p: &Palette) -> bool {
        let Some(idx) = self.controller.tabs.iter().position(|t| t.id == tab_id) else {
            return true;
        };
        let mut close = false;
        if menu_item(ui, p, "New tab", "Ctrl+T", None).clicked() {
            self.open_new_tab();
            close = true;
        }
        if menu_item(ui, p, "Reload", "Ctrl+R", None).clicked() {
            if let Some(twv) = self.webviews.get(&tab_id) {
                let _ = twv.webview.reload();
            }
            close = true;
        }
        if menu_item(ui, p, "Duplicate", "", None).clicked() {
            self.controller.duplicate_tab(idx);
            self.sync_address_bar_from_tab();
            close = true;
        }
        let bg = self.controller.tabs[idx].allow_in_background;
        if menu_item(ui, p, "Keep playing in background", "", Some(bg)).clicked() {
            self.controller.tabs[idx].allow_in_background = !bg;
        }
        if self.panes.is_multi() {
            menu_divider(ui, p);
            for slot in 0..self.panes.layout.slots() {
                let here = self.panes.slots[slot] == Some(tab_id);
                if menu_item(ui, p, &format!("Show in pane {}", slot + 1), &format!("Alt+{}", slot + 1), Some(here)).clicked() {
                    for s in self.panes.slots.iter_mut() {
                        if *s == Some(tab_id) {
                            *s = None;
                        }
                    }
                    self.panes.slots[slot] = Some(tab_id);
                    self.focus_pane(slot);
                    close = true;
                }
            }
        }
        if self.controller.tabs.len() > 1 {
            menu_divider(ui, p);
            if menu_item(ui, p, "Close tab", "Ctrl+W", None).clicked() {
                self.close_tab_at(idx);
                close = true;
            }
            if menu_item(ui, p, "Close other tabs", "", None).clicked() {
                let others: Vec<u64> = self
                    .controller
                    .tabs
                    .iter()
                    .map(|t| t.id)
                    .filter(|id| *id != tab_id)
                    .collect();
                for id in others {
                    if let Some(i) = self.controller.tabs.iter().position(|t| t.id == id) {
                        self.close_tab_at(i);
                    }
                }
                close = true;
            }
        }
        close
    }

    fn site_info_contents(&mut self, ui: &mut egui::Ui, p: &Palette) -> bool {
        let mut close = false;
        let url = self.controller.tab().current_url.clone();
        let origin = self.controller.tab().current_origin.clone();
        let security = SiteSecurity::of(&url);
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.add_space(12.0);
            ui.label(egui::RichText::new(host_of(&url)).strong().size(15.0).color(p.text));
        });
        ui.add_space(6.0);
        let (icon, color, headline, detail) = match security {
            SiteSecurity::Secure => (
                Icon::Lock,
                p.text,
                "Connection is secure",
                "Information you send to this site is encrypted (HTTPS).",
            ),
            SiteSecurity::Insecure => (
                Icon::Warning,
                p.danger,
                "Connection is not secure",
                "Don't enter passwords or payment details on this site. Oya will not offer to save or fill passwords here.",
            ),
            SiteSecurity::Internal => (
                Icon::Lock,
                p.text,
                "Oya page",
                "This page is part of the browser.",
            ),
            SiteSecurity::Other => (Icon::Search, p.text, "Local or special page", ""),
        };
        ui.horizontal(|ui| {
            ui.add_space(12.0);
            paint_inline_icon(ui, icon, color);
            ui.label(egui::RichText::new(headline).color(color).strong());
        });
        if !detail.is_empty() {
            ui.horizontal(|ui| {
                ui.add_space(38.0);
                ui.add(egui::Label::new(egui::RichText::new(detail).color(p.text_weak).size(12.5)).wrap());
            });
        }
        if matches!(security, SiteSecurity::Secure | SiteSecurity::Insecure) {
            ui.horizontal(|ui| {
                ui.add_space(38.0);
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(format!(
                            "Rendered by Microsoft Edge WebView2 in its own sandboxed processes. Tracking prevention: {}.",
                            if self.controller.settings.block_third_party_cookies {
                                "Strict"
                            } else {
                                "Balanced"
                            }
                        ))
                        .color(p.text_weak)
                        .size(12.5),
                    )
                    .wrap(),
                );
            });
        }
        menu_divider(ui, p);
        if security == SiteSecurity::Secure
            && self.vault.has_credential_for_origin(&origin)
            && menu_item(ui, p, "Sign in with saved password", "", None).clicked()
        {
            self.validation_status_msg.clear();
            self.active_validation_origin = Some(origin.clone());
            close = true;
        }
        let idx = self.controller.active_tab;
        let bg = self.controller.tabs[idx].allow_in_background;
        if menu_item(ui, p, "Keep playing in background", "", Some(bg)).clicked() {
            self.controller.tabs[idx].allow_in_background = !bg;
        }
        if menu_item(ui, p, "Privacy and security settings", "", None).clicked() {
            self.open_settings(OptionsSection::PrivacyAndSecurity);
            close = true;
        }
        close
    }

    /// Equalizer and video enhancement controls, centred with a maximum width so nothing runs to
    /// the window edge. Used in the media studio bar and in Settings.
    fn render_compact_media_fx_panel(&mut self, ui: &mut egui::Ui) {
        let pal = self.palette();
        let closable = self.show_media_fx_bar && !self.settings_open();
        let mut close = false;
        let mut changed = false;
        let avail = ui.available_width();
        let width = avail.min(920.0);
        let pad = ((avail - width) / 2.0).max(0.0);
        let s = &mut self.controller.settings;

        ui.horizontal(|ui| {
            ui.add_space(pad);
            ui.vertical(|ui| {
                ui.set_width(width);
                // Slider tracks: a visible grey with the filled part shown. The accent colour for
                // the filled part is set only around the sliders, so selected chips keep their
                // readable tonal style.
                ui.visuals_mut().widgets.inactive.bg_fill = pal.text_weak.gamma_multiply(0.35);
                ui.style_mut().visuals.slider_trailing_fill = true;

                // ---------------- Equalizer ----------------
                egui::Frame::new()
                    .fill(pal.field)
                    .corner_radius(12.0)
                    .inner_margin(egui::Margin::symmetric(20, 14))
                    .show(ui, |ui| {
                        ui.set_width(width - 40.0);
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new("Equalizer").strong().size(15.0).color(pal.text));
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                if closable && ui.small_button("Close studio").clicked() {
                                    close = true;
                                }
                                ui.add_space(8.0);
                                changed |= toggle_switch(ui, &pal, &mut s.eq_enabled, "Equalizer").changed();
                                ui.label(
                                    egui::RichText::new(if s.eq_enabled { "On" } else { "Off" })
                                        .color(pal.text_weak),
                                );
                            });
                        });
                        ui.add_space(4.0);
                        ui.horizontal_wrapped(|ui| {
                            for &preset in EqualizerPreset::all() {
                                if ui
                                    .selectable_value(&mut s.eq_preset, preset, preset.short_label())
                                    .on_hover_text(preset.label())
                                    .changed()
                                {
                                    if preset != EqualizerPreset::Custom {
                                        s.eq_bands_db = preset.band_gains_db();
                                    }
                                    s.eq_enabled = true;
                                    changed = true;
                                }
                            }
                            if ui.small_button("Reset").clicked() {
                                s.eq_preset = EqualizerPreset::Flat;
                                s.eq_preamp_db = 0.0;
                                s.eq_bands_db = [0.0; 10];
                                changed = true;
                            }
                        });
                        ui.add_space(10.0);

                        // Preamp + 10 bands as vertical sliders, centred; two rows when narrow.
                        let inner = ui.available_width();
                        let gap = 8.0;
                        let per_row = if inner >= 11.0 * 40.0 + 10.0 * gap { 11 } else { 6 };
                        let col_w = ((inner - gap * (per_row as f32 - 1.0)) / per_row as f32).clamp(34.0, 64.0);
                        let row_w = col_w * per_row as f32 + gap * (per_row as f32 - 1.0);
                        let left = ((inner - row_w) / 2.0).max(0.0);
                        for chunk_start in (0..11).step_by(per_row) {
                            ui.horizontal(|ui| {
                                ui.add_space(left);
                                ui.spacing_mut().item_spacing.x = gap;
                                ui.spacing_mut().slider_width = 110.0;
                                ui.visuals_mut().selection.bg_fill = pal.accent;
                                for i in chunk_start..(chunk_start + per_row).min(11) {
                                    ui.allocate_ui_with_layout(
                                        egui::vec2(col_w, 160.0),
                                        egui::Layout::top_down(egui::Align::Center),
                                        |ui| {
                                            ui.set_width(col_w);
                                            let (label, value) = if i == 0 {
                                                ("Pre", &mut s.eq_preamp_db)
                                            } else {
                                                (EQ_BAND_LABELS[i - 1], &mut s.eq_bands_db[i - 1])
                                            };
                                            let shown = if value.abs() < 0.05 { 0.0 } else { *value };
                                            ui.label(
                                                egui::RichText::new(format!("{shown:+.1}"))
                                                    .size(11.0)
                                                    .color(if shown != 0.0 { pal.accent } else { pal.text_weak }),
                                            );
                                            let r = ui.add(
                                                egui::Slider::new(value, -12.0..=12.0)
                                                    .vertical()
                                                    .show_value(false)
                                                    .step_by(0.5),
                                            );
                                            if r.changed() {
                                                changed = true;
                                                if i > 0 {
                                                    s.eq_preset = EqualizerPreset::Custom;
                                                }
                                                s.eq_enabled = true;
                                            }
                                            ui.label(
                                                egui::RichText::new(label)
                                                    .size(11.0)
                                                    .color(if i == 0 { pal.text } else { pal.text_weak }),
                                            );
                                        },
                                    );
                                }
                            });
                        }
                    });

                ui.add_space(10.0);

                // ---------------- Video enhancement ----------------
                egui::Frame::new()
                    .fill(pal.field)
                    .corner_radius(12.0)
                    .inner_margin(egui::Margin::symmetric(20, 14))
                    .show(ui, |ui| {
                        ui.set_width(width - 40.0);
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new("Video enhancement").strong().size(15.0).color(pal.text));
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                changed |= toggle_switch(ui, &pal, &mut s.optimize_4k_playback, "Prefer 4K").changed();
                                ui.label(egui::RichText::new("Prefer highest quality").color(pal.text_weak));
                            });
                        });
                        ui.add_space(4.0);
                        ui.horizontal_wrapped(|ui| {
                            for &mode in VideoUpscalerMode::all() {
                                if ui
                                    .selectable_value(&mut s.upscaler_mode, mode, mode.short_label())
                                    .on_hover_text(mode.label())
                                    .changed()
                                {
                                    changed = true;
                                }
                            }
                        });
                        ui.add_space(8.0);
                        let label_w = 120.0;
                        // Leave room for the value box so the card keeps the same width as the
                        // equalizer card above it.
                        let slider_w = (ui.available_width() - label_w - 96.0).max(80.0);
                        for (label, value) in [
                            ("Sharpness", &mut s.upscaler_sharpness),
                            ("Vibrance", &mut s.upscaler_vibrance),
                        ] {
                            ui.horizontal(|ui| {
                                // Fixed-width label so both sliders start at the same place.
                                let (rect, _) =
                                    ui.allocate_exact_size(egui::vec2(label_w, 24.0), egui::Sense::hover());
                                ui.painter().text(
                                    egui::pos2(rect.left(), rect.center().y),
                                    egui::Align2::LEFT_CENTER,
                                    label,
                                    egui::TextStyle::Body.resolve(ui.style()),
                                    pal.text,
                                );
                                ui.spacing_mut().slider_width = slider_w;
                                ui.visuals_mut().selection.bg_fill = pal.accent;
                                if ui
                                    .add(egui::Slider::new(value, 0.0..=100.0).suffix("%").step_by(1.0))
                                    .changed()
                                {
                                    changed = true;
                                }
                            });
                        }
                    });
            });
        });

        if close {
            self.show_media_fx_bar = false;
        }
        if changed {
            self.controller.settings.save();
        }
    }

    fn render_settings_page(&mut self, ui: &mut egui::Ui, p: &Palette) {
        let full_w = ui.available_width();
        let wide = full_w >= 920.0;
        let nav_w = if wide { 248.0 } else { 0.0 };
        let gutter = if wide { 24.0 } else { 16.0 };
        let col_w = (full_w - nav_w - gutter * 2.0).clamp(280.0, 1040.0);

        // Header: title and search
        ui.add_space(14.0);
        ui.horizontal(|ui| {
            ui.add_space(gutter);
            if let Some(logo) = &self.oya_logo_texture {
                ui.add(egui::Image::new(logo).fit_to_exact_size(egui::vec2(26.0, 26.0)));
            }
            ui.label(egui::RichText::new("Settings").size(22.0).color(p.text));
            let search_w = (ui.available_width() - gutter).clamp(160.0, 560.0);
            let pad = ((ui.available_width() - search_w) / 2.0 - nav_w / 2.0).max(8.0);
            ui.add_space(pad);
            let (rect, _) = ui.allocate_exact_size(egui::vec2(search_w, 38.0), egui::Sense::hover());
            ui.painter().rect_filled(rect, 19.0, p.surface);
            paint_icon(
                ui.painter(),
                Icon::Search,
                egui::pos2(rect.left() + 20.0, rect.center().y),
                p.text_weak,
            );
            let text_rect = egui::Rect::from_min_max(
                egui::pos2(rect.left() + 38.0, rect.top()),
                egui::pos2(rect.right() - 14.0, rect.bottom()),
            );
            let mut field_ui = ui.new_child(
                egui::UiBuilder::new()
                    .max_rect(text_rect)
                    .layout(egui::Layout::left_to_right(egui::Align::Center)),
            );
            field_ui.add(
                egui::TextEdit::singleline(&mut self.options_search_query)
                    .frame(egui::Frame::new())
                    .hint_text("Search settings")
                    .desired_width(text_rect.width()),
            );
        });
        ui.add_space(12.0);

        let query = self.options_search_query.trim().to_lowercase();
        let sections: Vec<OptionsSection> = if query.is_empty() {
            vec![self.options_section]
        } else {
            OptionsSection::all()
                .iter()
                .copied()
                .filter(|s| {
                    s.label().to_lowercase().contains(&query) || s.keywords().contains(&query)
                })
                .collect()
        };

        if !wide {
            // Narrow window: section chips that wrap instead of a side rail.
            ui.horizontal_wrapped(|ui| {
                ui.add_space(gutter);
                ui.set_max_width(full_w - gutter);
                for &sec in OptionsSection::all() {
                    if ui
                        .selectable_label(query.is_empty() && self.options_section == sec, sec.label())
                        .clicked()
                    {
                        self.options_section = sec;
                        self.options_search_query.clear();
                    }
                }
            });
            ui.add_space(8.0);
        }

        ui.horizontal_top(|ui| {
            if wide {
                ui.add_space(12.0);
                ui.vertical(|ui| {
                    ui.set_width(nav_w - 12.0);
                    for &sec in OptionsSection::all() {
                        let selected = query.is_empty() && self.options_section == sec;
                        if nav_item(ui, p, sec.label(), selected).clicked() {
                            self.options_section = sec;
                            self.options_search_query.clear();
                        }
                    }
                });
            }
            let left_pad = ((ui.available_width() - col_w) / 2.0).max(gutter);
            ui.add_space(left_pad);
            ui.vertical(|ui| {
                ui.set_width(col_w);
                egui::ScrollArea::vertical()
                    .id_salt("oya_settings_scroll")
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        ui.set_width(col_w);
                        if sections.is_empty() {
                            ui.add_space(24.0);
                            ui.label(
                                egui::RichText::new(format!("No settings match \"{query}\"."))
                                    .color(p.text_weak),
                            );
                        }
                        for sec in sections {
                            section_heading(ui, p, sec.label());
                            self.render_section(ui, p, sec);
                            ui.add_space(18.0);
                        }
                        ui.add_space(40.0);
                    });
            });
        });
    }

    fn render_section(&mut self, ui: &mut egui::Ui, p: &Palette, sec: OptionsSection) {
        match sec {
            OptionsSection::YouAndOya => self.section_bookmarks(ui, p),
            OptionsSection::AutofillAndPasswords => self.section_passwords(ui, p),
            OptionsSection::PrivacyAndSecurity => self.section_privacy(ui, p),
            OptionsSection::Performance => self.section_performance(ui, p),
            OptionsSection::Appearance => self.section_appearance(ui, p),
            OptionsSection::SearchEngine => self.section_search_engine(ui, p),
            OptionsSection::OnStartup => self.section_on_startup(ui, p),
            OptionsSection::Languages => self.section_languages(ui, p),
            OptionsSection::Downloads => self.section_downloads(ui, p),
            OptionsSection::SystemAndDeveloper => self.section_system(ui, p),
            OptionsSection::ResetSettings => self.section_reset(ui, p),
            OptionsSection::AboutOya => self.section_about(ui, p),
        }
    }

    fn section_bookmarks(&mut self, ui: &mut egui::Ui, p: &Palette) {
        card(ui, p, |ui| {
            row_label(ui, p, "Import bookmarks", "Copies bookmarks and folders from another browser on this PC.");
            ui.horizontal_wrapped(|ui| {
                if ui.button("Google Chrome").clicked() {
                    self.bookmark_status_banner = match self.controller.bookmarks.import_from_chrome() {
                        Ok(n) => format!("Imported {n} bookmarks from Google Chrome."),
                        Err(e) => format!("Chrome: {e}"),
                    };
                }
                if ui.button("Microsoft Edge").clicked() {
                    self.bookmark_status_banner = match self.controller.bookmarks.import_from_edge() {
                        Ok(n) => format!("Imported {n} bookmarks from Microsoft Edge."),
                        Err(e) => format!("Edge: {e}"),
                    };
                }
                if ui.button("Mozilla Firefox").clicked() {
                    self.bookmark_status_banner = match self.controller.bookmarks.import_from_firefox() {
                        Ok(n) => format!("Imported {n} bookmarks from Mozilla Firefox."),
                        Err(e) => format!("Firefox: {e}"),
                    };
                }
            });
            ui.horizontal_wrapped(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut self.bookmark_import_file_path)
                        .hint_text("Full path to an HTML or JSON bookmarks file")
                        .desired_width(ui.available_width().min(420.0)),
                );
                if ui.button("Import file").clicked() {
                    let path = self.bookmark_import_file_path.trim().to_string();
                    self.bookmark_status_banner = match self
                        .controller
                        .bookmarks
                        .import_from_file(Path::new(&path), "Imported/File")
                    {
                        Ok(n) => format!("Imported {n} bookmarks."),
                        Err(e) => e,
                    };
                }
            });
        });
        ui.add_space(10.0);

        // Add or edit a bookmark.
        card(ui, p, |ui| {
            let editing = self.editing_bookmark;
            row_label(ui, p, if editing.is_some() { "Edit bookmark" } else { "Add a bookmark" }, "");
            let field_w = ((ui.available_width() - 16.0) / 2.0).max(160.0);
            ui.horizontal_wrapped(|ui| {
                ui.add(egui::TextEdit::singleline(&mut self.bookmark_new_title).hint_text("Name").desired_width(field_w));
                ui.add(egui::TextEdit::singleline(&mut self.bookmark_new_url).hint_text("https://").desired_width(field_w));
            });
            ui.add(
                egui::TextEdit::singleline(&mut self.bookmark_new_description)
                    .hint_text("Description (optional) — shown when you hover over the bookmark")
                    .desired_width(ui.available_width()),
            );
            ui.horizontal_wrapped(|ui| {
                ui.label(egui::RichText::new("Folder").color(p.text_weak));
                egui::ComboBox::from_id_salt("bm_target_folder_combo")
                    .selected_text(&self.bookmark_target_folder)
                    .width(200.0)
                    .show_ui(ui, |ui| {
                        for folder in &self.controller.bookmarks.folders {
                            ui.selectable_value(&mut self.bookmark_target_folder, folder.clone(), folder);
                        }
                    });
                if ui.button(if editing.is_some() { "Save changes" } else { "Save" }).clicked() {
                    let (t, u, f, d) = (
                        self.bookmark_new_title.clone(),
                        self.bookmark_new_url.trim().to_string(),
                        self.bookmark_target_folder.clone(),
                        self.bookmark_new_description.clone(),
                    );
                    if !u.is_empty() {
                        // An edit that changes the address replaces the old entry.
                        if let Some(old_id) = editing
                            && self.controller.bookmarks.items.iter().any(|b| b.id == old_id && b.url != u)
                        {
                            self.controller.bookmarks.remove(old_id);
                        }
                        let id = self.controller.bookmarks.add_or_update(&t, &u, &f);
                        self.controller.bookmarks.set_description(id, &d);
                        self.bookmark_status_banner = format!("Saved \"{}\" in {f}.", if t.is_empty() { &u } else { &t });
                        self.editing_bookmark = None;
                        self.bookmark_new_description.clear();
                        self.bookmark_new_title.clear();
                        self.bookmark_new_url.clear();
                    }
                }
                if editing.is_some() && ui.button("Cancel").clicked() {
                    self.editing_bookmark = None;
                    self.bookmark_new_description.clear();
                }
                ui.add_space(12.0);
                ui.add(
                    egui::TextEdit::singleline(&mut self.bookmark_new_folder_input)
                        .hint_text("New folder, e.g. Work/Rust")
                        .desired_width(200.0),
                );
                if ui.button("Create folder").clicked() {
                    let f = self.bookmark_new_folder_input.trim().to_string();
                    if !f.is_empty() {
                        self.controller.bookmarks.add_folder(&f);
                        self.bookmark_target_folder = f.clone();
                        self.bookmark_new_folder_input.clear();
                        self.bookmark_status_banner = format!("Created folder \"{f}\".");
                    }
                }
            });
            if !self.bookmark_status_banner.is_empty() {
                ui.colored_label(p.success, &self.bookmark_status_banner);
            }
        });
        ui.add_space(10.0);

        // All bookmarks as a table.
        card(ui, p, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(
                    egui::RichText::new(format!("All bookmarks ({})", self.controller.bookmarks.items.len()))
                        .color(p.text),
                );
                ui.add_space(12.0);
                ui.add(
                    egui::TextEdit::singleline(&mut self.bookmark_search_query)
                        .hint_text("Search name, site or description")
                        .desired_width(260.0),
                );
                let cur_sort = self.controller.bookmarks.sort_mode;
                egui::ComboBox::from_id_salt("bm_sort_mode_combo")
                    .selected_text(cur_sort.label())
                    .show_ui(ui, |ui| {
                        for &mode in BookmarkSortMode::all() {
                            if ui
                                .selectable_value(&mut self.controller.bookmarks.sort_mode, mode, mode.label())
                                .changed()
                            {
                                self.controller.bookmarks.save();
                            }
                        }
                    });
            });
            ui.horizontal_wrapped(|ui| {
                if ui
                    .selectable_label(self.bookmark_selected_folder.is_none(), "All folders")
                    .clicked()
                {
                    self.bookmark_selected_folder = None;
                }
                for folder in self.controller.bookmarks.folders.clone() {
                    let is_sel = self.bookmark_selected_folder.as_deref() == Some(folder.as_str());
                    if ui.selectable_label(is_sel, &folder).clicked() {
                        self.bookmark_selected_folder = Some(folder);
                    }
                }
            });
            ui.add_space(6.0);

            let q = self.bookmark_search_query.trim().to_lowercase();
            let mut rows = self
                .controller
                .bookmarks
                .query("", self.bookmark_selected_folder.as_deref());
            if !q.is_empty() {
                rows.retain(|b| {
                    b.title.to_lowercase().contains(&q)
                        || b.url.to_lowercase().contains(&q)
                        || b.description.to_lowercase().contains(&q)
                });
            }
            let cols = [
                TableCol::new("Name", 2.0, 80.0),
                TableCol::new("Site", 1.5, 80.0),
                TableCol::new("Description", 3.5, 110.0),
                TableCol::new("Folder", 1.0, 70.0),
                TableCol::new("Visits", 0.3, 40.0),
            ];
            let tail = 128.0;
            let names: Vec<String> = rows
                .iter()
                .map(|b| if b.title.trim().is_empty() { b.url.clone() } else { b.title.clone() })
                .collect();
            let hosts: Vec<String> = rows.iter().map(|b| host_of(&b.url)).collect();
            let visits: Vec<String> = rows.iter().map(|b| b.visit_count.to_string()).collect();
            let content = column_content_widths(
                ui,
                &cols,
                rows.iter().enumerate().map(|(i, b)| {
                    vec![
                        names[i].as_str(),
                        hosts[i].as_str(),
                        b.description.as_str(),
                        b.folder_path.as_str(),
                        visits[i].as_str(),
                    ]
                }),
            );
            let widths = table_widths(ui.available_width(), &cols, tail, &content);
            table_header(ui, p, &cols, &widths, tail);
            if rows.is_empty() {
                ui.add_space(8.0);
                ui.label(egui::RichText::new("No bookmarks to show.").color(p.text_weak));
            }
            let mut open_url = None;
            let mut edit = None;
            let mut delete_id = None;
            for bm in rows {
                let name = if bm.title.trim().is_empty() { bm.url.clone() } else { bm.title.clone() };
                let cells = [
                    (name, p.text),
                    (host_of(&bm.url), p.text_weak),
                    (bm.description.clone(), p.text_weak),
                    (bm.folder_path.clone(), p.text_weak),
                    (bm.visit_count.to_string(), p.text_weak),
                ];
                let tooltip = if bm.description.trim().is_empty() {
                    bm.url.clone()
                } else {
                    format!("{}\n{}", bm.description, bm.url)
                };
                let resp = table_row(ui, p, egui::Id::unique(("bm_row", bm.id)), &widths, &cells, tail, |ui| {
                    if ui.small_button("Remove").clicked() {
                        delete_id = Some(bm.id);
                    }
                    if ui.small_button("Edit").clicked() {
                        edit = Some(bm.clone());
                    }
                });
                let resp = resp.on_hover_text(tooltip);
                if resp.clicked() {
                    open_url = Some(bm.url.clone());
                }
            }
            if let Some(b) = edit {
                self.editing_bookmark = Some(b.id);
                self.bookmark_new_title = b.title.clone();
                self.bookmark_new_url = b.url.clone();
                self.bookmark_target_folder = b.folder_path.clone();
                self.bookmark_new_description = b.description.clone();
            }
            if let Some(id) = delete_id {
                self.controller.bookmarks.remove(id);
                if self.editing_bookmark == Some(id) {
                    self.editing_bookmark = None;
                }
            }
            if let Some(target) = open_url {
                self.navigate_active(&target);
            }
        });
    }

    fn section_performance(&mut self, ui: &mut egui::Ui, p: &Palette) {
        card(ui, p, |ui| {
            let s = &mut self.controller.settings;
            let mut changed = false;
            changed |= toggle_row(
                ui,
                p,
                &mut s.memory_saver_enabled,
                "Memory Saver",
                "Background tabs use less memory and are unloaded after 15 minutes out of view. Tabs set to keep playing are never unloaded.",
            );
            row_divider(ui, p);
            changed |= toggle_row(
                ui,
                p,
                &mut s.default_allow_tabs_in_background,
                "Keep new tabs playing in the background",
                "Media keeps playing when you switch away. Change it per tab from the tab's right-click menu.",
            );
            if changed {
                s.save();
            }
            row_divider(ui, p);
            row_label(ui, p, "Open tabs that keep playing in the background", "");
            for tab in &mut self.controller.tabs {
                if is_settings_url(&tab.current_url) {
                    continue;
                }
                let title: String = tab_title(tab).chars().take(60).collect();
                ui.checkbox(&mut tab.allow_in_background, title);
            }
        });
        ui.add_space(10.0);
        card(ui, p, |ui| {
            row_label(ui, p, "Media studio", "Equalizer and video enhancement applied to pages that play media.");
            self.render_compact_media_fx_panel(ui);
        });
    }

    fn section_appearance(&mut self, ui: &mut egui::Ui, p: &Palette) {
        card(ui, p, |ui| {
            let s = &mut self.controller.settings;
            let mut changed = false;
            row_label(ui, p, "Theme", "");
            ui.horizontal_wrapped(|ui| {
                changed |= ui.selectable_value(&mut s.theme_mode, ThemeMode::Day, "Light").changed();
                changed |= ui.selectable_value(&mut s.theme_mode, ThemeMode::Night, "Dark").changed();
            });
            row_divider(ui, p);
            row_label(ui, p, "Interface text size", "");
            ui.horizontal_wrapped(|ui| {
                changed |= ui
                    .add(egui::Slider::new(&mut s.font_size_pt, 11.0..=22.0).step_by(0.5).suffix(" pt"))
                    .changed();
                if ui.small_button("Reset").clicked() {
                    s.font_size_pt = 14.0;
                    changed = true;
                }
            });
            row_label(ui, p, "Interface font", "");
            ui.horizontal_wrapped(|ui| {
                for &fam in UiFontFamily::all() {
                    changed |= ui.radio_value(&mut s.font_family, fam, fam.label()).changed();
                }
            });
            row_divider(ui, p);
            row_label(ui, p, "Page zoom", "Applies to all websites. Ctrl + and Ctrl − also change it.");
            ui.horizontal_wrapped(|ui| {
                changed |= ui
                    .add(egui::Slider::new(&mut s.page_zoom_pct, 25..=300).step_by(5.0).suffix("%"))
                    .changed();
                if ui.small_button("100%").clicked() {
                    s.page_zoom_pct = 100;
                    changed = true;
                }
            });
            row_divider(ui, p);
            changed |= toggle_row(ui, p, &mut s.show_home_button, "Show Home button", "");
            row_divider(ui, p);
            changed |= toggle_row(ui, p, &mut s.show_bookmarks_bar, "Show bookmarks bar", "");
            if changed {
                s.save();
            }
        });
    }



    fn section_languages(&mut self, ui: &mut egui::Ui, p: &Palette) {
        card(ui, p, |ui| {
            let s = &mut self.controller.settings;
            row_label(
                ui,
                p,
                "Preferred language",
                "Language tag such as en-US or fr-FR. Websites receive it after Oya restarts.",
            );
            if ui
                .add(egui::TextEdit::singleline(&mut s.preferred_language).desired_width(220.0))
                .changed()
            {
                s.save();
            }
            if s.language_tag().is_none() {
                ui.colored_label(p.danger, "Not a valid language tag; the system language will be used.");
            }
        });
    }


    fn section_system(&mut self, ui: &mut egui::Ui, p: &Palette) {
        let active_tab_id = self.controller.tab().id;
        card(ui, p, |ui| {
            let s = &mut self.controller.settings;
            let mut changed = toggle_row(
                ui,
                p,
                &mut s.hardware_acceleration_enabled,
                "Use graphics acceleration when available",
                "Takes effect after Oya restarts.",
            );
            row_divider(ui, p);
            changed |= toggle_row(
                ui,
                p,
                &mut s.block_code_injection,
                "Block code injection into Oya",
                "Stops other programs from loading code into Oya through legacy hooks. A few old input methods or assistive tools may need it off. Takes effect after Oya restarts.",
            );
            if changed {
                s.save();
            }
        });
        ui.add_space(10.0);
        card(ui, p, |ui| {
            row_label(ui, p, "Developer tools", "");
            ui.horizontal_wrapped(|ui| {
                ui.selectable_value(
                    &mut self.devtools_tab,
                    DevToolsTab::LogsAndLowLevel,
                    format!("Logs ({})", self.controller.log_store.events().len()),
                );
                ui.selectable_value(&mut self.devtools_tab, DevToolsTab::Console, "Console");
                ui.selectable_value(&mut self.devtools_tab, DevToolsTab::Processes, "Processes");
            });
            row_divider(ui, p);
            match self.devtools_tab {
                DevToolsTab::LogsAndLowLevel => {
                    let mut open_logs = false;
                    ui.horizontal_wrapped(|ui| {
                        ui.add(
                            egui::TextEdit::singleline(&mut self.log_filter_query)
                                .hint_text("Filter")
                                .desired_width(200.0),
                        );
                        if ui.button("Clear").clicked() {
                            self.controller.log_store.clear();
                        }
                        if ui.button("Open oya://logs").clicked() {
                            open_logs = true;
                        }
                    });
                    let q = self.log_filter_query.trim().to_lowercase();
                    egui::ScrollArea::vertical()
                        .id_salt("oya_log_scroll")
                        .max_height(420.0)
                        .show(ui, |ui| {
                            for ev in self.controller.log_store.events().iter().rev().take(200) {
                                if !q.is_empty()
                                    && !ev.message.to_lowercase().contains(&q)
                                    && !ev.origin.to_lowercase().contains(&q)
                                    && !ev.category.as_str().to_lowercase().contains(&q)
                                {
                                    continue;
                                }
                                let col = match ev.severity {
                                    Severity::LowLevel => p.text_weak,
                                    Severity::Info => p.accent,
                                    Severity::Warn => p.warn,
                                    Severity::Error | Severity::Crash => p.danger,
                                    Severity::Security => p.success,
                                };
                                let width = ui.available_width().max(100.0);
                                let mono = egui::TextStyle::Monospace.resolve(ui.style());
                                let body = egui::TextStyle::Body.resolve(ui.style());
                                let mut job = egui::text::LayoutJob::default();
                                job.append(
                                    &format!("{} · {}  ", ev.severity.as_str(), ev.category.as_str()),
                                    0.0,
                                    egui::text::TextFormat::simple(body, col),
                                );
                                job.append(
                                    &format!("{} — {}", ev.origin, ev.message),
                                    0.0,
                                    egui::text::TextFormat::simple(mono, p.text),
                                );
                                job.wrap = egui::text::TextWrapping {
                                    max_width: width,
                                    break_anywhere: true,
                                    ..Default::default()
                                };
                                let galley = ui.painter().layout_job(job);
                                let (rect, _) = ui.allocate_exact_size(
                                    egui::vec2(width, galley.size().y + 6.0),
                                    egui::Sense::hover(),
                                );
                                ui.painter().galley(rect.min + egui::vec2(0.0, 3.0), galley, p.text);
                            }
                        });
                    if open_logs {
                        self.navigate_active("oya://logs");
                    }
                }
                DevToolsTab::Console => {
                    ui.label(
                        egui::RichText::new("Runs JavaScript in the active tab's page. Only paste code you understand.")
                            .color(p.text_weak)
                            .size(12.5),
                    );
                    ui.horizontal_wrapped(|ui| {
                        let resp = ui.add(
                            egui::TextEdit::singleline(&mut self.js_input)
                                .code_editor()
                                .desired_width(ui.available_width().min(460.0)),
                        );
                        let run = ui.button("Run").clicked()
                            || (resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)));
                        if run {
                            let code = self.js_input.clone();
                            if let Some(twv) = self.webviews.get(&active_tab_id) {
                                let _ = twv.webview.evaluate_script(&code);
                                self.js_output = "Sent to the page.".to_string();
                            } else {
                                self.js_output = match self.controller.eval_js(&code) {
                                    Ok(v) => format!("=> {v}"),
                                    Err(e) => format!("Error: {e}"),
                                };
                            }
                        }
                    });
                    if !self.js_output.is_empty() {
                        ui.monospace(&self.js_output);
                    }
                    let tab = self.controller.tab();
                    for log in &tab.console_logs {
                        ui.add(egui::Label::new(egui::RichText::new(format!("[console] {log}")).monospace()).wrap());
                    }
                    for err in &tab.script_errors {
                        ui.colored_label(p.danger, format!("[error] {err}"));
                    }
                }
                DevToolsTab::Processes => {
                    if ui.button("Close unused Oya renderer processes").clicked() {
                        let _ = self.controller.discard_idle_renderers();
                    }
                    ui.label(format!(
                        "Browser process {} · {} web tab(s) loaded in WebView2 (its processes are managed by Microsoft Edge WebView2)",
                        std::process::id(),
                        self.webviews.len()
                    ));
                    for (origin, pid, sandboxed) in self.controller.active_renderers_info() {
                        ui.monospace(format!(
                            "Oya renderer {pid} · {} · {origin}",
                            if sandboxed { "restricted" } else { "NOT restricted" }
                        ));
                    }
                }
            }
        });
    }


    fn section_about(&mut self, ui: &mut egui::Ui, p: &Palette) {
        card(ui, p, |ui| {
            ui.horizontal(|ui| {
                if let Some(logo) = &self.oya_logo_texture {
                    ui.add(egui::Image::new(logo).fit_to_exact_size(egui::vec2(56.0, 56.0)));
                }
                ui.vertical(|ui| {
                    ui.label(egui::RichText::new("Oya Browser").size(18.0).strong().color(p.text));
                    ui.label(
                        egui::RichText::new(format!("Version {}", env!("CARGO_PKG_VERSION")))
                            .color(p.text_weak),
                    );
                });
            });
            row_divider(ui, p);
            ui.label(egui::RichText::new("Our mission").strong().color(p.text));
            for para in [
                "Oya exists to make browsing fast, safe and light at the same time. Most browsers trade one of these away: they become fast by keeping everything loaded, or safe by piling on background services, and your computer pays for it in memory, battery and heat.",
                "We believe speed and safety must never be bought by wasting your resources. A browser should protect you by default, respond instantly, and still leave your PC free for everything else you run. Balance is the goal: every feature has to earn its place by being secure, quick and frugal together.",
            ] {
                ui.add(egui::Label::new(egui::RichText::new(para).color(p.text)).wrap());
                ui.add_space(4.0);
            }
            row_divider(ui, p);
            ui.label(egui::RichText::new("What Oya does for you").strong().color(p.text));
            ui.add_space(2.0);
            for (title, text) in [
                ("Secure by default", "web pages run in Microsoft Edge WebView2's Chromium sandbox, with HTTPS-First, strict tracker blocking, SmartScreen and Global Privacy Control switched on."),
                ("Changes need your approval", "search engine, home page, download folder, privacy protections and remote control cannot be changed without Windows Hello or your vault PIN, and edits made by other programs are caught and shown to you."),
                ("A password vault locked to your PC", "Argon2id and two layers of encryption, keys tied to your Windows account, Windows Hello sign-in, auto-lock, and filling only on the exact site a password belongs to."),
                ("Protection against malware", "risky downloads wait for your decision, code-injection hooks and planted DLLs are blocked, and pages cannot reach Oya's internals."),
                ("Fast and light", "an optimised native interface, Memory Saver for background tabs, and no telemetry or background sync."),
                ("Panes", "up to four live pages side by side, each resizing to its pane and able to fill the window."),
                ("Media studio", "a 10-band equalizer and video enhancement for the pages you watch, plus playback that can continue in background tabs."),
                ("Calm, minimal design", "readable light and dark themes, a clean tab strip and address bar, and Settings in a single, searchable page."),
            ] {
                // Hanging indent: the dot sits in its own column and every wrapped line of the
                // text starts at the same left edge.
                ui.horizontal_top(|ui| {
                    ui.spacing_mut().item_spacing.x = 0.0;
                    let line_h = ui.text_style_height(&egui::TextStyle::Body);
                    let (dot, _) = ui.allocate_exact_size(egui::vec2(22.0, line_h), egui::Sense::hover());
                    ui.painter().circle_filled(egui::pos2(dot.left() + 6.0, dot.center().y), 3.0, p.accent);
                    let width = ui.available_width();
                    let font = egui::TextStyle::Body.resolve(ui.style());
                    let mut job = egui::text::LayoutJob::default();
                    job.append(title, 0.0, egui::text::TextFormat::simple(font.clone(), p.text));
                    job.append(&format!(" — {text}"), 0.0, egui::text::TextFormat::simple(font, p.text_weak));
                    job.wrap.max_width = width;
                    let galley = ui.painter().layout_job(job);
                    let (rect, _) = ui.allocate_exact_size(egui::vec2(width, galley.size().y), egui::Sense::hover());
                    ui.painter().galley(rect.min, galley, p.text);
                });
                ui.add_space(6.0);
            }
            row_divider(ui, p);
            for (k, v) in [
                ("Web engine", "Microsoft Edge WebView2 (Chromium)"),
                ("Data folder", "%LOCALAPPDATA%\\OyaBrowser (vault in %APPDATA%\\OyaBrowser)"),
            ] {
                ui.horizontal_wrapped(|ui| {
                    ui.label(egui::RichText::new(k).color(p.text_weak));
                    ui.label(egui::RichText::new(v).color(p.text));
                });
            }
            if let Ok(exe) = std::env::current_exe() {
                ui.horizontal_wrapped(|ui| {
                    ui.label(egui::RichText::new("Program").color(p.text_weak));
                    ui.label(egui::RichText::new(exe.display().to_string()).color(p.text).monospace());
                });
            }
        });
    }
}

// =========================================================================
// Design tokens
// =========================================================================

#[derive(Clone, Copy)]
struct Palette {
    /// Window frame behind the tabs, and the settings page background.
    frame: egui::Color32,
    /// Toolbar, active tab, cards and menus.
    surface: egui::Color32,
    /// Address bar and text fields.
    field: egui::Color32,
    control: egui::Color32,
    control_hover: egui::Color32,
    hover: egui::Color32,
    divider: egui::Color32,
    text: egui::Color32,
    text_weak: egui::Color32,
    accent: egui::Color32,
    on_accent: egui::Color32,
    tonal: egui::Color32,
    on_tonal: egui::Color32,
    danger: egui::Color32,
    warn: egui::Color32,
    success: egui::Color32,
}

/// Neutral, low-chroma palette in the style of current Chromium / Material 3 browsers.
/// Every text/background pair used here meets WCAG AA (4.5:1); primary text is above 12:1.
fn palette_for(night: bool) -> Palette {
    use egui::Color32 as C;
    if night {
        Palette {
            frame: C::from_rgb(27, 28, 31),
            surface: C::from_rgb(40, 42, 46),
            field: C::from_rgb(30, 31, 34),
            control: C::from_rgb(52, 54, 59),
            control_hover: C::from_rgb(64, 67, 73),
            hover: C::from_white_alpha(22),
            divider: C::from_rgb(68, 71, 70),
            text: C::from_rgb(227, 227, 227),
            text_weak: C::from_rgb(196, 199, 197),
            accent: C::from_rgb(168, 199, 250),
            on_accent: C::from_rgb(6, 46, 111),
            tonal: C::from_rgb(0, 74, 119),
            on_tonal: C::from_rgb(194, 231, 255),
            danger: C::from_rgb(242, 184, 181),
            warn: C::from_rgb(253, 214, 99),
            success: C::from_rgb(109, 213, 140),
        }
    } else {
        Palette {
            frame: C::from_rgb(233, 238, 246),
            surface: C::from_rgb(255, 255, 255),
            field: C::from_rgb(240, 243, 248),
            control: C::from_rgb(233, 238, 246),
            control_hover: C::from_rgb(220, 227, 237),
            hover: C::from_black_alpha(18),
            divider: C::from_rgb(218, 220, 224),
            text: C::from_rgb(31, 31, 31),
            text_weak: C::from_rgb(68, 71, 70),
            accent: C::from_rgb(11, 87, 208),
            on_accent: C::from_rgb(255, 255, 255),
            tonal: C::from_rgb(211, 227, 253),
            on_tonal: C::from_rgb(4, 30, 73),
            danger: C::from_rgb(179, 38, 30),
            warn: C::from_rgb(146, 92, 0),
            success: C::from_rgb(20, 108, 46),
        }
    }
}

// =========================================================================
// WebView2 configuration helpers
// =========================================================================

/// Command-line switches for the WebView2 browser process. They are fixed when the first tab's
/// WebView2 environment is created, so changes need a restart.
fn webview2_browser_args(settings: &BrowserSettings) -> String {
    let mut args = vec![
        "--disk-cache-size=268435456",
        "--disable-sync",
        "--disable-translate",
        "--disable-default-apps",
        "--no-first-run",
        "--enable-features=PlatformHEVCDecoderSupport,WebAuthenticationHybridTransport",
    ];
    if settings.hardware_acceleration_enabled {
        args.extend(["--enable-gpu-rasterization", "--enable-zero-copy"]);
    } else {
        args.extend(["--disable-gpu", "--disable-gpu-compositing"]);
    }
    let mut out = args.join(" ");
    // `language_tag` only returns [A-Za-z0-9-], so this cannot inject another switch.
    if let Some(tag) = settings.language_tag() {
        out.push_str(&format!(" --lang={tag}"));
    }
    out
}

/// Global Privacy Control signal (https://globalprivacycontrol.org), defined before page scripts.
const GPC_SCRIPT: &str = r#"(function(){try{Object.defineProperty(Navigator.prototype,"globalPrivacyControl",{get:function(){return true;},configurable:true});}catch(_){}})();"#;

enum NavDecision {
    Allow,
    /// Plain-HTTP navigation to this host.
    Http(String),
    Block,
}

/// Top-level navigations are limited to web pages and a few safe internal schemes. `file:`,
/// `javascript:`, `data:` and custom protocol handlers are refused.
fn classify_navigation(url: &str) -> NavDecision {
    let lower = url.trim_start().to_ascii_lowercase();
    if lower.starts_with("https://")
        || lower.starts_with("about:blank")
        || lower.starts_with("about:srcdoc")
        || lower.starts_with("blob:https://")
    {
        return NavDecision::Allow;
    }
    if let Some(rest) = lower.strip_prefix("http://") {
        let host = rest.split(['/', '?', '#']).next().unwrap_or("");
        let host = host.rsplit_once('@').map(|(_, h)| h).unwrap_or(host);
        let host = if host.starts_with('[') {
            host.split(']').next().map(|h| format!("{h}]")).unwrap_or_default()
        } else {
            host.split(':').next().unwrap_or("").to_string()
        };
        return NavDecision::Http(host);
    }
    NavDecision::Block
}

/// Hosts that commonly have no HTTPS: loopback, `.local`/`.localhost` names and private IPv4.
fn is_local_host(host: &str) -> bool {
    if host == "localhost"
        || host.ends_with(".localhost")
        || host.ends_with(".local")
        || host == "[::1]"
        || !host.contains('.')
    {
        return true;
    }
    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        return ip.is_loopback() || ip.is_private() || ip.is_link_local();
    }
    false
}

/// Sends a JSON message to the page bridge (WebView2 `PostWebMessageAsJson`). Unlike running a
/// script, this needs no function that page scripts could also see or replace.
fn post_to_page(webview: &WebView, msg: &serde_json::Value) -> bool {
    let mut json = msg.to_string();
    let wide = windows_core::HSTRING::from(json.as_str());
    json.zeroize();
    // SAFETY: COM call on the UI thread that owns this WebView2 instance.
    unsafe { webview.webview().PostWebMessageAsJson(&wide).is_ok() }
}

/// Sets the WebView2 profile's tracking-prevention level (Strict when blocking third-party
/// trackers, otherwise WebView2's default Balanced).
fn set_tracking_prevention(webview: &WebView, strict: bool) -> Result<(), String> {
    use webview2_com::Microsoft::Web::WebView2::Win32::{
        COREWEBVIEW2_TRACKING_PREVENTION_LEVEL_BALANCED,
        COREWEBVIEW2_TRACKING_PREVENTION_LEVEL_STRICT, ICoreWebView2_13, ICoreWebView2Profile3,
    };
    use windows_core::Interface;
    let core = webview.webview();
    // SAFETY: plain COM calls on interfaces obtained from a live WebView2 instance, made on the
    // UI thread that owns it, as WebView2 requires.
    unsafe {
        let wv13: ICoreWebView2_13 = core.cast().map_err(|e| e.to_string())?;
        let profile = wv13.Profile().map_err(|e| e.to_string())?;
        let profile3: ICoreWebView2Profile3 = profile.cast().map_err(|e| e.to_string())?;
        profile3
            .SetPreferredTrackingPreventionLevel(if strict {
                COREWEBVIEW2_TRACKING_PREVENTION_LEVEL_STRICT
            } else {
                COREWEBVIEW2_TRACKING_PREVENTION_LEVEL_BALANCED
            })
            .map_err(|e| e.to_string())
    }
}

/// Syncs WebView2's `prefers-color-scheme` with Oya Browser's Day/Night mode so websites
/// follow the browser theme instead of staying light when Windows is in light mode.
fn set_preferred_color_scheme(webview: &WebView, dark: bool) -> Result<(), String> {
    use webview2_com::Microsoft::Web::WebView2::Win32::{
        COREWEBVIEW2_PREFERRED_COLOR_SCHEME_DARK, COREWEBVIEW2_PREFERRED_COLOR_SCHEME_LIGHT,
        ICoreWebView2_13,
    };
    use windows_core::Interface;
    let core = webview.webview();
    // SAFETY: plain COM calls on interfaces obtained from a live WebView2 instance, made on the
    // UI thread that owns it, as WebView2 requires.
    unsafe {
        let wv13: ICoreWebView2_13 = core.cast().map_err(|e| e.to_string())?;
        let profile = wv13.Profile().map_err(|e| e.to_string())?;
        profile
            .SetPreferredColorScheme(if dark {
                COREWEBVIEW2_PREFERRED_COLOR_SCHEME_DARK
            } else {
                COREWEBVIEW2_PREFERRED_COLOR_SCHEME_LIGHT
            })
            .map_err(|e| e.to_string())
    }
}

// =========================================================================
// Small helpers
// =========================================================================

#[derive(Clone, Copy, PartialEq, Eq)]
enum SiteSecurity {
    Secure,
    Insecure,
    Internal,
    Other,
}

impl SiteSecurity {
    fn of(url: &str) -> Self {
        if url.starts_with("https://") {
            SiteSecurity::Secure
        } else if url.starts_with("http://") {
            SiteSecurity::Insecure
        } else if url.starts_with("oya://") || url.starts_with("rustchrome://") {
            SiteSecurity::Internal
        } else {
            SiteSecurity::Other
        }
    }
}

fn host_of(url: &str) -> String {
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.trim_start_matches("www.").to_string()))
        .unwrap_or_else(|| url.to_string())
}

fn tab_title(tab: &crate::tab_manager::TabState) -> String {
    if is_settings_url(&tab.current_url) {
        return "Settings".to_string();
    }
    let t = tab.title.trim();
    if t.is_empty() || t == tab.current_url {
        host_of(&tab.current_url)
    } else {
        t.to_string()
    }
}

fn favicon_letter(url: &str) -> char {
    host_of(url)
        .chars()
        .find(|c| c.is_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .unwrap_or('•')
}

/// Address-bar text with the registrable host emphasised and the rest dimmed (anti-spoofing cue),
/// as in Chromium. While editing, all text uses the normal colour.
fn url_layout_job(
    text: &str,
    emphasise_host: bool,
    text_color: egui::Color32,
    weak_color: egui::Color32,
    ui: &egui::Ui,
) -> egui::text::LayoutJob {
    let font = egui::TextStyle::Body.resolve(ui.style());
    let mut job = egui::text::LayoutJob::default();
    let fmt = |c| egui::text::TextFormat::simple(font.clone(), c);
    let host_range = if emphasise_host && (text.starts_with("https://") || text.starts_with("http://")) {
        let start = text.find("://").map(|i| i + 3).unwrap_or(0);
        let end = text[start..]
            .find(['/', '?', '#'])
            .map(|i| start + i)
            .unwrap_or(text.len());
        Some((start, end))
    } else {
        None
    };
    match host_range {
        Some((start, end)) => {
            job.append(&text[..start], 0.0, fmt(weak_color));
            job.append(&text[start..end], 0.0, fmt(text_color));
            job.append(&text[end..], 0.0, fmt(weak_color));
        }
        None => job.append(text, 0.0, fmt(text_color)),
    }
    job
}

struct TabPaint {
    id: u64,
    title: String,
    badge: char,
    internal: bool,
    loading: bool,
    active: bool,
    background_media: bool,
    can_close: bool,
}

struct TabOutput {
    response: egui::Response,
    close_clicked: bool,
    highlighted: bool,
}

/// One tab in the strip: active tab merges with the toolbar surface; inactive tabs are flat with a
/// hover fill and hairline separators; close button on hover/active; title truncated with "…".
fn draw_tab(
    ui: &mut egui::Ui,
    p: &Palette,
    tab: &TabPaint,
    size: egui::Vec2,
    prev_highlight: bool,
    logo: Option<&egui::TextureHandle>,
) -> TabOutput {
    let (_, rect) = ui.allocate_space(size);
    let response = ui.interact(
        rect,
        egui::Id::unique(("oya_tab", tab.id)),
        egui::Sense::click_and_drag(),
    );
    let hovered = response.hovered();
    let painter = ui.painter().clone();
    if tab.active {
        painter.rect_filled(
            rect,
            egui::CornerRadius { nw: 10, ne: 10, sw: 0, se: 0 },
            p.surface,
        );
    } else if hovered {
        painter.rect_filled(rect.shrink2(egui::vec2(2.0, 3.0)), 8.0, p.hover);
    }
    let highlighted = tab.active || hovered;
    if !highlighted && !prev_highlight {
        let x = rect.left();
        painter.line_segment(
            [egui::pos2(x, rect.center().y - 9.0), egui::pos2(x, rect.center().y + 9.0)],
            egui::Stroke::new(1.0, p.divider),
        );
    }

    let icon_c = egui::pos2(rect.left() + 20.0, rect.center().y);
    if tab.loading {
        ui.put(
            egui::Rect::from_center_size(icon_c, egui::vec2(16.0, 16.0)),
            egui::Spinner::new().size(14.0).color(p.accent),
        );
    } else if tab.internal {
        if let Some(logo) = logo {
            painter.image(
                logo.id(),
                egui::Rect::from_center_size(icon_c, egui::vec2(16.0, 16.0)),
                egui::Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(1.0, 1.0)),
                egui::Color32::WHITE,
            );
        }
    } else {
        painter.circle_filled(icon_c, 8.0, p.tonal);
        painter.text(
            icon_c,
            egui::Align2::CENTER_CENTER,
            tab.badge,
            egui::FontId::proportional(10.0),
            p.on_tonal,
        );
    }
    if tab.background_media {
        painter.circle_filled(icon_c + egui::vec2(6.0, 6.0), 3.0, p.accent);
    }

    let show_close = tab.can_close && (tab.active || hovered || size.x >= 120.0);
    let close_c = egui::pos2(rect.right() - 16.0, rect.center().y);
    let mut close_clicked = false;
    if show_close {
        let close_rect = egui::Rect::from_center_size(close_c, egui::vec2(20.0, 20.0));
        let close = ui.interact(close_rect, egui::Id::unique(("oya_tab_close", tab.id)), egui::Sense::click());
        if close.hovered() {
            painter.circle_filled(close_c, 10.0, p.hover);
        }
        paint_icon(&painter, Icon::CloseSmall, close_c, p.text_weak);
        close.widget_info(|| egui::WidgetInfo::labeled(egui::Role::Button, true, "Close tab"));
        close_clicked = close.clicked();
    }

    let text_left = icon_c.x + 14.0;
    let text_right = if show_close { close_c.x - 14.0 } else { rect.right() - 10.0 };
    if text_right > text_left + 8.0 {
        let color = if tab.active { p.text } else { p.text_weak };
        let mut job = egui::text::LayoutJob::single_section(
            tab.title.clone(),
            egui::text::TextFormat::simple(egui::FontId::proportional(13.0), color),
        );
        job.wrap = egui::text::TextWrapping::truncate_at_width(text_right - text_left);
        let galley = painter.layout_job(job);
        let pos = egui::pos2(text_left, rect.center().y - galley.size().y / 2.0);
        painter.galley(pos, galley, color);
    }
    let title = tab.title.clone();
    let active = tab.active;
    response.widget_info(|| egui::WidgetInfo::selected(egui::Role::Tab, true, active, &title));
    TabOutput {
        response,
        close_clicked,
        highlighted,
    }
}

#[derive(Clone, Copy)]
enum Icon {
    Back,
    Forward,
    Reload,
    Close,
    CloseSmall,
    Home,
    Menu,
    Equalizer,
    Star,
    StarFilled,
    Key,
    Lock,
    Warning,
    Plus,
    Minus,
    Fullscreen,
    Search,
    Check,
    Panes,
    Downloads,
}

/// Simple 16px line icons drawn with the painter (no icon font needed).
fn paint_icon(painter: &egui::Painter, icon: Icon, c: egui::Pos2, color: egui::Color32) {
    let s = egui::Stroke::new(1.6, color);
    let p = |x: f32, y: f32| egui::pos2(c.x + x, c.y + y);
    match icon {
        Icon::Back | Icon::Forward => {
            let d = if matches!(icon, Icon::Back) { -1.0 } else { 1.0 };
            painter.line_segment([p(-6.0 * d, 0.0), p(6.0 * d, 0.0)], s);
            painter.line_segment([p(6.0 * d, 0.0), p(1.0 * d, -5.0)], s);
            painter.line_segment([p(6.0 * d, 0.0), p(1.0 * d, 5.0)], s);
        }
        Icon::Reload => {
            let r = 6.0;
            let pts: Vec<egui::Pos2> = (0..=24)
                .map(|i| {
                    let a = (-60.0_f32 + 290.0 * i as f32 / 24.0).to_radians();
                    p(r * a.cos(), r * a.sin())
                })
                .collect();
            painter.add(egui::Shape::line(pts, s));
            let a = (-60.0_f32).to_radians();
            let tip = p(r * a.cos(), r * a.sin());
            painter.line_segment([tip, tip + egui::vec2(-4.5, -0.5)], s);
            painter.line_segment([tip, tip + egui::vec2(0.5, 4.5)], s);
        }
        Icon::Close | Icon::CloseSmall => {
            let k = if matches!(icon, Icon::Close) { 5.0 } else { 4.0 };
            painter.line_segment([p(-k, -k), p(k, k)], s);
            painter.line_segment([p(-k, k), p(k, -k)], s);
        }
        Icon::Home => {
            painter.line_segment([p(-7.0, 0.0), p(0.0, -6.5)], s);
            painter.line_segment([p(0.0, -6.5), p(7.0, 0.0)], s);
            painter.add(egui::Shape::line(
                vec![p(-5.0, -1.5), p(-5.0, 6.0), p(5.0, 6.0), p(5.0, -1.5)],
                s,
            ));
        }
        Icon::Menu => {
            for y in [-5.0, 0.0, 5.0] {
                painter.circle_filled(p(0.0, y), 1.7, color);
            }
        }
        Icon::Equalizer => {
            for (x, top, knob) in [(-5.0, -6.0, 2.0), (0.0, -6.0, -3.0), (5.0, -6.0, 1.0)] {
                painter.line_segment([p(x, top), p(x, 6.0)], s);
                painter.circle_filled(p(x, knob), 2.2, color);
            }
        }
        Icon::Star | Icon::StarFilled => {
            let pts: Vec<egui::Pos2> = (0..10)
                .map(|i| {
                    let r = if i % 2 == 0 { 7.0 } else { 3.0 };
                    let a = (-90.0 + i as f32 * 36.0_f32).to_radians();
                    p(r * a.cos(), r * a.sin())
                })
                .collect();
            if matches!(icon, Icon::StarFilled) {
                painter.add(egui::Shape::convex_polygon(pts.clone(), color, egui::Stroke::NONE));
                // A concave star drawn as a convex polygon leaves gaps; outline it as well.
                painter.add(egui::Shape::closed_line(pts, s));
                painter.circle_filled(c, 3.2, color);
            } else {
                painter.add(egui::Shape::closed_line(pts, s));
            }
        }
        Icon::Key => {
            painter.circle_stroke(p(-3.5, 0.0), 3.5, s);
            painter.line_segment([p(0.0, 0.0), p(7.0, 0.0)], s);
            painter.line_segment([p(4.5, 0.0), p(4.5, 3.0)], s);
            painter.line_segment([p(7.0, 0.0), p(7.0, 3.0)], s);
        }
        Icon::Lock => {
            let body = egui::Rect::from_center_size(p(0.0, 2.0), egui::vec2(10.0, 8.0));
            painter.rect_stroke(body, 2.0, s, egui::StrokeKind::Middle);
            let pts: Vec<egui::Pos2> = (0..=12)
                .map(|i| {
                    let a = (180.0_f32 + 180.0 * i as f32 / 12.0).to_radians();
                    p(3.0 * a.cos(), -2.0 + 3.0 * a.sin())
                })
                .collect();
            painter.add(egui::Shape::line(pts, s));
        }
        Icon::Warning => {
            painter.add(egui::Shape::closed_line(vec![p(0.0, -6.5), p(7.0, 6.0), p(-7.0, 6.0)], s));
            painter.line_segment([p(0.0, -2.0), p(0.0, 2.0)], s);
            painter.circle_filled(p(0.0, 4.0), 1.0, color);
        }
        Icon::Plus => {
            painter.line_segment([p(-6.0, 0.0), p(6.0, 0.0)], s);
            painter.line_segment([p(0.0, -6.0), p(0.0, 6.0)], s);
        }
        Icon::Minus => {
            painter.line_segment([p(-6.0, 0.0), p(6.0, 0.0)], s);
        }
        Icon::Fullscreen => {
            for (sx, sy) in [(-1.0, -1.0), (1.0, -1.0), (-1.0, 1.0), (1.0, 1.0)] {
                painter.line_segment([p(6.0 * sx, 6.0 * sy), p(6.0 * sx, 2.5 * sy)], s);
                painter.line_segment([p(6.0 * sx, 6.0 * sy), p(2.5 * sx, 6.0 * sy)], s);
            }
        }
        Icon::Search => {
            painter.circle_stroke(p(-1.5, -1.5), 4.5, s);
            painter.line_segment([p(2.0, 2.0), p(6.0, 6.0)], s);
        }
        Icon::Panes => {
            for (dx, dy) in [(-4.0, -4.0), (4.0, -4.0), (-4.0, 4.0), (4.0, 4.0)] {
                painter.rect_stroke(
                    egui::Rect::from_center_size(p(dx, dy), egui::vec2(6.5, 6.5)),
                    1.5,
                    s,
                    egui::StrokeKind::Middle,
                );
            }
        }
        Icon::Check => {
            painter.line_segment([p(-5.0, 0.0), p(-1.5, 4.0)], s);
            painter.line_segment([p(-1.5, 4.0), p(5.5, -4.5)], s);
        }
        Icon::Downloads => {
            painter.line_segment([p(0.0, -6.5), p(0.0, 2.5)], s);
            painter.line_segment([p(0.0, 2.5), p(-4.0, -1.5)], s);
            painter.line_segment([p(0.0, 2.5), p(4.0, -1.5)], s);
            painter.add(egui::Shape::line(
                vec![p(-6.0, 3.0), p(-6.0, 6.0), p(6.0, 6.0), p(6.0, 3.0)],
                s,
            ));
        }
    }
}

/// 32px round icon button with hover fill; `selected` shows a tonal background.
/// The label is exposed to screen readers (no floating tooltip: it would be hidden behind the page).
fn icon_button(
    ui: &mut egui::Ui,
    p: &Palette,
    icon: Icon,
    enabled: bool,
    selected: bool,
    label: &str,
) -> egui::Response {
    let sense = if enabled {
        egui::Sense::click()
    } else {
        egui::Sense::hover()
    };
    let (rect, resp) = ui.allocate_exact_size(egui::vec2(34.0, 34.0), sense);
    let painter = ui.painter();
    if selected {
        painter.circle_filled(rect.center(), 16.0, p.tonal);
    } else if enabled && resp.hovered() {
        painter.circle_filled(rect.center(), 16.0, p.hover);
    }
    let color = if !enabled {
        p.text_weak.gamma_multiply(0.45)
    } else if selected {
        p.on_tonal
    } else {
        p.text
    };
    paint_icon(painter, icon, rect.center(), color);
    let label = label.to_string();
    resp.widget_info(|| egui::WidgetInfo::labeled(egui::Role::Button, enabled, &label));
    resp
}

fn paint_inline_icon(ui: &mut egui::Ui, icon: Icon, color: egui::Color32) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(20.0, 20.0), egui::Sense::hover());
    paint_icon(ui.painter(), icon, rect.center(), color);
}

fn menu_item(
    ui: &mut egui::Ui,
    p: &Palette,
    label: &str,
    shortcut: &str,
    checked: Option<bool>,
) -> egui::Response {
    let w = ui.available_width();
    let (rect, resp) = ui.allocate_exact_size(egui::vec2(w, 32.0), egui::Sense::click());
    let painter = ui.painter();
    if resp.hovered() {
        painter.rect_filled(rect, 6.0, p.hover);
    }
    let mut x = rect.left() + 12.0;
    if let Some(on) = checked {
        if on {
            paint_icon(painter, Icon::Check, egui::pos2(x + 7.0, rect.center().y), p.accent);
        }
        x += 24.0;
    }
    let font = egui::TextStyle::Body.resolve(ui.style());
    painter.text(egui::pos2(x, rect.center().y), egui::Align2::LEFT_CENTER, label, font, p.text);
    if !shortcut.is_empty() {
        painter.text(
            egui::pos2(rect.right() - 12.0, rect.center().y),
            egui::Align2::RIGHT_CENTER,
            shortcut,
            egui::FontId::proportional(12.0),
            p.text_weak,
        );
    }
    let label = label.to_string();
    match checked {
        Some(on) => resp.widget_info(|| egui::WidgetInfo::selected(egui::Role::MenuItemCheckBox, true, on, &label)),
        None => resp.widget_info(|| egui::WidgetInfo::labeled(egui::Role::MenuItem, true, &label)),
    }
    resp
}

fn menu_divider(ui: &mut egui::Ui, p: &Palette) {
    ui.add_space(3.0);
    let (rect, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), 1.0), egui::Sense::hover());
    ui.painter().rect_filled(rect, 0.0, p.divider);
    ui.add_space(3.0);
}

fn nav_item(ui: &mut egui::Ui, p: &Palette, label: &str, selected: bool) -> egui::Response {
    let w = ui.available_width();
    let (rect, resp) = ui.allocate_exact_size(egui::vec2(w, 36.0), egui::Sense::click());
    let painter = ui.painter();
    if selected {
        painter.rect_filled(rect, egui::CornerRadius { nw: 0, sw: 0, ne: 18, se: 18 }, p.tonal);
    } else if resp.hovered() {
        painter.rect_filled(rect, egui::CornerRadius { nw: 0, sw: 0, ne: 18, se: 18 }, p.hover);
    }
    let font = egui::TextStyle::Body.resolve(ui.style());
    painter.text(
        egui::pos2(rect.left() + 20.0, rect.center().y),
        egui::Align2::LEFT_CENTER,
        label,
        font,
        if selected { p.on_tonal } else { p.text },
    );
    let label = label.to_string();
    resp.widget_info(|| egui::WidgetInfo::selected(egui::Role::Tab, true, selected, &label));
    resp
}

fn section_heading(ui: &mut egui::Ui, p: &Palette, title: &str) {
    ui.add_space(6.0);
    ui.label(egui::RichText::new(title).size(17.0).color(p.text));
    ui.add_space(6.0);
}

fn card(ui: &mut egui::Ui, p: &Palette, add: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::new()
        .fill(p.surface)
        .corner_radius(12.0)
        .inner_margin(egui::Margin::symmetric(20, 14))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add(ui);
        });
}

fn row_label(ui: &mut egui::Ui, p: &Palette, title: &str, subtitle: &str) {
    ui.vertical(|ui| {
        ui.label(egui::RichText::new(title).color(p.text));
        if !subtitle.is_empty() {
            ui.add(egui::Label::new(egui::RichText::new(subtitle).color(p.text_weak).size(12.5)).wrap());
        }
    });
}

fn row_divider(ui: &mut egui::Ui, p: &Palette) {
    ui.add_space(4.0);
    let (rect, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), 1.0), egui::Sense::hover());
    ui.painter().rect_filled(rect, 0.0, p.divider);
    ui.add_space(4.0);
}

/// A bookmarks-bar item: plain text with a rounded, slightly darkened fill on hover (like the
/// tabs). Returns `None` if it does not fit in `max_w`.
fn bar_chip(
    ui: &mut egui::Ui,
    p: &Palette,
    text: &str,
    color: egui::Color32,
    max_w: f32,
) -> Option<egui::Response> {
    let font = egui::FontId::proportional(12.5);
    let galley = ui.painter().layout_no_wrap(text.to_string(), font, color);
    let size = egui::vec2(galley.size().x + 20.0, 26.0);
    if size.x > max_w {
        return None;
    }
    let (rect, resp) = ui.allocate_exact_size(size, egui::Sense::click());
    if resp.hovered() {
        ui.painter().rect_filled(rect, 8.0, p.hover);
    }
    let pos = egui::pos2(rect.left() + 10.0, rect.center().y - galley.size().y / 2.0);
    ui.painter().galley(pos, galley, color);
    let label = text.to_string();
    resp.widget_info(|| egui::WidgetInfo::labeled(egui::Role::Link, true, &label));
    Some(resp)
}

/// One column of a [`table_row`] table: relative width `weight`, never narrower than `min`.
struct TableCol {
    title: &'static str,
    weight: f32,
    min: f32,
}

impl TableCol {
    const fn new(title: &'static str, weight: f32, min: f32) -> Self {
        Self { title, weight, min }
    }
}

const TABLE_GAP: f32 = 12.0;

/// Splits `avail` (minus the actions area `tail`) between the columns. Each column first gets
/// room for its widest text (`content`, at least its minimum), so nothing is cut when the table
/// fits; leftover space is shared by weight so the table always uses the full width. Only when
/// the window is too narrow are columns shrunk (text then ends with "…").
fn table_widths(avail: f32, cols: &[TableCol], tail: f32, content: &[f32]) -> Vec<f32> {
    let gaps = TABLE_GAP * cols.len() as f32;
    let space = (avail - tail - gaps - 10.0).max(0.0);
    let want: Vec<f32> = cols
        .iter()
        .enumerate()
        .map(|(i, c)| c.min.max(content.get(i).copied().unwrap_or(0.0) + 4.0))
        .collect();
    let want_total: f32 = want.iter().sum();
    if space <= want_total {
        return want.iter().map(|w| space * w / want_total.max(0.001)).collect();
    }
    let weight_total: f32 = cols.iter().map(|c| c.weight).sum::<f32>().max(0.001);
    let extra = space - want_total;
    want.iter()
        .zip(cols)
        .map(|(w, c)| w + extra * c.weight / weight_total)
        .collect()
}

/// Widest single-line width of each column (header and cells), for [`table_widths`].
fn column_content_widths<'a>(
    ui: &egui::Ui,
    cols: &[TableCol],
    rows: impl Iterator<Item = Vec<&'a str>>,
) -> Vec<f32> {
    let measure = |text: &str, size: f32| {
        ui.painter()
            .layout_no_wrap(text.to_string(), egui::FontId::proportional(size), egui::Color32::WHITE)
            .size()
            .x
    };
    let mut widths: Vec<f32> = cols.iter().map(|c| measure(c.title, 12.5)).collect();
    for row in rows.take(300) {
        for (i, text) in row.iter().enumerate() {
            if let Some(w) = widths.get_mut(i) {
                *w = w.max(measure(text, 14.0));
            }
        }
    }
    widths
}

fn paint_cell(painter: &egui::Painter, rect: egui::Rect, text: &str, color: egui::Color32, size: f32) {
    let mut job = egui::text::LayoutJob::single_section(
        text.replace('\n', " "),
        egui::text::TextFormat::simple(egui::FontId::proportional(size), color),
    );
    job.wrap = egui::text::TextWrapping::truncate_at_width(rect.width().max(1.0));
    let galley = painter.layout_job(job);
    let pos = egui::pos2(rect.left(), rect.center().y - galley.size().y / 2.0);
    painter.galley(pos, galley, color);
}

fn table_header(ui: &mut egui::Ui, p: &Palette, cols: &[TableCol], widths: &[f32], tail: f32) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), 26.0), egui::Sense::hover());
    let painter = ui.painter();
    let mut x = rect.left() + 10.0;
    for (c, w) in cols.iter().zip(widths) {
        let cell = egui::Rect::from_min_size(egui::pos2(x, rect.top()), egui::vec2(*w, rect.height()));
        paint_cell(painter, cell, c.title, p.text_weak, 12.5);
        x += w + TABLE_GAP;
    }
    let _ = tail;
}

/// A borderless table row: cells are single lines (cut with "…" if needed), the row gets a
/// rounded darker fill on hover, and `actions` draws buttons right-aligned in the last `tail`
/// pixels. The returned response is for the whole row (click / hover tooltip).
fn table_row(
    ui: &mut egui::Ui,
    p: &Palette,
    id: egui::Id,
    widths: &[f32],
    cells: &[(String, egui::Color32)],
    tail: f32,
    actions: impl FnOnce(&mut egui::Ui),
) -> egui::Response {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), 34.0), egui::Sense::hover());
    let resp = ui.interact(rect, id, egui::Sense::click());
    if ui.rect_contains_pointer(rect) {
        ui.painter().rect_filled(rect, 8.0, p.hover);
    }
    let painter = ui.painter().clone();
    let mut x = rect.left() + 10.0;
    for ((text, color), w) in cells.iter().zip(widths) {
        let cell = egui::Rect::from_min_size(egui::pos2(x, rect.top()), egui::vec2(*w, rect.height()));
        paint_cell(&painter, cell, text, *color, 14.0);
        x += w + TABLE_GAP;
    }
    let tail_rect = egui::Rect::from_min_max(
        egui::pos2(rect.right() - tail, rect.top()),
        egui::pos2(rect.right() - 6.0, rect.bottom()),
    );
    let mut tail_ui = ui.new_child(
        egui::UiBuilder::new()
            .max_rect(tail_rect)
            .layout(egui::Layout::right_to_left(egui::Align::Center)),
    );
    actions(&mut tail_ui);
    resp
}

/// `YYYY-MM-DD` for a Unix time in milliseconds (UTC).
fn format_date(ms: u64) -> String {
    if ms == 0 {
        return String::new();
    }
    // Howard Hinnant's days-to-civil algorithm.
    let z = (ms / 86_400_000) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    format!("{y:04}-{m:02}-{d:02}")
}

/// Title + optional description on the left, switch on the right. Returns `true` when toggled.
fn toggle_row(ui: &mut egui::Ui, p: &Palette, value: &mut bool, title: &str, subtitle: &str) -> bool {
    let mut changed = false;
    ui.horizontal(|ui| {
        let text_w = (ui.available_width() - 60.0).max(120.0);
        ui.vertical(|ui| {
            ui.set_width(text_w);
            ui.add(egui::Label::new(egui::RichText::new(title).color(p.text)).wrap());
            if !subtitle.is_empty() {
                ui.add(egui::Label::new(egui::RichText::new(subtitle).color(p.text_weak).size(12.5)).wrap());
            }
        });
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            changed = toggle_switch(ui, p, value, title).changed();
        });
    });
    changed
}

fn toggle_switch(ui: &mut egui::Ui, p: &Palette, on: &mut bool, label: &str) -> egui::Response {
    let (rect, mut resp) = ui.allocate_exact_size(egui::vec2(40.0, 22.0), egui::Sense::click());
    if resp.clicked() {
        *on = !*on;
        resp.mark_changed();
    }
    let state = *on;
    let label = label.to_string();
    resp.widget_info(|| egui::WidgetInfo::selected(egui::Role::Switch, true, state, &label));
    let t = ui.ctx().animate_bool_responsive(resp.id, *on);
    let painter = ui.painter();
    let radius = rect.height() / 2.0;
    let track = if *on { p.accent } else { p.control_hover };
    painter.rect_filled(rect, radius, track);
    if !*on {
        painter.rect_stroke(rect, radius, egui::Stroke::new(1.0, p.text_weak), egui::StrokeKind::Inside);
    }
    let x = egui::lerp((rect.left() + radius)..=(rect.right() - radius), t);
    let knob = if *on { p.on_accent } else { p.text_weak };
    painter.circle_filled(egui::pos2(x, rect.center().y), radius * if *on { 0.72 } else { 0.55 }, knob);
    resp
}

fn infobar_frame(p: &Palette) -> egui::Frame {
    egui::Frame::new().fill(p.tonal).inner_margin(egui::Margin::symmetric(12, 6))
}

fn to_egui_color(c: Color) -> egui::Color32 {
    egui::Color32::from_rgba_unmultiplied(c.r, c.g, c.b, c.a)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contrast(a: egui::Color32, b: egui::Color32) -> f32 {
        fn lum(c: egui::Color32) -> f32 {
            let ch = |v: u8| {
                let s = v as f32 / 255.0;
                if s <= 0.03928 { s / 12.92 } else { ((s + 0.055) / 1.055).powf(2.4) }
            };
            0.2126 * ch(c.r()) + 0.7152 * ch(c.g()) + 0.0722 * ch(c.b())
        }
        let (l1, l2) = (lum(a), lum(b));
        (l1.max(l2) + 0.05) / (l1.min(l2) + 0.05)
    }

    #[test]
    fn palette_text_meets_wcag_aa() {
        for night in [false, true] {
            let p = palette_for(night);
            for (fg, bg, what) in [
                (p.text, p.surface, "text/surface"),
                (p.text, p.frame, "text/frame"),
                (p.text, p.field, "text/field"),
                (p.text, p.control, "text/control"),
                (p.text, p.control_hover, "text/control_hover"),
                (p.text_weak, p.surface, "weak/surface"),
                (p.text_weak, p.frame, "weak/frame (inactive tab)"),
                (p.on_tonal, p.tonal, "selected item"),
                (p.on_accent, p.accent, "primary button"),
                (p.danger, p.surface, "danger/surface"),
            ] {
                let r = contrast(fg, bg);
                assert!(r >= 4.5, "night={night} {what}: {r:.2}");
            }
        }
    }

    #[test]
    fn navigation_scheme_policy() {
        assert!(matches!(classify_navigation("https://example.com/"), NavDecision::Allow));
        assert!(matches!(classify_navigation("about:blank"), NavDecision::Allow));
        for bad in [
            "file:///C:/Windows/win.ini",
            "javascript:alert(1)",
            "data:text/html,<script>1</script>",
            "ms-settings:privacy",
            "search-ms:query=x",
        ] {
            assert!(matches!(classify_navigation(bad), NavDecision::Block), "{bad}");
        }
        match classify_navigation("http://user@Example.com:8080/x") {
            NavDecision::Http(h) => assert_eq!(h, "example.com"),
            _ => panic!("expected Http"),
        }
        assert!(is_local_host("localhost"));
        assert!(is_local_host("192.168.1.10"));
        assert!(is_local_host("router"));
        assert!(!is_local_host("example.com"));
        assert!(!is_local_host("8.8.8.8"));
    }

    #[test]
    fn smartscreen_is_never_switched_off() {
        let mut s = BrowserSettings::default();
        for hw in [true, false] {
            s.hardware_acceleration_enabled = hw;
            let args = webview2_browser_args(&s).to_ascii_lowercase();
            assert!(!args.contains("smartscreen"), "{args}");
            assert!(!args.contains("--disable-features"), "{args}");
        }
    }

    #[test]
    fn risky_downloads_and_protected_settings() {
        assert!(is_risky_download("setup.EXE"));
        assert!(is_risky_download("invoice.pdf.js"));
        assert!(!is_risky_download("report.pdf"));
        let old = BrowserSettings::default();
        let mut new = old.clone();
        new.block_third_party_cookies = true; // already on: not a change
        assert!(security::protected_changes(&old, &new).is_empty());
        new.search_engine = SearchEngine::Bing;
        new.https_first_mode = false;
        assert_eq!(security::protected_changes(&old, &new).len(), 2);
    }

    #[test]
    fn language_switch_cannot_inject_arguments() {
        let mut s = BrowserSettings::default();
        assert!(webview2_browser_args(&s).contains("--lang=en-US"));
        s.preferred_language = "en --remote-debugging-port=9222".to_string();
        assert!(webview2_browser_args(&s).ends_with(" --lang=en"));
        s.preferred_language = "--remote-debugging-port=9222".to_string();
        assert!(!webview2_browser_args(&s).contains("remote-debugging"));
    }
}
