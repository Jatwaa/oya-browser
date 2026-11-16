#![forbid(unsafe_code)]

use boa_engine::object::ObjectInitializer;
use boa_engine::object::builtins::JsArray;
use boa_engine::property::Attribute;
use boa_engine::{
    Context, JsArgs, JsNativeError, JsObject, JsResult, JsValue, NativeFunction, Source, js_string,
};
use rc_dom::{ArenaDom, NodeData, NodeId};
use rc_log::{DiagnosticEvent, LogCategory, Severity};
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

#[derive(Clone)]
struct HostBridge {
    dom: Rc<RefCell<ArenaDom>>,
    logs: Rc<RefCell<Vec<String>>>,
    diagnostics: Rc<RefCell<Vec<DiagnosticEvent>>>,
    storage: Rc<RefCell<HashMap<String, String>>>,
    click_listeners: Rc<RefCell<HashMap<NodeId, Vec<JsObject>>>>,
    origin: String,
    pid: u32,
}

pub struct JsRuntime {
    context: Context,
    bridge: HostBridge,
}

impl JsRuntime {
    pub fn new(dom: Rc<RefCell<ArenaDom>>, url: &str, origin: &str) -> Self {
        let mut context = Context::default();
        // Security & Low-Resource guardrails: cap recursion and loop iterations,
        // sized generously enough for real-world bundles while halting infinite loops.
        context.runtime_limits_mut().set_recursion_limit(256);
        context
            .runtime_limits_mut()
            .set_loop_iteration_limit(2_000_000);

        let bridge = HostBridge {
            dom,
            logs: Rc::new(RefCell::new(Vec::new())),
            diagnostics: Rc::new(RefCell::new(Vec::new())),
            storage: Rc::new(RefCell::new(HashMap::new())),
            click_listeners: Rc::new(RefCell::new(HashMap::new())),
            origin: origin.to_string(),
            pid: std::process::id(),
        };
        context.insert_data(bridge.clone());

        install_web_apis(&mut context, url, origin);

        Self { context, bridge }
    }

    pub fn eval(&mut self, source: &str) -> Result<String, String> {
        match self.context.eval(Source::from_bytes(source)) {
            Ok(val) => Ok(val
                .to_string(&mut self.context)
                .map(|s| s.to_std_string_escaped())
                .unwrap_or_else(|_| "undefined".to_string())),
            Err(err) => {
                let msg = err.to_string();
                self.bridge.diagnostics.borrow_mut().push(DiagnosticEvent::new(
                    Severity::Warn,
                    LogCategory::JsCompat,
                    &self.bridge.origin,
                    self.bridge.pid,
                    format!("JS Exception: {msg}"),
                ));
                Err(msg)
            }
        }
    }

    pub fn dispatch_click(&mut self, node_id: NodeId) -> Vec<String> {
        let listeners = self
            .bridge
            .click_listeners
            .borrow()
            .get(&node_id)
            .cloned()
            .unwrap_or_default();
        let mut errors = Vec::new();
        for func in listeners {
            if let Err(err) = func.call(&JsValue::undefined(), &[], &mut self.context) {
                let msg = err.to_string();
                self.bridge.diagnostics.borrow_mut().push(DiagnosticEvent::new(
                    Severity::Warn,
                    LogCategory::JsCompat,
                    &self.bridge.origin,
                    self.bridge.pid,
                    format!("Click handler error: {msg}"),
                ));
                errors.push(msg);
            }
        }
        errors
    }

    pub fn take_logs(&self) -> Vec<String> {
        std::mem::take(&mut *self.bridge.logs.borrow_mut())
    }

    pub fn take_diagnostics(&self) -> Vec<DiagnosticEvent> {
        std::mem::take(&mut *self.bridge.diagnostics.borrow_mut())
    }
}

fn install_web_apis(context: &mut Context, url: &str, origin: &str) {
    // 1. Alias window, self, top, parent directly to globalThis so `var x` and `window.x` / `self.x` match!
    let global = context.global_object();
    let _ = context.register_global_property(
        js_string!("window"),
        global.clone(),
        Attribute::WRITABLE | Attribute::CONFIGURABLE,
    );
    let _ = context.register_global_property(
        js_string!("self"),
        global.clone(),
        Attribute::WRITABLE | Attribute::CONFIGURABLE,
    );
    let _ = context.register_global_property(
        js_string!("top"),
        global.clone(),
        Attribute::WRITABLE | Attribute::CONFIGURABLE,
    );
    let _ = context.register_global_property(
        js_string!("parent"),
        global,
        Attribute::WRITABLE | Attribute::CONFIGURABLE,
    );

    // 2. console.log / warn / error / info / debug
    let log_fn = NativeFunction::from_fn_ptr(js_console_log);
    let noop = NativeFunction::from_fn_ptr(|_, _, _| Ok(JsValue::undefined()));
    let console = ObjectInitializer::new(context)
        .function(log_fn.clone(), js_string!("log"), 1)
        .function(log_fn.clone(), js_string!("warn"), 1)
        .function(log_fn.clone(), js_string!("error"), 1)
        .function(log_fn.clone(), js_string!("info"), 1)
        .function(log_fn, js_string!("debug"), 1)
        .function(noop.clone(), js_string!("time"), 1)
        .function(noop.clone(), js_string!("timeEnd"), 1)
        .function(noop.clone(), js_string!("group"), 1)
        .function(noop.clone(), js_string!("groupEnd"), 0)
        .build();
    let _ = context.register_global_property(js_string!("console"), console, Attribute::all());

    // 3. location & navigator
    let location = ObjectInitializer::new(context)
        .property(js_string!("href"), js_string!(url), Attribute::all())
        .property(js_string!("origin"), js_string!(origin), Attribute::all())
        .property(js_string!("protocol"), js_string!("https:"), Attribute::all())
        .property(js_string!("host"), js_string!(origin.trim_start_matches("https://").trim_start_matches("http://")), Attribute::all())
        .property(js_string!("hostname"), js_string!(origin.trim_start_matches("https://").trim_start_matches("http://")), Attribute::all())
        .property(js_string!("pathname"), js_string!("/"), Attribute::all())
        .property(js_string!("search"), js_string!(""), Attribute::all())
        .property(js_string!("hash"), js_string!(""), Attribute::all())
        .function(noop.clone(), js_string!("assign"), 1)
        .function(noop.clone(), js_string!("replace"), 1)
        .function(noop.clone(), js_string!("reload"), 0)
        .build();
    let navigator = ObjectInitializer::new(context)
        .property(
            js_string!("userAgent"),
            js_string!("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"),
            Attribute::READONLY,
        )
        .property(js_string!("vendor"), js_string!("Google Inc."), Attribute::READONLY)
        .property(js_string!("platform"), js_string!("Win32"), Attribute::READONLY)
        .property(js_string!("language"), js_string!("en-US"), Attribute::READONLY)
        .property(js_string!("onLine"), JsValue::from(true), Attribute::READONLY)
        .property(js_string!("cookieEnabled"), JsValue::from(true), Attribute::READONLY)
        .function(noop.clone(), js_string!("sendBeacon"), 2)
        .build();

    // 4. localStorage & sessionStorage
    let ls_get = NativeFunction::from_fn_ptr(js_ls_get);
    let ls_set = NativeFunction::from_fn_ptr(js_ls_set);
    let ls_rem = NativeFunction::from_fn_ptr(js_ls_remove);
    let ls_clr = NativeFunction::from_fn_ptr(js_ls_clear);
    let local_storage = ObjectInitializer::new(context)
        .function(ls_get, js_string!("getItem"), 1)
        .function(ls_set, js_string!("setItem"), 2)
        .function(ls_rem, js_string!("removeItem"), 1)
        .function(ls_clr, js_string!("clear"), 0)
        .build();

    // 5. history
    let history = ObjectInitializer::new(context)
        .property(js_string!("length"), JsValue::from(1), Attribute::all())
        .property(js_string!("state"), JsValue::null(), Attribute::all())
        .function(noop.clone(), js_string!("pushState"), 3)
        .function(noop.clone(), js_string!("replaceState"), 3)
        .function(noop.clone(), js_string!("back"), 0)
        .function(noop.clone(), js_string!("forward"), 0)
        .function(noop.clone(), js_string!("go"), 1)
        .build();

    // 6. Timers
    let set_timeout = NativeFunction::from_fn_ptr(js_set_timeout);
    let _ = context.register_global_builtin_callable(js_string!("setTimeout"), 1, set_timeout);
    let _ = context.register_global_builtin_callable(js_string!("clearTimeout"), 1, noop.clone());
    let _ = context.register_global_builtin_callable(js_string!("setInterval"), 1, noop.clone());
    let _ = context.register_global_builtin_callable(js_string!("clearInterval"), 1, noop.clone());

    // 7. document
    let get_by_id = NativeFunction::from_fn_ptr(js_get_element_by_id);
    let query_sel = NativeFunction::from_fn_ptr(js_query_selector);
    let query_sel_all = NativeFunction::from_fn_ptr(js_query_selector_all);
    let create_elem = NativeFunction::from_fn_ptr(js_create_element);
    let create_text = NativeFunction::from_fn_ptr(js_create_text_node);
    let get_title = NativeFunction::from_fn_ptr(js_get_title).to_js_function(context.realm());
    let get_doc_elem = NativeFunction::from_fn_ptr(js_get_doc_element).to_js_function(context.realm());
    let get_head = NativeFunction::from_fn_ptr(js_get_head).to_js_function(context.realm());
    let get_body = NativeFunction::from_fn_ptr(js_get_body).to_js_function(context.realm());

    let mut doc_init = ObjectInitializer::new(context);
    doc_init.function(get_by_id, js_string!("getElementById"), 1);
    doc_init.function(query_sel, js_string!("querySelector"), 1);
    doc_init.function(query_sel_all.clone(), js_string!("querySelectorAll"), 1);
    doc_init.function(query_sel_all.clone(), js_string!("getElementsByTagName"), 1);
    doc_init.function(query_sel_all, js_string!("getElementsByClassName"), 1);
    doc_init.function(create_elem.clone(), js_string!("createElement"), 1);
    doc_init.function(create_elem.clone(), js_string!("createElementNS"), 2);
    doc_init.function(create_elem, js_string!("createDocumentFragment"), 0);
    doc_init.function(create_text.clone(), js_string!("createTextNode"), 1);
    doc_init.function(create_text, js_string!("createComment"), 1);
    doc_init.function(noop.clone(), js_string!("addEventListener"), 2);
    doc_init.function(noop.clone(), js_string!("removeEventListener"), 2);
    doc_init.function(noop, js_string!("dispatchEvent"), 1);
    doc_init.property(js_string!("cookie"), js_string!(""), Attribute::all());
    doc_init.property(js_string!("readyState"), js_string!("complete"), Attribute::all());
    doc_init.property(js_string!("visibilityState"), js_string!("visible"), Attribute::all());
    doc_init.property(js_string!("hidden"), JsValue::from(false), Attribute::all());
    doc_init.property(js_string!("location"), location.clone(), Attribute::all());
    doc_init.accessor(js_string!("title"), Some(get_title), None, Attribute::CONFIGURABLE);
    doc_init.accessor(js_string!("documentElement"), Some(get_doc_elem), None, Attribute::CONFIGURABLE);
    doc_init.accessor(js_string!("head"), Some(get_head), None, Attribute::CONFIGURABLE);
    doc_init.accessor(js_string!("body"), Some(get_body), None, Attribute::CONFIGURABLE);
    let document = doc_init.build();

    let _ = context.register_global_property(js_string!("location"), location, Attribute::all());
    let _ = context.register_global_property(js_string!("navigator"), navigator, Attribute::all());
    let _ = context.register_global_property(js_string!("localStorage"), local_storage.clone(), Attribute::all());
    let _ = context.register_global_property(js_string!("sessionStorage"), local_storage, Attribute::all());
    let _ = context.register_global_property(js_string!("history"), history, Attribute::all());
    let _ = context.register_global_property(js_string!("document"), document, Attribute::all());

    let report_fn = NativeFunction::from_fn_ptr(js_report_missing_api);
    let _ = context.register_global_builtin_callable(
        js_string!("__rcReportMissingApi"),
        1,
        report_fn,
    );

    // 8. Install Chrome-compatible Web API constructors & prototypes (Element, Node, Event, etc.)
    let bootstrap_js = r#"
(function(g) {
  g.EventTarget = function EventTarget() {};
  g.EventTarget.prototype.addEventListener = function() {};
  g.EventTarget.prototype.removeEventListener = function() {};
  g.EventTarget.prototype.dispatchEvent = function() { return true; };

  g.Node = function Node() {};
  g.Node.prototype = Object.create(g.EventTarget.prototype);
  g.Node.ELEMENT_NODE = 1;
  g.Node.TEXT_NODE = 3;
  g.Node.DOCUMENT_NODE = 9;

  g.Element = function Element() {};
  g.Element.prototype = Object.create(g.Node.prototype);
  g.Element.prototype.matches = function() { return false; };
  g.Element.prototype.closest = function() { return null; };
  g.Element.prototype.getBoundingClientRect = function() {
    return { top: 0, left: 0, right: 0, bottom: 0, width: 0, height: 0, x: 0, y: 0 };
  };
  g.Element.prototype.attachShadow = function() {
    return g.document.createElement("div");
  };

  g.HTMLElement = function HTMLElement() {};
  g.HTMLElement.prototype = Object.create(g.Element.prototype);
  g.HTMLDocument = function HTMLDocument() {};
  g.Document = g.HTMLDocument;
  g.DocumentFragment = function DocumentFragment() {};
  g.ShadowRoot = function ShadowRoot() {};
  g.NodeFilter = {
    SHOW_ALL: 4294967295,
    SHOW_ELEMENT: 1,
    SHOW_TEXT: 4,
    SHOW_COMMENT: 128,
    FILTER_ACCEPT: 1,
    FILTER_REJECT: 2,
    FILTER_SKIP: 3
  };
  g.Polymer = function Polymer() {};
  g.Polymer.Base = {};
  g.Polymer.BaseDescriptors = {};
  g.MessageChannel = function MessageChannel() {
    this.port1 = { postMessage: function() {}, close: function() {} };
    this.port2 = { postMessage: function() {}, close: function() {} };
  };

  g.Event = function Event(type, opts) {
    this.type = type;
    this.bubbles = !!(opts && opts.bubbles);
    this.cancelable = !!(opts && opts.cancelable);
    this.defaultPrevented = false;
  };
  g.Event.prototype.preventDefault = function() { this.defaultPrevented = true; };
  g.Event.prototype.stopPropagation = function() {};
  g.CustomEvent = function CustomEvent(type, opts) {
    g.Event.call(this, type, opts);
    this.detail = opts ? opts.detail : null;
  };
  g.CustomEvent.prototype = Object.create(g.Event.prototype);
  g.MouseEvent = g.Event;
  g.KeyboardEvent = g.Event;
  g.UIEvent = g.Event;

  g.MutationObserver = function MutationObserver() {};
  g.MutationObserver.prototype.observe = function() {};
  g.MutationObserver.prototype.disconnect = function() {};
  g.MutationObserver.prototype.takeRecords = function() { return []; };
  g.ResizeObserver = g.MutationObserver;
  g.IntersectionObserver = g.MutationObserver;
  g.PerformanceObserver = g.MutationObserver;

  g.Image = function Image(w, h) {
    var el = g.document.createElement("img");
    el.width = w || 0;
    el.height = h || 0;
    return el;
  };
  g.Audio = function Audio() { return g.document.createElement("audio"); };
  g.CSSStyleSheet = function CSSStyleSheet() { this.cssRules = []; };
  g.CSSStyleSheet.prototype.replaceSync = function() {};
  g.CSS = { supports: function() { return true; }, escape: function(s) { return String(s); } };

  g.customElements = {
    _reg: {},
    define: function(name, ctor) { this._reg[name] = ctor; },
    get: function(name) { return this._reg[name]; },
    whenDefined: function() { return Promise.resolve(); }
  };

  var startMs = Date.now();
  g.performance = {
    timeOrigin: startMs,
    now: function() { return Date.now() - startMs; },
    mark: function() {},
    measure: function() {},
    clearMarks: function() {},
    clearMeasures: function() {},
    getEntriesByName: function() { return []; },
    getEntriesByType: function() { return []; },
    timing: { navigationStart: startMs, loadEventEnd: startMs + 50 }
  };

  g.addEventListener = function() {};
  g.removeEventListener = function() {};
  g.dispatchEvent = function() { return true; };
  g.requestAnimationFrame = function(cb) { return 1; };
  g.cancelAnimationFrame = function() {};
  g.requestIdleCallback = function(cb) { return 1; };
  g.cancelIdleCallback = function() {};
  g.queueMicrotask = function(cb) { if (typeof cb === "function") { try { cb(); } catch (_) {} } };
  g.getComputedStyle = function(el) {
    return (el && el.style) ? el.style : {};
  };
  g.matchMedia = function(q) {
    return {
      matches: false,
      media: String(q),
      addListener: function() {},
      removeListener: function() {},
      addEventListener: function() {},
      removeEventListener: function() {}
    };
  };
  g.innerWidth = 1080;
  g.innerHeight = 720;
  g.devicePixelRatio = 1;
  g.screen = { width: 1920, height: 1080, availWidth: 1920, availHeight: 1040, colorDepth: 24 };
  g.XMLHttpRequest = function XMLHttpRequest() {
    this.readyState = 0;
    this.status = 200;
    this.responseText = "";
  };
  g.XMLHttpRequest.prototype.open = function() {};
  g.XMLHttpRequest.prototype.send = function() {};
  g.XMLHttpRequest.prototype.setRequestHeader = function() {};
  g.XMLHttpRequest.prototype.addEventListener = function() {};
  g.fetch = function() {
    return Promise.resolve({
      ok: true,
      status: 200,
      text: function() { return Promise.resolve(""); },
      json: function() { return Promise.resolve({}); }
    });
  };
})(globalThis);
"#;
    let _ = context.eval(Source::from_bytes(bootstrap_js));
}

fn js_report_missing_api(
    _this: &JsValue,
    args: &[JsValue],
    context: &mut Context,
) -> JsResult<JsValue> {
    let api_name = args
        .get_or_undefined(0)
        .to_string(context)?
        .to_std_string_escaped();
    if let Some(bridge) = context.get_data::<HostBridge>() {
        bridge.diagnostics.borrow_mut().push(DiagnosticEvent::new(
            Severity::Warn,
            LogCategory::JsCompat,
            &bridge.origin,
            bridge.pid,
            format!("Missing Web API probed: {api_name}"),
        ));
    }
    Ok(JsValue::undefined())
}

fn js_set_timeout(
    _this: &JsValue,
    args: &[JsValue],
    context: &mut Context,
) -> JsResult<JsValue> {
    if let Some(cb) = args.first().and_then(|v| v.as_object())
        && cb.is_callable()
    {
        let _ = cb.call(&JsValue::undefined(), &[], context);
    }
    Ok(JsValue::from(1))
}

fn js_ls_get(_this: &JsValue, args: &[JsValue], context: &mut Context) -> JsResult<JsValue> {
    let k = args
        .get_or_undefined(0)
        .to_string(context)?
        .to_std_string_escaped();
    if let Some(bridge) = context.get_data::<HostBridge>()
        && let Some(v) = bridge.storage.borrow().get(&k)
    {
        return Ok(JsValue::from(js_string!(v.clone())));
    }
    Ok(JsValue::null())
}

fn js_ls_set(_this: &JsValue, args: &[JsValue], context: &mut Context) -> JsResult<JsValue> {
    let k = args
        .get_or_undefined(0)
        .to_string(context)?
        .to_std_string_escaped();
    let v = args
        .get_or_undefined(1)
        .to_string(context)?
        .to_std_string_escaped();
    if let Some(bridge) = context.get_data::<HostBridge>() {
        bridge.storage.borrow_mut().insert(k, v);
    }
    Ok(JsValue::undefined())
}

fn js_ls_remove(_this: &JsValue, args: &[JsValue], context: &mut Context) -> JsResult<JsValue> {
    let k = args
        .get_or_undefined(0)
        .to_string(context)?
        .to_std_string_escaped();
    if let Some(bridge) = context.get_data::<HostBridge>() {
        bridge.storage.borrow_mut().remove(&k);
    }
    Ok(JsValue::undefined())
}

fn js_ls_clear(_this: &JsValue, _args: &[JsValue], context: &mut Context) -> JsResult<JsValue> {
    if let Some(bridge) = context.get_data::<HostBridge>() {
        bridge.storage.borrow_mut().clear();
    }
    Ok(JsValue::undefined())
}

fn js_console_log(_this: &JsValue, args: &[JsValue], context: &mut Context) -> JsResult<JsValue> {
    let mut parts = Vec::with_capacity(args.len());
    for arg in args {
        parts.push(arg.to_string(context)?.to_std_string_escaped());
    }
    let line = parts.join(" ");
    if let Some(bridge) = context.get_data::<HostBridge>() {
        bridge.logs.borrow_mut().push(line);
    }
    Ok(JsValue::undefined())
}

fn js_get_title(_this: &JsValue, _args: &[JsValue], context: &mut Context) -> JsResult<JsValue> {
    if let Some(bridge) = context.get_data::<HostBridge>() {
        let title = bridge.dom.borrow().title();
        return Ok(JsValue::from(js_string!(title)));
    }
    Ok(JsValue::from(js_string!("")))
}

fn js_get_doc_element(_this: &JsValue, _args: &[JsValue], context: &mut Context) -> JsResult<JsValue> {
    let id = context
        .get_data::<HostBridge>()
        .and_then(|b| b.dom.borrow().find_first_tag("html"))
        .unwrap_or(0);
    Ok(build_element_wrapper(context, id))
}

fn js_get_head(_this: &JsValue, _args: &[JsValue], context: &mut Context) -> JsResult<JsValue> {
    let id = context
        .get_data::<HostBridge>()
        .and_then(|b| b.dom.borrow().find_first_tag("head"))
        .unwrap_or(0);
    Ok(build_element_wrapper(context, id))
}

fn js_get_body(_this: &JsValue, _args: &[JsValue], context: &mut Context) -> JsResult<JsValue> {
    let id = context
        .get_data::<HostBridge>()
        .and_then(|b| b.dom.borrow().find_first_tag("body"))
        .unwrap_or(0);
    Ok(build_element_wrapper(context, id))
}

fn js_get_element_by_id(
    _this: &JsValue,
    args: &[JsValue],
    context: &mut Context,
) -> JsResult<JsValue> {
    let id_str = args
        .get_or_undefined(0)
        .to_string(context)?
        .to_std_string_escaped();

    let node_id: Option<NodeId> = context
        .get_data::<HostBridge>()
        .and_then(|b| b.dom.borrow().get_element_by_id(&id_str));

    match node_id {
        Some(id) => Ok(build_element_wrapper(context, id)),
        None => Ok(JsValue::null()),
    }
}

fn js_query_selector(
    _this: &JsValue,
    args: &[JsValue],
    context: &mut Context,
) -> JsResult<JsValue> {
    let sel = args
        .get_or_undefined(0)
        .to_string(context)?
        .to_std_string_escaped();
    let node_id: Option<NodeId> = context
        .get_data::<HostBridge>()
        .and_then(|b| b.dom.borrow().query_selector(&sel));
    match node_id {
        Some(id) => Ok(build_element_wrapper(context, id)),
        None => Ok(JsValue::null()),
    }
}

fn js_query_selector_all(
    _this: &JsValue,
    args: &[JsValue],
    context: &mut Context,
) -> JsResult<JsValue> {
    let sel = args
        .get_or_undefined(0)
        .to_string(context)?
        .to_std_string_escaped();
    let ids: Vec<NodeId> = context
        .get_data::<HostBridge>()
        .map(|b| b.dom.borrow().query_selector_all(&sel))
        .unwrap_or_default();
    let arr = JsArray::new(context)?;
    for id in ids {
        let elem = build_element_wrapper(context, id);
        let _ = arr.push(elem, context);
    }
    Ok(arr.into())
}

fn js_create_element(
    _this: &JsValue,
    args: &[JsValue],
    context: &mut Context,
) -> JsResult<JsValue> {
    let tag = args
        .get_or_undefined(0)
        .to_string(context)?
        .to_std_string_escaped()
        .to_ascii_lowercase();
    let node_id = context
        .get_data::<HostBridge>()
        .map(|b| {
            b.dom.borrow_mut().alloc(NodeData::Element {
                tag,
                attrs: HashMap::new(),
            })
        })
        .unwrap_or(0);
    Ok(build_element_wrapper(context, node_id))
}

fn js_create_text_node(
    _this: &JsValue,
    args: &[JsValue],
    context: &mut Context,
) -> JsResult<JsValue> {
    let text = args
        .get_or_undefined(0)
        .to_string(context)?
        .to_std_string_escaped();
    let node_id = context
        .get_data::<HostBridge>()
        .map(|b| b.dom.borrow_mut().alloc(NodeData::Text(text)))
        .unwrap_or(0);
    Ok(build_element_wrapper(context, node_id))
}

fn build_element_wrapper(context: &mut Context, node_id: NodeId) -> JsValue {
    let get_tc = NativeFunction::from_fn_ptr(js_elem_get_text_content).to_js_function(context.realm());
    let set_tc = NativeFunction::from_fn_ptr(js_elem_set_text_content).to_js_function(context.realm());
    let append_child = NativeFunction::from_fn_ptr(js_elem_append_child);
    let remove_child = NativeFunction::from_fn_ptr(|_, args, _| Ok(args.get_or_undefined(0).clone()));
    let set_attr = NativeFunction::from_fn_ptr(js_elem_set_attribute);
    let get_attr = NativeFunction::from_fn_ptr(js_elem_get_attribute);
    let has_attr = NativeFunction::from_fn_ptr(js_elem_has_attribute);
    let rem_attr = NativeFunction::from_fn_ptr(|_, _, _| Ok(JsValue::undefined()));
    let add_listener = NativeFunction::from_fn_ptr(js_elem_add_event_listener);
    let noop = NativeFunction::from_fn_ptr(|_, _, _| Ok(JsValue::undefined()));
    let query_sel = NativeFunction::from_fn_ptr(js_query_selector);
    let query_sel_all = NativeFunction::from_fn_ptr(js_query_selector_all);

    let style_obj = ObjectInitializer::new(context)
        .function(noop.clone(), js_string!("setProperty"), 2)
        .function(
            NativeFunction::from_fn_ptr(|_, _, _| Ok(JsValue::from(js_string!("")))),
            js_string!("getPropertyValue"),
            1,
        )
        .build();
    let dataset_obj = ObjectInitializer::new(context).build();
    let class_list = ObjectInitializer::new(context)
        .function(noop.clone(), js_string!("add"), 1)
        .function(noop.clone(), js_string!("remove"), 1)
        .function(
            NativeFunction::from_fn_ptr(|_, _, _| Ok(JsValue::from(false))),
            js_string!("toggle"),
            1,
        )
        .function(
            NativeFunction::from_fn_ptr(|_, _, _| Ok(JsValue::from(false))),
            js_string!("contains"),
            1,
        )
        .build();
    let children_arr: JsValue = JsArray::new(context)
        .map(Into::into)
        .unwrap_or_default();

    let mut elem = ObjectInitializer::new(context);
    elem.property(
        js_string!("__nodeId"),
        JsValue::from(node_id as i32),
        Attribute::empty(),
    );
    elem.property(js_string!("nodeType"), JsValue::from(1), Attribute::all());
    elem.property(js_string!("style"), style_obj, Attribute::all());
    elem.property(js_string!("dataset"), dataset_obj, Attribute::all());
    elem.property(js_string!("classList"), class_list, Attribute::all());
    elem.property(js_string!("children"), children_arr.clone(), Attribute::all());
    elem.property(js_string!("childNodes"), children_arr, Attribute::all());
    elem.function(append_child, js_string!("appendChild"), 1);
    elem.function(remove_child, js_string!("removeChild"), 1);
    elem.function(set_attr, js_string!("setAttribute"), 2);
    elem.function(get_attr, js_string!("getAttribute"), 1);
    elem.function(has_attr, js_string!("hasAttribute"), 1);
    elem.function(rem_attr, js_string!("removeAttribute"), 1);
    elem.function(add_listener, js_string!("addEventListener"), 2);
    elem.function(noop.clone(), js_string!("removeEventListener"), 2);
    elem.function(noop, js_string!("dispatchEvent"), 1);
    elem.function(query_sel, js_string!("querySelector"), 1);
    elem.function(query_sel_all, js_string!("querySelectorAll"), 1);
    elem.accessor(
        js_string!("textContent"),
        Some(get_tc.clone()),
        Some(set_tc.clone()),
        Attribute::CONFIGURABLE,
    );
    elem.accessor(
        js_string!("innerHTML"),
        Some(get_tc),
        Some(set_tc),
        Attribute::CONFIGURABLE,
    );
    elem.build().into()
}

fn js_elem_append_child(
    this: &JsValue,
    args: &[JsValue],
    context: &mut Context,
) -> JsResult<JsValue> {
    let parent_id = extract_node_id(this, context)?;
    if let Ok(child_id) = extract_node_id(args.get_or_undefined(0), context)
        && let Some(bridge) = context.get_data::<HostBridge>()
    {
        bridge.dom.borrow_mut().append_child(parent_id, child_id);
    }
    Ok(args.get_or_undefined(0).clone())
}

fn js_elem_set_attribute(
    this: &JsValue,
    args: &[JsValue],
    context: &mut Context,
) -> JsResult<JsValue> {
    let node_id = extract_node_id(this, context)?;
    let k = args
        .get_or_undefined(0)
        .to_string(context)?
        .to_std_string_escaped();
    let v = args
        .get_or_undefined(1)
        .to_string(context)?
        .to_std_string_escaped();
    if let Some(bridge) = context.get_data::<HostBridge>()
        && let NodeData::Element { attrs, .. } = &mut bridge.dom.borrow_mut().nodes[node_id].data
    {
        attrs.insert(k, v);
    }
    Ok(JsValue::undefined())
}

fn js_elem_get_attribute(
    this: &JsValue,
    args: &[JsValue],
    context: &mut Context,
) -> JsResult<JsValue> {
    let node_id = extract_node_id(this, context)?;
    let k = args
        .get_or_undefined(0)
        .to_string(context)?
        .to_std_string_escaped();
    if let Some(bridge) = context.get_data::<HostBridge>()
        && let NodeData::Element { attrs, .. } = &bridge.dom.borrow().nodes[node_id].data
        && let Some(val) = attrs.get(&k)
    {
        return Ok(JsValue::from(js_string!(val.clone())));
    }
    Ok(JsValue::null())
}

fn js_elem_has_attribute(
    this: &JsValue,
    args: &[JsValue],
    context: &mut Context,
) -> JsResult<JsValue> {
    let node_id = extract_node_id(this, context)?;
    let k = args
        .get_or_undefined(0)
        .to_string(context)?
        .to_std_string_escaped();
    if let Some(bridge) = context.get_data::<HostBridge>()
        && let NodeData::Element { attrs, .. } = &bridge.dom.borrow().nodes[node_id].data
    {
        return Ok(JsValue::from(attrs.contains_key(&k)));
    }
    Ok(JsValue::from(false))
}

fn js_elem_add_event_listener(
    this: &JsValue,
    args: &[JsValue],
    context: &mut Context,
) -> JsResult<JsValue> {
    let node_id = extract_node_id(this, context)?;
    let ev_type = args
        .get_or_undefined(0)
        .to_string(context)?
        .to_std_string_escaped();
    if ev_type == "click"
        && let Some(cb) = args.get_or_undefined(1).as_object()
        && cb.is_callable()
        && let Some(bridge) = context.get_data::<HostBridge>()
    {
        bridge
            .click_listeners
            .borrow_mut()
            .entry(node_id)
            .or_default()
            .push(cb.clone());
    }
    Ok(JsValue::undefined())
}

fn js_elem_get_text_content(
    this: &JsValue,
    _args: &[JsValue],
    context: &mut Context,
) -> JsResult<JsValue> {
    let node_id = extract_node_id(this, context)?;
    if let Some(bridge) = context.get_data::<HostBridge>() {
        let text = bridge.dom.borrow().text_content(node_id);
        return Ok(JsValue::from(js_string!(text)));
    }
    Ok(JsValue::from(js_string!("")))
}

fn js_elem_set_text_content(
    this: &JsValue,
    args: &[JsValue],
    context: &mut Context,
) -> JsResult<JsValue> {
    let node_id = extract_node_id(this, context)?;
    let new_text = args
        .get_or_undefined(0)
        .to_string(context)?
        .to_std_string_escaped();
    if let Some(bridge) = context.get_data::<HostBridge>() {
        bridge.dom.borrow_mut().set_text_content(node_id, new_text);
    }
    Ok(JsValue::undefined())
}

fn extract_node_id(this: &JsValue, context: &mut Context) -> JsResult<NodeId> {
    let obj = this
        .as_object()
        .ok_or_else(|| JsNativeError::typ().with_message("Expected DOM Element"))?;
    let val = obj.get(js_string!("__nodeId"), context)?;
    let idx = val.to_i32(context)?;
    if idx < 0 {
        return Err(JsNativeError::typ().with_message("Invalid nodeId").into());
    }
    Ok(idx as usize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rc_dom::parse_html;

    #[test]
    fn js_mutates_dom_and_logs_console() {
        let dom = Rc::new(RefCell::new(parse_html(
            "<html><head><title>JS Test</title></head><body><div id='out'>before</div></body></html>",
        )));
        let mut js = JsRuntime::new(dom.clone(), "https://example.com/", "https://example.com");
        let res = js
            .eval(
                r##"
                var globalVar = "ok";
                const el = document.querySelector("#out");
                el.textContent = "after:" + document.title + ":" + window.globalVar + ":" + self.globalVar;
                localStorage.setItem("k", "v");
                console.log("updated", window.location.href, localStorage.getItem("k"));
                el.textContent
                "##,
            )
            .unwrap();
        assert_eq!(res, "after:JS Test:ok:ok");
        let id = dom.borrow().get_element_by_id("out").unwrap();
        assert_eq!(dom.borrow().text_content(id), "after:JS Test:ok:ok");
        assert_eq!(js.take_logs(), vec!["updated https://example.com/ v"]);
    }

    #[test]
    fn infinite_loop_is_halted_by_sandbox_limit() {
        let dom = Rc::new(RefCell::new(ArenaDom::new()));
        let mut js = JsRuntime::new(dom, "about:blank", "null");
        let res = js.eval("while (true) {}");
        assert!(res.is_err());
    }
}
