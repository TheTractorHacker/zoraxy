/*
    rulesmodel.js: the data model of the visual rules builder, free of DOM code (so it can be tested in node).

    Model (what the builder edits):
      group  {kind:"group", id, op:"and"|"or", not:bool, children:[node...]}
      cond   {kind:"cond",  id, not:bool, field, key, lower:bool, op, value:"", items:[], ref:"", useRef:bool}
    The engine's tree (GET/POST /api/ruleset/*) has "and" / "or" / "not" / "cond" nodes; "not" is a flag on the model
    node here. fromTree(toTree(x)) keeps the meaning (a double "not" cancels), and text -> tree -> text goes through
    the validate endpoint, which returns the normalised tree this file loads.

    Also here: the plain-English sentence of a rule.
*/
(function () {
    "use strict";
    if (window.RBModel) { return; }
    function N_(s) { return s; }
    function t(s) { return typeof window.t === "function" ? window.t(s) : s; }
    function tf(s) {
        var a = Array.prototype.slice.call(arguments, 1);
        if (typeof window.tf === "function") { return window.tf.apply(null, [s].concat(a)); }
        return s.replace(/\{(\d+)\}/g, function (m, n) { return a[+n] !== undefined ? a[+n] : m; });
    }
    var D = window.RBData;
    var M = window.RBModel = {};
    var uid = 0;
    function nid() { uid++; return "rbn" + uid; }

    // meta = answer of /api/ruleset/meta (fields with type / indexed / country)
    var fieldMeta = {};
    M.setMeta = function (meta) {
        fieldMeta = {};
        ((meta && meta.fields) || []).forEach(function (f) { fieldMeta[f.name] = f; });
    };
    M.field = function (name) { return fieldMeta[name] || { name: name, type: "string" }; };

    // operators that apply to a field (engine table filtered by type; exists only for keyed fields)
    M.opsFor = function (meta, fieldName) {
        var f = M.field(fieldName), out = [];
        var avail = {};
        ((meta && meta.operators) || []).forEach(function (o) { avail[o.op] = o; });
        D.opOrder.forEach(function (op) {
            var o = avail[op];
            if (!o) { return; }
            if ((op === "exists" || op === "not_exists") && !f.indexed) { return; }
            if (o.types.indexOf(f.type) < 0) { return; }
            out.push(op);
        });
        return out;
    };
    // "none" | "int" | "bool" | "list" | "regex" | "string"
    M.valueKind = function (fieldName, op) {
        var f = M.field(fieldName);
        if (op === "exists" || op === "not_exists") { return "none"; }
        if (f.type === "bool") { return "bool"; }
        if (f.type === "int") { return "int"; }
        if (op === "in" || op === "not_in") { return "list"; }
        if (op === "matches" || op === "not_matches") { return "regex"; }
        return "string";
    };

    // "Ignore case" only means something for plain string comparisons: not for regexes (they are not lower-cased),
    // exists checks, or country codes (always upper case)
    M.lowerApplies = function (c) {
        return !!c.lower && M.field(c.field).type === "string" && c.field !== "ip.country" && ["none", "regex"].indexOf(M.valueKind(c.field, c.op)) < 0;
    };

    M.newGroup = function (op, children) { return { kind: "group", id: nid(), op: op || "and", not: false, children: children || [] }; };
    M.newCond = function (field, meta) {
        var f = field || "http.path", ops = meta ? M.opsFor(meta, f) : ["eq"];
        var op = ops[0] || "eq";
        var kind = M.field(f).type;
        var c = { kind: "cond", id: nid(), not: false, field: f, key: "", lower: false, op: op, value: "", items: [], ref: "", useRef: false };
        if (kind === "bool") { c.value = "true"; }
        // a sensible default operator per field
        if (f === "http.path") { c.op = "starts_with"; }
        else if (f === "ip.country") { c.op = "in"; }
        else if (f === "http.method") { c.op = "eq"; c.value = "GET"; }
        else if (f === "ip.src") { c.op = "in"; }
        if (D.fields[f] && D.fields[f].choices && !c.value && c.op === "eq") { c.value = D.fields[f].choices[0]; }
        return c;
    };

    // ---------------------------------------------------------------- tree <-> model
    function condFrom(n) {
        var c = { kind: "cond", id: nid(), not: false, field: n.field, key: n.key || "", lower: n.transform === "lower", op: n.op, value: "", items: [], ref: "", useRef: false };
        var v = n.value;
        if (Array.isArray(v)) { c.items = v.map(String); }
        else if (v && typeof v === "object" && v.list !== undefined) { c.ref = String(v.list); c.useRef = true; }
        else if (typeof v === "boolean") { c.value = v ? "true" : "false"; }
        else if (typeof v === "number") { c.value = String(v); }
        else if (v !== undefined && v !== null) { c.value = String(v); }
        return c;
    }
    function conv(n) {
        if (n.type === "cond" || (!n.type && n.field)) { return condFrom(n); }
        if (n.type === "not") {
            var c = conv((n.children || [])[0] || { type: "and", children: [] });
            c.not = !c.not;
            return c;
        }
        return { kind: "group", id: nid(), op: n.type === "or" ? "or" : "and", not: false, children: (n.children || []).map(conv) };
    }
    M.fromTree = function (tree) {
        if (!tree) { return M.newGroup("and", []); }
        var n = conv(tree);
        if (n.kind !== "group" || n.not) { n = M.newGroup("and", [n]); }
        return n;
    };

    function valueOf(c) {
        var k = M.valueKind(c.field, c.op);
        if (k === "none") { return undefined; }
        if (c.useRef && k === "list") { return { list: c.ref }; }
        if (k === "list") { return c.items.map(function (s) { return M.lowerApplies(c) ? String(s).toLowerCase() : s; }); }
        if (k === "int") { return parseInt(c.value, 10); }
        if (k === "bool") { return c.value === "true"; }
        return M.lowerApplies(c) && k === "string" ? String(c.value).toLowerCase() : String(c.value);
    }
    function wrapNot(n, inner) { return n.not ? { type: "not", children: [inner] } : inner; }
    M.toTree = function (n) {
        if (n.kind === "cond") {
            var o = { type: "cond", field: n.field };
            if (M.field(n.field).indexed) { o.key = n.key; }
            if (M.lowerApplies(n)) { o.transform = "lower"; }
            o.op = n.op;
            var v = valueOf(n);
            if (v !== undefined) { o.value = v; }
            return wrapNot(n, o);
        }
        return wrapNot(n, { type: n.op, children: n.children.map(M.toTree) });
    };

    // conditions that cannot be sent yet: [{node, why}]
    M.incomplete = function (root) {
        var out = [];
        (function walk(n) {
            if (n.kind === "group") {
                if (!n.children.length) { out.push({ node: n, why: t("This group has no conditions yet.") }); }
                n.children.forEach(walk);
                return;
            }
            var k = M.valueKind(n.field, n.op), f = M.field(n.field);
            if (f.indexed && !String(n.key).trim()) { out.push({ node: n, why: t("Enter the name.") }); return; }
            if (k === "list" && n.useRef && !n.ref) { out.push({ node: n, why: t("Pick a list.") }); }
            else if (k === "list" && !n.useRef && !n.items.length) { out.push({ node: n, why: t("Add at least one value.") }); }
            else if ((k === "string" || k === "regex") && n.value === "" && !(D.fields[n.field] && D.fields[n.field].choices)) { out.push({ node: n, why: t("Enter a value.") }); }
            else if (k === "string" && n.value === "") { out.push({ node: n, why: t("Choose a value.") }); }
            else if (k === "int" && !/^-?\d{1,15}$/.test(String(n.value).trim())) { out.push({ node: n, why: t("Enter a whole number.") }); }
        })(root);
        return out;
    };

    // find a node by the tree path of an engine error ("children[1].children[0]")
    M.byPath = function (root, path) {
        var idx = [], re = /children\[(\d+)\]/g, m;
        while ((m = re.exec(path || "")) !== null) { idx.push(+m[1]); }
        // the engine counts "not" wrappers as nodes; the model folds them into the node flag, so walk the tree form alongside
        var tree = M.toTree(root), cur = tree, model = root;
        for (var i = 0; i < idx.length; i++) {
            if (!cur || !cur.children) { return model; }
            if (cur.type === "not") { cur = cur.children[idx[i]]; }
            else { cur = cur.children[idx[i]]; model = (model.children || [])[idx[i]] || model; }
        }
        return model;
    };

    M.count = function (root) {
        var n = 0;
        (function walk(x) { n++; (x.children || []).forEach(walk); })(root);
        return n;
    };

    // ---------------------------------------------------------------- plain English
    function quote(s) {
        s = String(s);
        if (s === "" || /\s/.test(s)) { return "“" + s + "”"; }
        return s;
    }
    function joinOr(a) {
        if (a.length <= 1) { return a.join(""); }
        return tf("{0} or {1}", a.slice(0, -1).join(", "), a[a.length - 1]);
    }
    function listText(c) {
        if (c.useRef) { return tf("the list “{0}”", c.ref); }
        var items = c.items.map(function (x) { return c.field === "ip.country" ? D.countryName(x) + " (" + x + ")" : quote(x); });
        if (items.length > 5) { return tf("{0} and {1} more", items.slice(0, 5).join(", "), items.length - 5); }
        return joinOr(items);
    }
    M.condSentence = function (c) {
        var fd = D.fields[c.field] || { noun: c.field };
        var op = D.ops[c.op] || { phrase: c.op };
        var s;
        if (c.field === "ip.is_private") {
            // the value and the operator both count: "is not true" means public clients
            var priv = (c.value === "false") === (c.op === "ne");
            s = priv ? t("the client is on a private network") : t("the client is not on a private network");
        } else {
            var noun = t(fd.noun);
            if (M.field(c.field).indexed) { noun = tf("{0} “{1}”", noun, c.key); }
            if (M.lowerApplies(c)) { noun = tf("{0} (ignoring case)", noun); }
            var k = M.valueKind(c.field, c.op), val = "";
            if (k === "list") { val = " " + listText(c); }
            else if (k === "string" || k === "regex" || k === "int") {
                val = " " + (c.field === "ip.country" ? D.countryName(c.value) + " (" + c.value + ")" : quote(c.value));
            }
            s = noun + " " + t(op.phrase) + val;
        }
        return c.not ? tf("it is not true that {0}", s) : s;
    };
    function nodeSentence(n, top) {
        if (n.kind === "cond") { return M.condSentence(n); }
        var parts = n.children.map(function (c) { return nodeSentence(c, false); });
        if (!parts.length) { return t("(nothing yet)"); }
        var s = parts.join(" " + t(n.op === "or" ? "or" : "and") + " ");
        if (n.not) { return tf("it is not true that ({0})", s); }
        return !top && parts.length > 1 ? "(" + s + ")" : s;
    }
    M.whenSentence = function (root) { return nodeSentence(root, true); };

    M.actionSentence = function (a) {
        if (!a || !a.type) { return t("do nothing"); }
        switch (a.type) {
            case "block": return tf("block with status {0}", a.status || 403) + (a.body ? " " + t("and a custom message") : "");
            case "allow": return t("allow the request and stop evaluating rules");
            case "challenge": return tf("require a CAPTCHA challenge (remembered for {0} minutes)", a.ttl_minutes || 30);
            case "log": return t("only log it");
            case "skip": return tf("skip {0}", (a.skip || []).map(function (s) { return t(D.skipLabels[s] || s); }).join(", ") || "…");
            case "rate_limit": return tf("limit each client to {0} requests per second", a.rate || "…");
            case "redirect": return tf("redirect ({0}) to {1}", a.status || 302, a.url || "…");
            case "set_request_header": return tf("set the request header {0} to {1}", a.name || "…", a.value || "…");
            case "remove_request_header": return tf("remove the request header {0}", a.name || "…");
            case "set_response_header": return tf("set the response header {0} to {1}", a.name || "…", a.value || "…");
            case "remove_response_header": return tf("remove the response header {0}", a.name || "…");
            case "tag": return tf("tag the request {0}", a.tag || "…");
        }
        return a.type;
    };
    M.sentence = function (root, action) {
        return tf("When {0}, {1}.", M.whenSentence(root), M.actionSentence(action));
    };
    // the same for a rule as the API returns it (tree + action), used by the list
    M.ruleSentence = function (rule) {
        if (!rule.tree) { return rule.expression || ""; }
        return M.sentence(M.fromTree(rule.tree), rule.action);
    };
})();
