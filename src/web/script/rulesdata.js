/*
    rulesdata.js: static data of the visual rules builder (page components/ruleset.html).

    Everything here is DATA: field groups and labels, operator phrases, action labels, the country list and the
    quick-start templates. The engine's own tables (fields, operators, actions, limits) come from
    GET /api/ruleset/meta at run time; this file only adds the human wording and the widget choice.
    English strings are wrapped in N_() so tools/i18n/extract.py finds them (translated in the DOM / by t()).
*/
(function () {
    "use strict";
    if (window.RBData) { return; }
    function N_(s) { return s; }

    var D = window.RBData = {};

    // Field groups of the dropdown, in display order. Fields not listed here (a future engine field) go to "Other".
    D.groups = [
        { label: N_("Request"), fields: ["http.host", "http.path", "http.raw_path", "http.query", "http.query_arg", "http.method", "http.scheme", "http.version", "req.size"] },
        { label: N_("Headers and cookies"), fields: ["http.user_agent", "http.referer", "http.content_type", "http.header", "http.cookie"] },
        { label: N_("Client"), fields: ["ip.src", "ip.country", "ip.is_private"] },
        { label: N_("TLS"), fields: ["tls.version", "tls.sni"] }
    ];

    // label = dropdown text, noun = how the plain-English sentence names it, choices = fixed values for a select
    D.fields = {
        "http.host": { label: N_("Host name"), noun: N_("the host name") },
        "http.path": { label: N_("Path"), noun: N_("the path") },
        "http.raw_path": { label: N_("Raw path (as received)"), noun: N_("the raw path") },
        "http.query": { label: N_("Query string"), noun: N_("the query string") },
        "http.query_arg": { label: N_("Query parameter"), noun: N_("the query parameter"), keyLabel: N_("Parameter name"), keyPlaceholder: "id" },
        "http.method": { label: N_("Method"), noun: N_("the method"), choices: ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT", "TRACE"] },
        "http.scheme": { label: N_("Scheme (http or https)"), noun: N_("the scheme"), choices: ["https", "http"] },
        "http.version": { label: N_("HTTP version"), noun: N_("the HTTP version"), choices: ["HTTP/1.0", "HTTP/1.1", "HTTP/2.0", "HTTP/3.0"] },
        "req.size": { label: N_("Body size (bytes)"), noun: N_("the body size in bytes") },
        "http.user_agent": { label: N_("User agent"), noun: N_("the user agent") },
        "http.referer": { label: N_("Referer"), noun: N_("the referer") },
        "http.content_type": { label: N_("Content type"), noun: N_("the content type") },
        "http.header": { label: N_("Header"), noun: N_("the header"), keyLabel: N_("Header name"), keyPlaceholder: "x-api-key" },
        "http.cookie": { label: N_("Cookie"), noun: N_("the cookie"), keyLabel: N_("Cookie name"), keyPlaceholder: "session" },
        "ip.src": { label: N_("Client IP address"), noun: N_("the client address") },
        "ip.country": { label: N_("Country"), noun: N_("the country") },
        "ip.is_private": { label: N_("Client is on a private network"), noun: N_("the client is on a private network") },
        "tls.version": { label: N_("TLS version"), noun: N_("the TLS version"), choices: ["TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"] },
        "tls.sni": { label: N_("TLS server name (SNI)"), noun: N_("the TLS server name") }
    };

    // Operators: text for the dropdown (the engine's order is kept, this is the wording), phrase for the sentence
    D.ops = {
        eq: { label: N_("is"), phrase: N_("is") },
        ne: { label: N_("is not"), phrase: N_("is not") },
        lt: { label: N_("is less than"), phrase: N_("is less than") },
        gt: { label: N_("is greater than"), phrase: N_("is greater than") },
        le: { label: N_("is at most"), phrase: N_("is at most") },
        ge: { label: N_("is at least"), phrase: N_("is at least") },
        contains: { label: N_("contains"), phrase: N_("contains") },
        not_contains: { label: N_("does not contain"), phrase: N_("does not contain") },
        starts_with: { label: N_("starts with"), phrase: N_("starts with") },
        not_starts_with: { label: N_("does not start with"), phrase: N_("does not start with") },
        ends_with: { label: N_("ends with"), phrase: N_("ends with") },
        not_ends_with: { label: N_("does not end with"), phrase: N_("does not end with") },
        matches: { label: N_("matches the regex"), phrase: N_("matches the pattern") },
        not_matches: { label: N_("does not match the regex"), phrase: N_("does not match the pattern") },
        "in": { label: N_("is one of"), phrase: N_("is one of") },
        not_in: { label: N_("is not one of"), phrase: N_("is not one of") },
        exists: { label: N_("is present"), phrase: N_("is present") },
        not_exists: { label: N_("is not present"), phrase: N_("is not present") }
    };
    D.opOrder = ["eq", "ne", "in", "not_in", "contains", "not_contains", "starts_with", "not_starts_with", "ends_with", "not_ends_with", "matches", "not_matches", "lt", "gt", "le", "ge", "exists", "not_exists"];

    // Actions: label, group of the dropdown, one-line help (the engine's own doc is shown as well)
    D.actions = {
        block: { label: N_("Block"), group: 0, help: N_("Answer with an error page instead of passing the request on.") },
        redirect: { label: N_("Redirect"), group: 0, help: N_("Send the visitor to another address.") },
        challenge: { label: N_("Require a CAPTCHA challenge"), group: 0, help: N_("The visitor has to solve the CAPTCHA of the site first.") },
        rate_limit: { label: N_("Rate limit"), group: 0, help: N_("Slow down a client that sends too many requests.") },
        allow: { label: N_("Allow and stop evaluating rules"), group: 0, help: N_("Later rules do not run. This is not a bypass: the WAF, rate limit, CAPTCHA and sign-in still apply.") },
        log: { label: N_("Only log"), group: 1, help: N_("Count and record the match, nothing else happens.") },
        tag: { label: N_("Add a tag"), group: 1, help: N_("Mark the request; blocked-request log entries carry the tag.") },
        skip: { label: N_("Skip protections"), group: 1, help: N_("Switch other protections off for matching requests.") },
        set_request_header: { label: N_("Set a request header"), group: 1, help: N_("Change what the upstream server receives.") },
        remove_request_header: { label: N_("Remove a request header"), group: 1, help: N_("Hide a header from the upstream server.") },
        set_response_header: { label: N_("Set a response header"), group: 1, help: N_("Change what the visitor receives.") },
        remove_response_header: { label: N_("Remove a response header"), group: 1, help: N_("Strip a header from the response.") }
    };
    D.actionGroups = [N_("Decide the request"), N_("Change or observe the request")];
    D.terminating = { block: 1, redirect: 1, challenge: 1, rate_limit: 1, allow: 1 };
    D.skipLabels = {
        waf: N_("Web Application Firewall"), rate_limit: N_("Rate limit of the proxy rule"), auth: N_("Authentication"),
        captcha: N_("CAPTCHA"), rules: N_("All later rules")
    };
    D.redirectStatus = [301, 302, 303, 307, 308];
    D.placeholders = ["{host}", "{path}", "{query}", "{uri}", "{scheme}"];

    // ISO 3166 alpha-2 codes offered in the country picker (names come from Intl.DisplayNames, English fallback = the code)
    D.countries = ("AF AX AL DZ AS AD AO AI AG AR AM AW AU AT AZ BS BH BD BB BY BE BZ BJ BM BT BO BA BW BV BR VG BN BG BF MM BI TC KH CM CA CV KY CF TD CL CN CX CC CO KM CG CD CK CR CI HR CU CY CZ DK DJ DM DO EC EG SV GB GQ ER EE ET EU FK FO FJ FI FR GF PF TF GA GM GE DE GH GI GR GL GD GP GU GT GW GN GY HT HM HN HK HU IS IN IO ID IR IQ IE IL IT JM JP JO KZ KE KI KW KG LA LV LB LS LR LY LI LT LU MO MK MG MW MY MV ML MT MH MQ MR MU YT MX FM MD MC MN ME MS MA MZ NA NR NP NL NC PG NZ NI NE NG NU NF KP MP NO OM PK PW PS PA PY PE PH PN PL PT PR QA RE RO RU RW SH KN LC PM VC WS SM GS ST SA SN RS SC SL SG SK SI SB SO ZA KR ES LK SD SR SJ SZ SE CH SY TW TJ TZ TH TL TG TK TO TT TN TR TM TV UG UA AE US UY UM VI UZ VU VA VE VN WF EH YE ZM ZW XX").split(" ");
    var names = null;
    try { names = new Intl.DisplayNames([document.documentElement.lang || "en"], { type: "region" }); } catch (e) { names = null; }
    D.countryName = function (code) {
        if (code === "XX") { return typeof window.t === "function" ? window.t("Unknown country") : "Unknown country"; }
        try { var n = names && names.of(code); if (n && n !== code) { return n; } } catch (e) { /* not a region code */ }
        return code;
    };

    /*
        Quick-start templates. tree = the engine's structured form; action as in the API. Every template opens the
        builder pre-filled and LOG-ONLY. Empty values (a country, an address, a path) are the part the user fills in;
        the builder points at them. icon = Fomantic icon name.
    */
    D.templates = [
        {
            id: "block-country", icon: "globe", title: N_("Block a country"),
            desc: N_("Refuse visitors from the countries you pick."),
            name: "Block countries", description: "",
            tree: { type: "and", children: [{ type: "cond", field: "ip.country", op: "in", value: [] }] },
            action: { type: "block", status: 403 }
        },
        {
            id: "admin-my-ip", icon: "lock", title: N_("Allow only my IP to /admin"),
            desc: N_("Block everybody except the addresses you list from the /admin area."),
            name: "Admin area for my IP only", description: "",
            tree: { type: "and", children: [
                { type: "cond", field: "http.path", op: "starts_with", value: "/admin" },
                { type: "cond", field: "ip.src", op: "not_in", value: [] }] },
            action: { type: "block", status: 403 }
        },
        {
            id: "bad-agents", icon: "bug", title: N_("Block bad user agents"),
            desc: N_("Refuse well-known scanner and attack tools by their user agent."),
            name: "Block scanner user agents", description: "",
            tree: { type: "and", children: [
                { type: "cond", field: "http.user_agent", op: "matches", value: "(?i)(sqlmap|nikto|masscan|zgrab|dirbuster|nmap|wpscan)" }] },
            action: { type: "block", status: 403 }
        },
        {
            id: "rate-login", icon: "tachometer alternate", title: N_("Rate limit a login path"),
            desc: N_("Allow only a few requests per second per client to /login."),
            name: "Rate limit login", description: "",
            tree: { type: "and", children: [{ type: "cond", field: "http.path", op: "eq", value: "/login" }] },
            action: { type: "rate_limit", rate: 2, burst: 5, status: 429 }
        },
        {
            id: "redirect-old", icon: "share", title: N_("Redirect an old path"),
            desc: N_("Send visitors of an old address to the new one."),
            name: "Redirect old path", description: "",
            tree: { type: "and", children: [{ type: "cond", field: "http.path", op: "eq", value: "/old-page" }] },
            action: { type: "redirect", status: 301, url: "/new-page" }
        },
        {
            id: "challenge-path", icon: "check square", title: N_("Require a challenge for a path"),
            desc: N_("Make visitors of a sensitive path solve the CAPTCHA. Without a CAPTCHA provider on the site, matching requests are blocked."),
            name: "Challenge sensitive path", description: "",
            tree: { type: "and", children: [{ type: "cond", field: "http.path", op: "starts_with", value: "/wp-login.php" }] },
            action: { type: "challenge", ttl_minutes: 30 }
        },
        {
            id: "security-header", icon: "heading", title: N_("Add a security header"),
            desc: N_("Add X-Content-Type-Options: nosniff to every response."),
            name: "Add nosniff header", description: "",
            tree: { type: "and", children: [{ type: "cond", field: "http.path", op: "starts_with", value: "/" }] },
            action: { type: "set_response_header", name: "X-Content-Type-Options", value: "nosniff" }
        }
    ];
})();
