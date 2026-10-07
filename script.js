let historyData =
    JSON.parse(localStorage.getItem("phishguard_history")) || [];


/* =========================================================
   PHISHGUARD URL DETECTION ENGINE
   ========================================================= */


/* Suspicious words commonly found in phishing URLs */

const suspiciousWords = [
    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "authenticate",
    "authentication",
    "account",
    "update",
    "secure",
    "security",
    "password",
    "passwd",
    "confirm",
    "confirmation",
    "bank",
    "banking",
    "wallet",
    "payment",
    "pay",
    "billing",
    "invoice",
    "recover",
    "recovery",
    "unlock",
    "suspend",
    "suspended",
    "alert",
    "urgent",
    "validate",
    "credential",
    "credentials",
    "webmail",
    "support"
];


/* Popular brands commonly impersonated by phishing sites */

const popularBrands = [
    "paypal",
    "microsoft",
    "google",
    "apple",
    "amazon",
    "facebook",
    "instagram",
    "netflix",
    "linkedin",
    "whatsapp",
    "steam",
    "github",
    "outlook",
    "office365",
    "dropbox",
    "adobe",
    "docusign",
    "coinbase",
    "binance"
];


/* TLDs that deserve additional scrutiny.
   These are NOT automatically malicious. */

const suspiciousTLDs = [
    ".tk",
    ".ml",
    ".ga",
    ".cf",
    ".gq",
    ".top",
    ".xyz",
    ".click",
    ".link",
    ".work",
    ".download",
    ".zip",
    ".mov",
    ".cam",
    ".buzz",
    ".monster"
];


/* =========================================================
   MAIN SCANNER
   ========================================================= */

function scanURL() {

    const input =
        document.getElementById("urlInput");

    const value =
        input.value.trim();


    if (!value) {

        alert("Please enter a URL first.");

        return;

    }


    /* Show loading screen if available */

    const loading =
        document.getElementById("loading");

    if (loading) {

        loading.style.display = "block";

    }


    const resultBox =
        document.getElementById("result");

    if (resultBox) {

        resultBox.style.display = "none";

    }


    /* Small delay for scanning animation */

    setTimeout(() => {

        const result =
            analyzeURL(value);


        displayResult(result);

        saveHistory(result);


        if (loading) {

            loading.style.display = "none";

        }

    }, 700);

}


/* =========================================================
   URL ANALYSIS
   ========================================================= */

function analyzeURL(original) {

    let url =
        original.trim();


    /* Add protocol when user enters only a domain */

    if (
        !url.startsWith("http://") &&
        !url.startsWith("https://")
    ) {

        url =
            "http://" + url;

    }


    let parsed;


    try {

        parsed =
            new URL(url);

    }

    catch {

        return {

            url: original,

            score: 100,

            status: "High Risk",

            reasons: [
                "🚨 The entered URL is invalid or cannot be parsed."
            ],

            recommendation:
                "Do not open this link. Check the URL carefully.",

            protocol: "--",

            domain: "--",

            length: original.length

        };

    }


    const hostname =
        parsed.hostname.toLowerCase();


    const fullURL =
        original.toLowerCase();


    let score = 0;

    const reasons = [];


    /* =====================================================
       1. HTTPS CHECK
       ===================================================== */

    if (
        parsed.protocol !== "https:"
    ) {

        score += 15;

        reasons.push(
            "⚠ Website does not use HTTPS"
        );

    }


    /* =====================================================
       2. IP ADDRESS CHECK
       ===================================================== */

    const ipv4Pattern =
        /^(?:\d{1,3}\.){3}\d{1,3}$/;


    const ipv6Pattern =
        /^\[?[0-9a-fA-F:]+\]?$/;


    if (
        ipv4Pattern.test(hostname) ||
        ipv6Pattern.test(hostname)
    ) {

        score += 30;

        reasons.push(
            "🚨 Website uses an IP address instead of a normal domain"
        );

    }


    /* =====================================================
       3. PUNYCODE CHECK
       ===================================================== */

    if (
        hostname.includes("xn--")
    ) {

        score += 30;

        reasons.push(
            "🚨 Domain uses Punycode, which can be used for look-alike domains"
        );

    }


    /* =====================================================
       4. URL LENGTH CHECK
       ===================================================== */

    if (
        original.length > 100
    ) {

        score += 20;

        reasons.push(
            "⚠ URL is unusually long"
        );

    }

    else if (
        original.length > 75
    ) {

        score += 10;

        reasons.push(
            "⚠ URL is longer than typical"
        );

    }


    /* =====================================================
       5. @ SYMBOL CHECK
       ===================================================== */

    if (
        original.includes("@")
    ) {

        score += 25;

        reasons.push(
            "🚨 URL contains an @ symbol"
        );

    }


    /* =====================================================
       6. SUBDOMAIN CHECK
       ===================================================== */

    const hostnameParts =
        hostname.split(".");


    const dotCount =
        hostnameParts.length - 1;


    if (
        dotCount >= 4
    ) {

        score += 25;

        reasons.push(
            "🚨 Domain contains an unusually large number of subdomains"
        );

    }

    else if (
        dotCount >= 3
    ) {

        score += 15;

        reasons.push(
            "⚠ Domain contains multiple subdomains"
        );

    }


    /* =====================================================
       7. HYPHEN CHECK
       ===================================================== */

    const hyphenCount =
        (
            hostname.match(/-/g) || []
        ).length;


    if (
        hyphenCount >= 4
    ) {

        score += 20;

        reasons.push(
            "⚠ Domain contains many hyphens"
        );

    }

    else if (
        hyphenCount >= 2
    ) {

        score += 10;

        reasons.push(
            "⚠ Domain contains multiple hyphens"
        );

    }


    /* =====================================================
       8. SUSPICIOUS TLD CHECK
       ===================================================== */

    const suspiciousTLD =
        suspiciousTLDs.find(
            tld =>
                hostname.endsWith(tld)
        );


    if (
        suspiciousTLD
    ) {

        score += 15;

        reasons.push(
            "⚠ Domain uses a TLD frequently seen in suspicious links: " +
            suspiciousTLD
        );

    }


    /* =====================================================
       9. SUSPICIOUS KEYWORDS
       ===================================================== */

    const foundWords =
        suspiciousWords.filter(
            word =>
                fullURL.includes(word)
        );


    if (
        foundWords.length >= 4
    ) {

        score += 25;

        reasons.push(
            "🚨 Multiple suspicious keywords detected: " +
            foundWords.slice(0, 6).join(", ")
        );

    }

    else if (
        foundWords.length >= 2
    ) {

        score += 15;

        reasons.push(
            "⚠ Suspicious keywords detected: " +
            foundWords.join(", ")
        );

    }

    else if (
        foundWords.length === 1
    ) {

        score += 7;

        reasons.push(
            "⚠ Suspicious keyword detected: " +
            foundWords[0]
        );

    }


    /* =====================================================
       10. BRAND IMPERSONATION CHECK
       ===================================================== */

    const baseDomain =
        hostnameParts.length >= 2
            ? hostnameParts.slice(-2).join(".")
            : hostname;


    const brandMatches =
        popularBrands.filter(
            brand =>
                fullURL.includes(brand)
        );


    const impersonatedBrand =
        brandMatches.find(
            brand =>
                !baseDomain.startsWith(
                    brand + "."
                ) &&
                !baseDomain.startsWith(
                    brand
                )
        );


    if (
        impersonatedBrand
    ) {

        score += 30;

        reasons.push(
            "🚨 Possible brand impersonation detected: " +
            impersonatedBrand
        );

    }


    /* =====================================================
       11. REDIRECT PARAMETER CHECK
       ===================================================== */

    const redirectWords = [
        "redirect=",
        "redirect_url=",
        "redirecturl=",
        "return=",
        "returnurl=",
        "url=",
        "next=",
        "continue=",
        "destination=",
        "target="
    ];


    const foundRedirect =
        redirectWords.some(
            word =>
                fullURL.includes(word)
        );


    if (
        foundRedirect
    ) {

        score += 12;

        reasons.push(
            "⚠ URL contains a possible redirect parameter"
        );

    }


    /* =====================================================
       12. ENCODED CHARACTER CHECK
       ===================================================== */

    const encodedCount =
        (
            original.match(
                /%[0-9a-fA-F]{2}/g
            ) || []
        ).length;


    if (
        encodedCount >= 5
    ) {

        score += 20;

        reasons.push(
            "⚠ URL contains many encoded characters"
        );

    }

    else if (
        encodedCount >= 2
    ) {

        score += 8;

        reasons.push(
            "⚠ URL contains encoded characters"
        );

    }


    /* =====================================================
       13. SPECIAL CHARACTER CHECK
       ===================================================== */

    const specialCharacters =
        (
            original.match(
                /[@?=&%$!#*]/g
            ) || []
        ).length;


    if (
        specialCharacters >= 10
    ) {

        score += 20;

        reasons.push(
            "⚠ URL contains an unusually high number of special characters"
        );

    }


    /* =====================================================
       14. PORT CHECK
       ===================================================== */

    const port =
        parsed.port;


    if (
        port &&
        port !== "80" &&
        port !== "443"
    ) {

        score += 15;

        reasons.push(
            "⚠ Website uses a non-standard network port: " +
            port
        );

    }


    /* =====================================================
       15. DOUBLE-SLASH PATH CHECK
       ===================================================== */

    if (
        parsed.pathname.includes("//")
    ) {

        score += 10;

        reasons.push(
            "⚠ URL contains an unusual double-slash path"
        );

    }


    /* =====================================================
       16. QUERY PARAMETER CHECK
       ===================================================== */

    const queryParameters =
        parsed.search
            ? parsed.search
                .substring(1)
                .split("&")
                .length
            : 0;


    if (
        queryParameters >= 8
    ) {

        score += 15;

        reasons.push(
            "⚠ URL contains an unusually large number of parameters"
        );

    }


    /* =====================================================
       17. UNUSUAL DOMAIN CHARACTERISTICS
       ===================================================== */

    const domainWithoutTLD =
        hostnameParts.length >= 2
            ? hostnameParts[
                hostnameParts.length - 2
            ]
            : hostname;


    const digitCount =
        (
            domainWithoutTLD.match(/\d/g)
            || []
        ).length;


    if (
        domainWithoutTLD.length >= 12 &&
        digitCount >= 4
    ) {

        score += 15;

        reasons.push(
            "⚠ Domain contains an unusual combination of letters and numbers"
        );

    }


    /* =====================================================
       18. VERY LONG DOMAIN
       ===================================================== */

    if (
        domainWithoutTLD.length > 30
    ) {

        score += 15;

        reasons.push(
            "⚠ Domain name is unusually long"
        );

    }


    /* =====================================================
       19. SENSITIVE PATH CHECK
       ===================================================== */

    const credentialPattern =
        /\/(login|signin|verify|account|password|payment|bank|wallet)/i;


    if (
        credentialPattern.test(
            parsed.pathname
        )
    ) {

        score += 10;

        reasons.push(
            "⚠ URL contains a sensitive credential/payment-related path"
        );

    }


    /* =====================================================
       20. DANGEROUS URL SCHEME
       ===================================================== */

    if (
        fullURL.startsWith("javascript:") ||
        fullURL.startsWith("data:")
    ) {

        score = 100;

        reasons.push(
            "🚨 Dangerous URL scheme detected"
        );

    }


    /* =====================================================
       LIMIT SCORE TO 100
       ===================================================== */

    score =
        Math.min(score, 100);


    /* =====================================================
       CLASSIFICATION
       
       IMPORTANT:
       
       0 indicators       = Likely Safe
       1–2 indicators     = Suspicious
       3+ indicators      = High Risk
       
       This means the displayed result ALWAYS matches
       the number of warnings shown below.
       ===================================================== */

    let status;
    let recommendation;


    if (
        reasons.length === 0
    ) {

        status =
            "Likely Safe";

        recommendation =
            "No suspicious URL patterns were detected. However, this does not guarantee that the website is completely safe.";

    }

    else if (
        reasons.length <= 2
    ) {

        status =
            "Suspicious";

        recommendation =
            "This URL contains suspicious characteristics. Verify the website carefully before continuing.";

    }

    else {

        status =
            "High Risk";

        recommendation =
            "This URL contains multiple suspicious characteristics. Avoid opening the link or entering personal information.";

    }


    /* =====================================================
       RETURN ANALYSIS RESULT
       ===================================================== */

    return {

        url:
            original,

        score:
            score,

        status:
            status,

        reasons:
            reasons,

        recommendation:
            recommendation,

        protocol:
            parsed.protocol
                .replace(":", "")
                .toUpperCase(),

        domain:
            hostname,

        length:
            original.length

    };

}


/* =========================================================
   DISPLAY RESULT
   ========================================================= */

function displayResult(data) {

    const result =
        document.getElementById("result");


    if (result) {

        result.style.display =
            "block";

    }


    /* Result title */

    const resultTitle =
        document.getElementById("resultTitle");


    if (resultTitle) {

        resultTitle.textContent =
            data.status;

    }


    /* Risk score */

    const score =
        document.getElementById("score");


    if (score) {

        score.textContent =
            data.score;

    }


    /* Risk badge */

    const riskBadge =
        document.getElementById("riskBadge");


    if (riskBadge) {

        riskBadge.textContent =
            data.status;

    }


    /* Recommendation */

    const recommendation =
        document.getElementById("recommendation");


    if (recommendation) {

        recommendation.textContent =
            data.recommendation;

    }


    /* Analyzed URL */

    const analyzedURL =
        document.getElementById("analyzedUrl");


    if (analyzedURL) {

        analyzedURL.textContent =
            data.url;

    }


    /* Protocol */

    const protocol =
        document.getElementById("protocol");


    if (protocol) {

        protocol.textContent =
            data.protocol || "--";

    }


    /* Domain */

    const domain =
        document.getElementById("domain");


    if (domain) {

        domain.textContent =
            data.domain || "--";

    }


    /* URL length */

    const urlLength =
        document.getElementById("urlLength");


    if (urlLength) {

        urlLength.textContent =
            data.length || data.url.length;

    }


    /* =====================================================
       DISPLAY INDICATORS
       ===================================================== */

    const container =
        document.getElementById("indicators");


    if (container) {

        container.innerHTML = "";


        if (
            data.reasons.length === 0
        ) {

            container.innerHTML = `

                <div class="indicator safe">

                    ✓ No major suspicious indicators detected

                </div>

            `;

        }

        else {

            data.reasons.forEach(
                reason => {

                    const div =
                        document.createElement(
                            "div"
                        );


                    div.className =
                        "indicator warning";


                    div.textContent =
                        reason;


                    container.appendChild(
                        div
                    );

                }
            );

        }

    }


    /* Indicator count */

    const indicatorCount =
        document.getElementById(
            "indicatorCount"
        );


    if (indicatorCount) {

        indicatorCount.textContent =
            data.reasons.length +
            (
                data.reasons.length === 1
                    ? " indicator"
                    : " indicators"
            );

    }


    /* =====================================================
       RISK COLORS
       ===================================================== */

    if (
        riskBadge
    ) {

        if (
            data.status === "High Risk"
        ) {

            riskBadge.style.color =
                "#ff596b";

        }

        else if (
            data.status === "Suspicious"
        ) {

            riskBadge.style.color =
                "#f4c451";

        }

        else {

            riskBadge.style.color =
                "#28d39b";

        }

    }


    /* Score circle */

    const scoreCircle =
        document.querySelector(
            ".score-circle"
        );


    if (
        scoreCircle
    ) {

        if (
            data.status === "High Risk"
        ) {

            scoreCircle.style.borderColor =
                "#69313b";

        }

        else if (
            data.status === "Suspicious"
        ) {

            scoreCircle.style.borderColor =
                "#66532b";

        }

        else {

            scoreCircle.style.borderColor =
                "#24614e";

        }

    }


    /* Scroll to result */

    if (
        result
    ) {

        result.scrollIntoView({
            behavior: "smooth"
        });

    }

}


/* =========================================================
   SAVE SCAN HISTORY
   ========================================================= */

function saveHistory(data) {

    historyData.unshift({

        url:
            data.url,

        status:
            data.status,

        score:
            data.score,

        time:
            new Date()
                .toLocaleTimeString()

    });


    /* Keep only latest 10 scans */

    historyData =
        historyData.slice(0, 10);


    localStorage.setItem(
        "phishguard_history",
        JSON.stringify(historyData)
    );


    displayHistory();

}


/* =========================================================
   DISPLAY HISTORY
   ========================================================= */

function displayHistory() {

    const container =
        document.getElementById(
            "historyList"
        );


    if (!container) {

        return;

    }


    if (
        historyData.length === 0
    ) {

        container.innerHTML = `

            <div class="empty">

                <div>◷</div>

                <p>
                    No scans yet
                </p>

                <small>
                    Scanned URLs will appear here.
                </small>

            </div>

        `;

        return;

    }


    container.innerHTML = "";


    historyData.forEach(
        item => {

            const row =
                document.createElement(
                    "div"
                );


            row.className =
                "history-item";


            let color =
                "#28d39b";


            if (
                item.status === "High Risk"
            ) {

                color =
                    "#ff596b";

            }

            else if (
                item.status === "Suspicious"
            ) {

                color =
                    "#f4c451";

            }


            row.innerHTML = `

                <div class="history-url">

                    🔗
                    ${escapeHTML(item.url)}

                </div>

                <div
                    class="history-status"
                    style="color:${color}"
                >

                    ${escapeHTML(item.status)}
                    ·
                    ${item.score}/100

                </div>

            `;


            container.appendChild(
                row
            );

        }
    );

}


/* =========================================================
   CLEAR HISTORY
   ========================================================= */

function clearHistory() {

    historyData = [];


    localStorage.removeItem(
        "phishguard_history"
    );


    displayHistory();

}


/* =========================================================
   HTML ESCAPING
   ========================================================= */

function escapeHTML(value) {

    const div =
        document.createElement(
            "div"
        );


    div.textContent =
        value;


    return div.innerHTML;

}


/* =========================================================
   ENTER KEY SUPPORT
   ========================================================= */

const urlInput =
    document.getElementById(
        "urlInput"
    );


if (urlInput) {

    urlInput.addEventListener(
        "keydown",
        event => {

            if (
                event.key === "Enter"
            ) {

                scanURL();

            }

        }
    );

}


/* =========================================================
   LOAD SAVED HISTORY
   ========================================================= */

displayHistory();
