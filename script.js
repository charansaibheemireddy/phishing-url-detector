let historyData =
    JSON.parse(
        localStorage.getItem("phishguard_history")
    ) || [];


/* =========================================================
   PHISHGUARD URL DETECTION ENGINE
   ========================================================= */


/* Common suspicious words found in phishing URLs */

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
    "support",
    "microsoft",
    "paypal",
    "apple",
    "google",
    "facebook",
    "instagram",
    "amazon",
    "netflix"
];


/* Common brands attackers may try to imitate */

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
   They are NOT automatically malicious. */

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


    document.getElementById(
        "loading"
    ).style.display = "block";


    document.getElementById(
        "result"
    ).style.display = "none";


    setTimeout(() => {

        const result =
            analyzeURL(value);


        displayResult(result);

        saveHistory(result);


        document.getElementById(
            "loading"
        ).style.display = "none";

    }, 900);

}


/* =========================================================
   URL ANALYSIS
   ========================================================= */

function analyzeURL(original) {

    let url = original.trim();


    /*
        Add protocol if the user did not enter one.
    */

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
                "❌ The entered URL is invalid or cannot be parsed."
            ],

            recommendation:
                "Do not open this link. Check the URL carefully."

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
       4. URL LENGTH
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
       5. @ SYMBOL
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
       6. MULTIPLE SUBDOMAINS
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
       8. SUSPICIOUS TLD
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
            "⚠ Domain uses a TLD frequently associated with suspicious links: " +
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
       10. BRAND IMPERSONATION
       ===================================================== */

    const brandMatches =
        popularBrands.filter(
            brand =>
                fullURL.includes(brand)
        );


    if (
        brandMatches.length > 0
    ) {

        /*
           Determine whether the brand is actually
           the registered-looking domain itself.
        */

        const baseDomain =
            hostnameParts
                .slice(-2)
                .join(".");


        const impersonatedBrand =
            brandMatches.find(
                brand =>
                    !baseDomain.startsWith(
                        brand + "."
                    ) &&
                    !baseDomain.includes(
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

    }


    /* =====================================================
       11. REDIRECT PARAMETERS
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
       12. ENCODED CHARACTERS
       ===================================================== */

    const encodedCount =
        (
            original.match(/%[0-9a-fA-F]{2}/g)
            || []
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
       13. SPECIAL CHARACTER COUNT
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
       15. DOUBLE SLASH PATH
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
       16. EXCESSIVE QUERY PARAMETERS
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
       17. RANDOM-LOOKING DOMAIN
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
       19. CREDENTIAL PATH
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
       20. DATA URI / JAVASCRIPT URL
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
       FINAL SCORE
       ===================================================== */

    score =
        Math.min(
            score,
            100
        );


    /* =====================================================
       CLASSIFICATION
       ===================================================== */

    let status;

    let recommendation;


    if (
        score >= 70
    ) {

        status =
            "High Risk";

        recommendation =
            "This URL contains several suspicious characteristics. Avoid opening it or entering personal information.";

    }

    else if (
        score >= 35
    ) {

        status =
            "Suspicious";

        recommendation =
            "This URL contains potentially suspicious characteristics. Verify the website independently before continuing.";

    }

    else {

        status =
            "Likely Safe";

        recommendation =
            "No major suspicious URL patterns were detected. However, this does not guarantee that the website is safe.";

    }


    return {

        url: original,

        score: score,

        status: status,

        reasons: reasons,

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

    document.getElementById(
        "result"
    ).style.display = "block";


    document.getElementById(
        "resultTitle"
    ).textContent =
        data.status;


    document.getElementById(
        "score"
    ).textContent =
        data.score;


    document.getElementById(
        "riskBadge"
    ).textContent =
        data.status;


    document.getElementById(
        "recommendation"
    ).textContent =
        data.recommendation;


    document.getElementById(
        "analyzedUrl"
    ).textContent =
        data.url;


    document.getElementById(
        "protocol"
    ).textContent =
        data.protocol || "--";


    document.getElementById(
        "domain"
    ).textContent =
        data.domain || "--";


    document.getElementById(
        "urlLength"
    ).textContent =
        data.length ||
        data.url.length;


    const container =
        document.getElementById(
            "indicators"
        );


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


    document.getElementById(
        "indicatorCount"
    ).textContent =

        data.reasons.length +
        " indicators";


    /* Risk colors */

    if (
        data.score >= 70
    ) {

        document.getElementById(
            "riskBadge"
        ).style.color =
            "#ff596b";


        document.querySelector(
            ".score-circle"
        ).style.borderColor =
            "#69313b";

    }

    else if (
        data.score >= 35
    ) {

        document.getElementById(
            "riskBadge"
        ).style.color =
            "#f4c451";


        document.querySelector(
            ".score-circle"
        ).style.borderColor =
            "#66532b";

    }

    else {

        document.getElementById(
            "riskBadge"
        ).style.color =
            "#28d39b";


        document.querySelector(
            ".score-circle"
        ).style.borderColor =
            "#24614e";

    }


    document.getElementById(
        "result"
    ).scrollIntoView({
        behavior: "smooth"
    });

}


/* =========================================================
   HISTORY
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


    historyData =
        historyData.slice(
            0,
            10
        );


    localStorage.setItem(
        "phishguard_history",
        JSON.stringify(
            historyData
        )
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
                item.score >= 70
            ) {

                color =
                    "#ff596b";

            }

            else if (
                item.score >= 35
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
   HTML SECURITY
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

document
    .getElementById("urlInput")
    .addEventListener(
        "keydown",
        event => {

            if (
                event.key === "Enter"
            ) {

                scanURL();

            }

        }
    );


/* =========================================================
   LOAD HISTORY
   ========================================================= */

displayHistory();
