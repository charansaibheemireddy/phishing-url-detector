/* =========================================================
   PHISHGUARD
   Phishing URL Detection Tool
   ========================================================= */


/* =========================================================
   SCAN HISTORY
   ========================================================= */

let historyData =
    JSON.parse(localStorage.getItem("phishguard_history")) || [];


/* =========================================================
   SUSPICIOUS KEYWORDS
   ========================================================= */

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


/* =========================================================
   BRANDS COMMONLY TARGETED BY PHISHING
   ========================================================= */

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


/* =========================================================
   SUSPICIOUS TLDs
   ========================================================= */

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
   SCAN URL
   ========================================================= */

function scanURL() {

    const input =
        document.getElementById("urlInput");

    if (!input) {

        console.error("urlInput not found.");

        return;

    }


    const value =
        input.value.trim();


    if (!value) {

        alert("Please enter a URL first.");

        return;

    }


    const loading =
        document.getElementById("loading");

    const result =
        document.getElementById("result");


    if (loading) {

        loading.style.display = "block";

    }


    if (result) {

        result.style.display = "none";

    }


    setTimeout(function () {

        const analysis =
            analyzeURL(value);


        displayResult(analysis);

        saveHistory(analysis);


        if (loading) {

            loading.style.display = "none";

        }

    }, 500);

}


/* =========================================================
   ANALYZE URL
   ========================================================= */

function analyzeURL(originalURL) {

    let url =
        originalURL.trim();


    /*
       Add http:// when the user enters only a domain.
    */

    if (
        !url.startsWith("http://") &&
        !url.startsWith("https://") &&
        !url.startsWith("javascript:") &&
        !url.startsWith("data:")
    ) {

        url =
            "http://" + url;

    }


    let parsedURL;


    try {

        parsedURL =
            new URL(url);

    }

    catch (error) {

        return {

            url: originalURL,

            score: 100,

            status: "High Risk",

            reasons: [
                "🚨 Invalid or malformed URL"
            ],

            recommendation:
                "Do not open this URL. Check the address carefully.",

            protocol: "--",

            domain: "--",

            length: originalURL.length

        };

    }


    const hostname =
        parsedURL.hostname.toLowerCase();


    const fullURL =
        originalURL.toLowerCase();


    let score = 0;

    let reasons = [];


    /* =====================================================
       1. HTTPS
       ===================================================== */

    if (
        parsedURL.protocol !== "https:"
    ) {

        score += 10;

        reasons.push(
            "⚠ Website does not use HTTPS"
        );

    }


    /* =====================================================
       2. IP ADDRESS
       ===================================================== */

    const ipv4 =
        /^(?:\d{1,3}\.){3}\d{1,3}$/;


    if (
        ipv4.test(hostname)
    ) {

        score += 30;

        reasons.push(
            "🚨 Website uses an IP address instead of a normal domain"
        );

    }


    /* =====================================================
       3. PUNYCODE
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
       4. LONG URL
       ===================================================== */

    if (
        originalURL.length > 120
    ) {

        score += 20;

        reasons.push(
            "⚠ URL is unusually long"
        );

    }

    else if (
        originalURL.length > 80
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
        originalURL.includes("@")
    ) {

        score += 25;

        reasons.push(
            "🚨 URL contains an @ symbol"
        );

    }


    /* =====================================================
       6. MANY SUBDOMAINS
       ===================================================== */

    const hostnameParts =
        hostname.split(".");


    const numberOfDots =
        hostnameParts.length - 1;


    if (
        numberOfDots >= 4
    ) {

        score += 25;

        reasons.push(
            "🚨 Domain contains an unusually large number of subdomains"
        );

    }

    else if (
        numberOfDots >= 3
    ) {

        score += 15;

        reasons.push(
            "⚠ Domain contains multiple subdomains"
        );

    }


    /* =====================================================
       7. HYPHENS
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

    const matchedTLD =
        suspiciousTLDs.find(
            function (tld) {

                return hostname.endsWith(tld);

            }
        );


    if (
        matchedTLD
    ) {

        score += 15;

        reasons.push(
            "⚠ Domain uses a TLD frequently seen in suspicious links: " +
            matchedTLD
        );

    }


    /* =====================================================
       9. SUSPICIOUS KEYWORDS
       ===================================================== */

    const foundWords =
        suspiciousWords.filter(
            function (word) {

                return fullURL.includes(word);

            }
        );


    if (
        foundWords.length >= 4
    ) {

        score += 30;

        reasons.push(
            "🚨 Multiple suspicious keywords detected: " +
            foundWords.slice(0, 8).join(", ")
        );

    }

    else if (
        foundWords.length >= 2
    ) {

        score += 20;

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

    const brandFound =
        popularBrands.find(
            function (brand) {

                return fullURL.includes(brand);

            }
        );


    if (
        brandFound
    ) {

        /*
           Look at the registered-looking domain.
        */

        const baseDomain =
            hostnameParts.length >= 2
                ? hostnameParts
                    .slice(-2)
                    .join(".")
                : hostname;


        const isBrandDomain =
            baseDomain.startsWith(
                brandFound + "."
            ) ||
            baseDomain.startsWith(
                brandFound
            );


        if (
            !isBrandDomain
        ) {

            score += 30;

            reasons.push(
                "🚨 Possible brand impersonation detected: " +
                brandFound
            );

        }

    }


    /* =====================================================
       11. REDIRECT PARAMETERS
       ===================================================== */

    const redirectPatterns = [

        "redirect=",
        "redirect_url=",
        "redirecturl=",
        "return=",
        "returnurl=",
        "next=",
        "continue=",
        "destination=",
        "target="

    ];


    const hasRedirect =
        redirectPatterns.some(
            function (pattern) {

                return fullURL.includes(pattern);

            }
        );


    if (
        hasRedirect
    ) {

        score += 12;

        reasons.push(
            "⚠ URL contains a possible redirect parameter"
        );

    }


    /* =====================================================
       12. ENCODED CHARACTERS
       ===================================================== */

    const encodedCharacters =
        (
            originalURL.match(
                /%[0-9a-fA-F]{2}/g
            ) || []
        ).length;


    if (
        encodedCharacters >= 5
    ) {

        score += 20;

        reasons.push(
            "⚠ URL contains many encoded characters"
        );

    }

    else if (
        encodedCharacters >= 2
    ) {

        score += 8;

        reasons.push(
            "⚠ URL contains encoded characters"
        );

    }


    /* =====================================================
       13. SPECIAL CHARACTERS
       ===================================================== */

    const specialCharacterCount =
        (
            originalURL.match(
                /[@?=&%$!#*]/g
            ) || []
        ).length;


    if (
        specialCharacterCount >= 10
    ) {

        score += 20;

        reasons.push(
            "⚠ URL contains an unusually high number of special characters"
        );

    }


    /* =====================================================
       14. NON-STANDARD PORT
       ===================================================== */

    if (
        parsedURL.port &&
        parsedURL.port !== "80" &&
        parsedURL.port !== "443"
    ) {

        score += 15;

        reasons.push(
            "⚠ Website uses a non-standard network port: " +
            parsedURL.port
        );

    }


    /* =====================================================
       15. DOUBLE SLASH IN PATH
       ===================================================== */

    if (
        parsedURL.pathname.includes("//")
    ) {

        score += 10;

        reasons.push(
            "⚠ URL contains an unusual double-slash path"
        );

    }


    /* =====================================================
       16. MANY QUERY PARAMETERS
       ===================================================== */

    let parameterCount = 0;


    if (
        parsedURL.search
    ) {

        parameterCount =
            parsedURL.search
                .substring(1)
                .split("&")
                .length;

    }


    if (
        parameterCount >= 8
    ) {

        score += 15;

        reasons.push(
            "⚠ URL contains an unusually large number of parameters"
        );

    }


    /* =====================================================
       17. UNUSUAL LETTER/NUMBER MIX
       ===================================================== */

    const domainWithoutTLD =
        hostnameParts.length >= 2
            ? hostnameParts[
                hostnameParts.length - 2
            ]
            : hostname;


    const numberCount =
        (
            domainWithoutTLD.match(/\d/g)
            || []
        ).length;


    if (
        domainWithoutTLD.length >= 12 &&
        numberCount >= 4
    ) {

        score += 15;

        reasons.push(
            "⚠ Domain contains an unusual combination of letters and numbers"
        );

    }


    /* =====================================================
       18. VERY LONG DOMAIN NAME
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
       19. SENSITIVE PATH
       ===================================================== */

    const sensitivePath =
        /\/(login|signin|verify|account|password|payment|bank|wallet)/i;


    if (
        sensitivePath.test(
            parsedURL.pathname
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
       REMOVE DUPLICATE INDICATORS
       ===================================================== */

    reasons =
        [...new Set(reasons)];


    /* =====================================================
       FINAL SCORE
       ===================================================== */

    score =
        Math.min(
            score,
            100
        );


    /* =====================================================
       FINAL CLASSIFICATION
       
       THIS IS THE IMPORTANT PART.
       
       0 warnings  = Likely Safe
       1-2 warnings = Suspicious
       3+ warnings  = High Risk
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
       RETURN RESULT
       ===================================================== */

    return {

        url:
            originalURL,

        score:
            score,

        status:
            status,

        reasons:
            reasons,

        recommendation:
            recommendation,

        protocol:
            parsedURL.protocol
                .replace(":", "")
                .toUpperCase(),

        domain:
            hostname,

        length:
            originalURL.length

    };

}


/* =========================================================
   DISPLAY RESULT
   ========================================================= */

function displayResult(data) {

    /*
       Recalculate status one more time before displaying.

       This guarantees that the result shown at the top
       always agrees with the indicators below.
    */

    if (
        data.reasons.length === 0
    ) {

        data.status =
            "Likely Safe";

    }

    else if (
        data.reasons.length <= 2
    ) {

        data.status =
            "Suspicious";

    }

    else {

        data.status =
            "High Risk";

    }


    /* =====================================================
       RESULT CONTAINER
       ===================================================== */

    const result =
        document.getElementById("result");


    if (result) {

        result.style.display =
            "block";

    }


    /* =====================================================
       RESULT TITLE
       ===================================================== */

    const resultTitle =
        document.getElementById("resultTitle");


    if (resultTitle) {

        resultTitle.textContent =
            data.status;

    }


    /* =====================================================
       SCORE
       ===================================================== */

    const scoreElement =
        document.getElementById("score");


    if (scoreElement) {

        scoreElement.textContent =
            data.score;

    }


    /* =====================================================
       RISK BADGE
       ===================================================== */

    const riskBadge =
        document.getElementById("riskBadge");


    if (riskBadge) {

        riskBadge.textContent =
            data.status;

    }


    /* =====================================================
       RECOMMENDATION
       ===================================================== */

    const recommendation =
        document.getElementById("recommendation");


    if (recommendation) {

        recommendation.textContent =
            data.recommendation;

    }


    /* =====================================================
       ANALYZED URL
       ===================================================== */

    const analyzedURL =
        document.getElementById("analyzedUrl");


    if (analyzedURL) {

        analyzedURL.textContent =
            data.url;

    }


    /* =====================================================
       PROTOCOL
       ===================================================== */

    const protocol =
        document.getElementById("protocol");


    if (protocol) {

        protocol.textContent =
            data.protocol;

    }


    /* =====================================================
       DOMAIN
       ===================================================== */

    const domain =
        document.getElementById("domain");


    if (domain) {

        domain.textContent =
            data.domain;

    }


    /* =====================================================
       URL LENGTH
       ===================================================== */

    const urlLength =
        document.getElementById("urlLength");


    if (urlLength) {

        urlLength.textContent =
            data.length;

    }


    /* =====================================================
       INDICATORS
       ===================================================== */

    const indicators =
        document.getElementById("indicators");


    if (indicators) {

        indicators.innerHTML = "";


        /*
           ZERO WARNINGS
        */

        if (
            data.reasons.length === 0
        ) {

            indicators.innerHTML = `

                <div class="indicator safe">

                    ✓ No major suspicious indicators detected

                </div>

            `;

        }


        /*
           WARNINGS FOUND
        */

        else {

            data.reasons.forEach(
                function (reason) {

                    const indicator =
                        document.createElement("div");


                    indicator.className =
                        "indicator warning";


                    indicator.textContent =
                        reason;


                    indicators.appendChild(
                        indicator
                    );

                }
            );

        }

    }


    /* =====================================================
       INDICATOR COUNT
       ===================================================== */

    const indicatorCount =
        document.getElementById(
            "indicatorCount"
        );


    if (indicatorCount) {

        if (
            data.reasons.length === 1
        ) {

            indicatorCount.textContent =
                "1 indicator";

        }

        else {

            indicatorCount.textContent =
                data.reasons.length +
                " indicators";

        }

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


    /* =====================================================
       SCORE CIRCLE COLOR
       ===================================================== */

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


    /* =====================================================
       SCROLL TO RESULT
       ===================================================== */

    if (
        result
    ) {

        result.scrollIntoView({
            behavior: "smooth"
        });

    }

}


/* =========================================================
   SAVE HISTORY
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


    /*
       Keep only the latest 10 scans.
    */

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

    const historyList =
        document.getElementById(
            "historyList"
        );


    if (!historyList) {

        return;

    }


    /* No history */

    if (
        historyData.length === 0
    ) {

        historyList.innerHTML = `

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


    historyList.innerHTML = "";


    historyData.forEach(
        function (item) {

            const row =
                document.createElement("div");


            row.className =
                "history-item";


            let statusColor =
                "#28d39b";


            if (
                item.status === "High Risk"
            ) {

                statusColor =
                    "#ff596b";

            }

            else if (
                item.status === "Suspicious"
            ) {

                statusColor =
                    "#f4c451";

            }


            row.innerHTML = `

                <div class="history-url">

                    🔗
                    ${escapeHTML(item.url)}

                </div>

                <div
                    class="history-status"
                    style="color:${statusColor}"
                >

                    ${escapeHTML(item.status)}
                    ·
                    ${item.score}/100

                </div>

            `;


            historyList.appendChild(
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
   ESCAPE HTML
   ========================================================= */

function escapeHTML(value) {

    const element =
        document.createElement("div");


    element.textContent =
        value;


    return element.innerHTML;

}


/* =========================================================
   ENTER KEY
   ========================================================= */

const urlInput =
    document.getElementById(
        "urlInput"
    );


if (
    urlInput
) {

    urlInput.addEventListener(
        "keydown",
        function (event) {

            if (
                event.key === "Enter"
            ) {

                scanURL();

            }

        }
    );

}


/* =========================================================
   LOAD HISTORY WHEN PAGE OPENS
   ========================================================= */

displayHistory();
