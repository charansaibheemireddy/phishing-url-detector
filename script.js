let historyData =
    JSON.parse(
        localStorage.getItem(
            "phishguard_history"
        )
    ) || [];


const suspiciousWords = [

    "login",
    "signin",
    "verify",
    "verification",
    "account",
    "update",
    "secure",
    "security",
    "password",
    "confirm",
    "bank",
    "wallet",
    "payment",
    "recover",
    "unlock"

];


function scanURL() {

    const input =
        document.getElementById(
            "urlInput"
        );

    const value =
        input.value.trim();


    if (!value) {

        alert(
            "Please enter a URL first."
        );

        return;

    }


    document.getElementById(
        "results"
    );


    document.getElementById(
        "loading"
    ).style.display = "block";


    document.getElementById(
        "result"
    ).style.display = "none";


    /*
        Small delay makes the scanner
        feel like a real security engine.
    */

    setTimeout(() => {

        const result =
            analyzeURL(value);


        displayResult(
            result
        );


        saveHistory(
            result
        );


        document.getElementById(
            "loading"
        ).style.display = "none";


    }, 900);

}


function analyzeURL(original) {

    let url =
        original;


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

            status: "Invalid URL",

            reasons: [
                "The entered URL could not be parsed."
            ],

            recommendation:
                "Check the URL and try again."

        };

    }


    const hostname =
        parsed.hostname;


    let score = 0;

    const reasons = [];


    /* HTTPS */

    if (
        parsed.protocol !==
        "https:"
    ) {

        score += 15;

        reasons.push(
            "⚠ Website does not use HTTPS"
        );

    }


    /* URL LENGTH */

    if (
        original.length > 75
    ) {

        score += 15;

        reasons.push(
            "⚠ URL is unusually long"
        );

    }


    /* IP ADDRESS */

    const ipPattern =
        /^(?:\d{1,3}\.){3}\d{1,3}$/;


    if (
        ipPattern.test(
            hostname
        )
    ) {

        score += 25;

        reasons.push(
            "⚠ URL uses an IP address instead of a domain"
        );

    }


    /* @ SYMBOL */

    if (
        original.includes("@")
    ) {

        score += 20;

        reasons.push(
            "⚠ URL contains an @ symbol"
        );

    }


    /* MANY SUBDOMAINS */

    const dots =
        hostname.split(".").length - 1;


    if (
        dots >= 3
    ) {

        score += 15;

        reasons.push(
            "⚠ URL contains multiple subdomains"
        );

    }


    /* HYPHENS */

    const hyphens =
        (hostname.match(
            /-/g
        ) || []).length;


    if (
        hyphens >= 2
    ) {

        score += 10;

        reasons.push(
            "⚠ Domain contains multiple hyphens"
        );

    }


    /* SUSPICIOUS WORDS */

    const lower =
        original.toLowerCase();


    const foundWords =
        suspiciousWords.filter(
            word =>
                lower.includes(word)
        );


    if (
        foundWords.length > 0
    ) {

        score += Math.min(
            foundWords.length * 5,
            20
        );


        reasons.push(
            "⚠ Suspicious keywords: " +
            foundWords.join(", ")
        );

    }


    score =
        Math.min(
            score,
            100
        );


    let status;

    let recommendation;


    if (
        score >= 60
    ) {

        status =
            "High Risk";

        recommendation =
            "Avoid this website and do not enter passwords, payment details or personal information.";

    }

    else if (
        score >= 30
    ) {

        status =
            "Suspicious";

        recommendation =
            "Verify the domain carefully before interacting with this website.";

    }

    else {

        status =
            "Likely Safe";

        recommendation =
            "No major suspicious URL patterns were detected.";

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
        data.length || data.url.length;


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


    if (
        data.score >= 60
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
        data.score >= 30
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


function saveHistory(data) {

    historyData.unshift({

        url: data.url,

        status: data.status,

        score: data.score,

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
                item.score >= 60
            ) {

                color =
                    "#ff596b";

            }

            else if (
                item.score >= 30
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


function clearHistory() {

    historyData = [];


    localStorage.removeItem(
        "phishguard_history"
    );


    displayHistory();

}


function escapeHTML(value) {

    const div =
        document.createElement(
            "div"
        );


    div.textContent =
        value;


    return div.innerHTML;

}


/* ENTER KEY */

document
    .getElementById(
        "urlInput"
    )
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


/* LOAD HISTORY */

displayHistory();
