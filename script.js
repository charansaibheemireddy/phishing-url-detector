let scanHistory =
    JSON.parse(localStorage.getItem("phishguard_history")) || [];


document.addEventListener(
    "DOMContentLoaded",
    loadHistory
);


async function scanURL() {

    const input =
        document.getElementById("urlInput");

    const url =
        input.value.trim();

    if (!url) {

        alert("Please enter a URL.");

        return;
    }


    document.getElementById("result")
        .style.display = "none";

    document.getElementById("loading")
        .style.display = "block";


    try {

        const response = await fetch(
            "/scan",
            {
                method: "POST",

                headers: {
                    "Content-Type":
                        "application/json"
                },

                body: JSON.stringify({
                    url: url
                })
            }
        );


        const data =
            await response.json();


        if (data.error) {

            throw new Error(data.error);

        }


        displayResult(data);

        addToHistory(data);


    } catch (error) {

        alert(error.message);

    } finally {

        document.getElementById("loading")
            .style.display = "none";

    }
}


function displayResult(data) {

    const result =
        document.getElementById("result");


    document.getElementById("score")
        .textContent = data.score;


    document.getElementById("status")
        .textContent = data.status;


    document.getElementById("recommendation")
        .textContent =
        data.recommendation;


    document.getElementById("analyzedUrl")
        .textContent = data.url;


    document.getElementById("protocol")
        .textContent =
        data.url.startsWith("https")
            ? "HTTPS"
            : "HTTP";


    try {

        const parsed =
            new URL(
                data.url.startsWith("http")
                    ? data.url
                    : "http://" + data.url
            );

        document.getElementById("domain")
            .textContent =
            parsed.hostname;

    } catch {

        document.getElementById("domain")
            .textContent = "Unknown";

    }


    const badge =
        document.getElementById("riskBadge");


    badge.textContent =
        data.status;


    const reasons =
        document.getElementById("reasons");


    reasons.innerHTML = "";


    if (data.reasons.length === 0) {

        const item =
            document.createElement("div");

        item.className =
            "indicator safe";

        item.textContent =
            "✓ No major suspicious indicators detected";

        reasons.appendChild(item);

    } else {

        data.reasons.forEach(reason => {

            const item =
                document.createElement("div");

            item.className =
                "indicator warning";

            item.textContent =
                "⚠ " + reason;

            reasons.appendChild(item);

        });

    }


    document.getElementById(
        "indicatorCount"
    ).textContent =
        `${data.reasons.length} indicators`;


    result.style.display = "block";


    result.scrollIntoView({
        behavior: "smooth",
        block: "start"
    });

}


function addToHistory(data) {

    scanHistory.unshift({

        url: data.url,

        status: data.status,

        score: data.score,

        time: new Date()
            .toLocaleTimeString()

    });


    scanHistory =
        scanHistory.slice(0, 8);


    localStorage.setItem(
        "phishguard_history",
        JSON.stringify(scanHistory)
    );


    loadHistory();

}


function loadHistory() {

    const container =
        document.getElementById(
            "historyList"
        );


    if (!scanHistory.length) {

        container.innerHTML = `

            <div class="empty-history">

                <span>◷</span>

                <p>No scans yet</p>

                <small>
                    Your recent URL scans
                    will appear here.
                </small>

            </div>

        `;

        return;
    }


    container.innerHTML = "";


    scanHistory.forEach(item => {

        const row =
            document.createElement("div");

        row.className =
            "history-item";


        const color =
            item.score >= 60
                ? "#ff5c6c"
                : item.score >= 30
                ? "#f6c453"
                : "#25d39a";


        row.innerHTML = `

            <div class="history-url">

                🔗 ${escapeHTML(item.url)}

            </div>

            <div
                class="history-status"
                style="color:${color}">

                ${escapeHTML(item.status)}
                · ${item.score}/100

            </div>

        `;


        container.appendChild(row);

    });

}


function clearHistory() {

    scanHistory = [];

    localStorage.removeItem(
        "phishguard_history"
    );

    loadHistory();

}


function escapeHTML(value) {

    const div =
        document.createElement("div");

    div.textContent = value;

    return div.innerHTML;

}


/* ENTER KEY */

document
    .getElementById("urlInput")
    .addEventListener(
        "keydown",
        function(event) {

            if (event.key === "Enter") {

                scanURL();

            }

        }
    );
