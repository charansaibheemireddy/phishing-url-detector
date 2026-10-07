async function scanURL() {

    const input = document.getElementById("urlInput");
    const result = document.getElementById("result");
    const loading = document.getElementById("loading");

    const url = input.value.trim();

    if (!url) {
        alert("Please enter a URL.");
        return;
    }

    result.style.display = "none";
    loading.style.display = "block";

    try {

        const response = await fetch("/scan", {

            method: "POST",

            headers: {
                "Content-Type": "application/json"
            },

            body: JSON.stringify({
                url: url
            })

        });

        const data = await response.json();

        loading.style.display = "none";

        if (data.error) {
            alert(data.error);
            return;
        }

        document.getElementById("score").textContent =
            data.score + "%";

        document.getElementById("status").textContent =
            data.status;

        const reasonsList =
            document.getElementById("reasons");

        reasonsList.innerHTML = "";

        if (data.reasons.length === 0) {

            const li = document.createElement("li");

            li.textContent =
                "No suspicious characteristics detected.";

            reasonsList.appendChild(li);

        } else {

            data.reasons.forEach(reason => {

                const li = document.createElement("li");

                li.textContent = "⚠ " + reason;

                reasonsList.appendChild(li);

            });
        }

        document.getElementById("recommendation")
            .textContent = data.recommendation;

        result.style.display = "block";

    } catch (error) {

        loading.style.display = "none";

        alert("Unable to connect to the server.");

        console.error(error);
    }
}
