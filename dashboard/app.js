document.addEventListener("DOMContentLoaded", () => {
  
  // 1. Navigation Controller
  const navDashboard = document.getElementById("nav-dashboard");
  const navHistory = document.getElementById("nav-history");
  const navSettings = document.getElementById("nav-settings");
  
  const pageDashboard = document.getElementById("page-dashboard");
  const pageHistory = document.getElementById("page-history");
  const pageSettings = document.getElementById("page-settings");
  
  const pageTitle = document.getElementById("page-title");
  
  function switchPage(activeLink, activePage, title) {
    // Reset pages
    pageDashboard.classList.add("hidden");
    pageHistory.classList.add("hidden");
    pageSettings.classList.add("hidden");
    
    // Reset nav links styling
    [navDashboard, navHistory, navSettings].forEach(link => {
      link.className = "flex items-center space-x-3 px-4 py-3 rounded-xl transition-all duration-200 text-zinc-400 hover:text-gray-200 hover:bg-zinc-900/50 border border-transparent";
    });
    
    // Set active page
    activePage.classList.remove("hidden");
    activeLink.className = "flex items-center space-x-3 px-4 py-3 rounded-xl transition-all duration-200 bg-amber-500/10 text-amber-500 border border-amber-500/20 shadow-lg shadow-amber-500/5";
    pageTitle.textContent = title;
  }
  
  navDashboard.addEventListener("click", (e) => {
    e.preventDefault();
    switchPage(navDashboard, pageDashboard, "API Fuzzing Dashboard");
  });
  
  navHistory.addEventListener("click", (e) => {
    e.preventDefault();
    switchPage(navHistory, pageHistory, "Fuzzing Test History");
  });
  
  navSettings.addEventListener("click", (e) => {
    e.preventDefault();
    switchPage(navSettings, pageSettings, "Engine Configuration");
  });

  // 2. Concurrency slider dynamic indicator
  const concurrencySlider = document.getElementById("concurrency-slider");
  const concurrencyDisplay = document.getElementById("concurrency-display");
  
  concurrencySlider.addEventListener("input", (e) => {
    concurrencyDisplay.textContent = `${e.target.value} threads`;
  });

  // 3. Simulated Fuzz Strategies list (matching Python results)
  const fuzzStrategies = [
    // Malformed JSON (400)
    { strategy: "Malformed JSON: trailing comma", code: 400, latMin: 12, latMax: 25 },
    { strategy: "Malformed JSON: missing brace", code: 400, latMin: 10, latMax: 18 },
    { strategy: "Malformed JSON: missing separator", code: 400, latMin: 15, latMax: 22 },
    { strategy: "Malformed JSON: extra junk bytes", code: 400, latMin: 18, latMax: 30 },
    
    // Standard baseline success (200)
    { strategy: "Baseline validation check", code: 200, latMin: 35, latMax: 50 },
    { strategy: "Empty elements fallback validation", code: 200, latMin: 32, latMax: 45 },
    
    // Type Fuzzing mismatch (422)
    { strategy: "Type swap: username -> integer", code: 422, latMin: 22, latMax: 40 },
    { strategy: "Type swap: age -> boolean", code: 422, latMin: 20, latMax: 38 },
    { strategy: "Type swap: age -> list", code: 422, latMin: 25, latMax: 42 },
    { strategy: "Type swap: is_active -> string", code: 422, latMin: 21, latMax: 35 },
    
    // Boundary and internal overflows (500)
    { strategy: "Boundary overflow: username (>5000 chars)", code: 500, latMin: 90, latMax: 140, msg: "Internal Database Column Overflow" },
    { strategy: "Arithmetic overflow: age (1.79e308)", code: 500, latMin: 85, latMax: 130, msg: "Arithmetic Error: Float limit exceeded" },
    { strategy: "Directory traversal threat: ../../passwd", code: 500, latMin: 110, latMax: 180, msg: "Security Filter Failure Exception" },
    
    // Latency exhaustion/timeouts (408)
    { strategy: "Boundary timeout check: age (-1)", code: 408, latMin: 5000, latMax: 5000, msg: "Read Timeout Exceeded (5.0s limit)" },
    { strategy: "Boundary timeout check: age (-2147483648)", code: 408, latMin: 5000, latMax: 5000, msg: "Read Timeout Exceeded (5.0s limit)" }
  ];

  // 4. State variables
  let isFuzzing = false;
  let timerId = null;
  let totalReqs = 0;
  let failedReqs = 0;
  let latencies = [];
  let reqsPerSec = 0;
  const maxSimulatedReqs = 52; // Matching exact python fuzzer session output

  // DOM Elements
  const btnStart = document.getElementById("btn-start");
  const headerStatusText = document.getElementById("header-status-text");
  const headerStatusDot = document.getElementById("header-status-dot");
  
  const statTotal = document.getElementById("stat-total");
  const statRate = document.getElementById("stat-rate");
  const statFailed = document.getElementById("stat-failed");
  const statFailPct = document.getElementById("stat-fail-pct");
  const statLatency = document.getElementById("stat-latency");
  const statLatencyP95 = document.getElementById("stat-latency-p95");
  const statStatus = document.getElementById("stat-status");
  const statProgressBar = document.getElementById("stat-progress-bar");
  
  const targetUrlInput = document.getElementById("target-url");
  const requestMethodSelect = document.getElementById("request-method");
  const chartOverlay = document.getElementById("chart-overlay");
  const logsTableBody = document.getElementById("logs-table-body");
  const tableEmptyRow = document.getElementById("table-empty-row");
  const btnClearLogs = document.getElementById("btn-clear-logs");

  // Initialize Chart.js
  const ctx = document.getElementById("latency-chart").getContext("2d");
  
  // Custom Amber Gradients for line fill
  const chartGradient = ctx.createLinearGradient(0, 0, 0, 250);
  chartGradient.addColorStop(0, 'rgba(245, 158, 11, 0.25)');
  chartGradient.addColorStop(1, 'rgba(245, 158, 11, 0)');

  const latencyChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels: [],
      datasets: [{
        label: 'TTFB Latency (ms)',
        data: [],
        borderColor: '#f59e0b',
        borderWidth: 2,
        pointBackgroundColor: '#f59e0b',
        pointBorderColor: '#070709',
        pointHoverRadius: 6,
        fill: true,
        backgroundColor: chartGradient,
        tension: 0.35,
        segment: {
          borderColor: ctx => ctx.p1.raw > 500 ? '#f87171' : '#f59e0b' // Red highlight on timeouts
        }
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false }
      },
      scales: {
        x: {
          grid: { color: 'rgba(245, 158, 11, 0.03)' },
          ticks: { color: '#6b7280', font: { size: 9, family: 'Plus Jakarta Sans' } }
        },
        y: {
          grid: { color: 'rgba(245, 158, 11, 0.04)' },
          ticks: { color: '#6b7280', font: { size: 9, family: 'Plus Jakarta Sans' } },
          min: 0
        }
      }
    }
  });

  // Toggles fuzzer active state
  function startFuzzing() {
    isFuzzing = true;
    totalReqs = 0;
    failedReqs = 0;
    latencies = [];
    reqsPerSec = 0;
    
    // UI state change
    btnStart.innerHTML = `<i data-lucide="square" class="w-4 h-4 fill-zinc-950"></i><span>STOP FUZZING RUN</span>`;
    btnStart.classList.replace("gold-gradient-bg", "bg-red-500");
    btnStart.classList.replace("text-zinc-950", "text-white");
    lucide.createIcons();

    headerStatusText.textContent = "Engine Active";
    headerStatusDot.className = "w-2 h-2 rounded-full status-dot-active";
    statStatus.textContent = "ACTIVE";
    statStatus.className = "text-3xl font-bold font-title tracking-tight text-amber-500 animate-pulse";

    // Chart overlay transition
    chartOverlay.classList.add("opacity-0", "pointer-events-none");

    // Clear logs table
    logsTableBody.innerHTML = "";
    
    // Clear chart points
    latencyChart.data.labels = [];
    latencyChart.data.datasets[0].data = [];
    latencyChart.update();

    // Start interval
    const intervalMs = Math.max(50, Math.floor(2500 / concurrencySlider.value));
    
    timerId = setInterval(() => {
      if (totalReqs >= maxSimulatedReqs) {
        stopFuzzing(true); // Complete run
        return;
      }
      
      simulateSingleRequest();
    }, intervalMs);
  }

  function simulateSingleRequest() {
    totalReqs++;
    
    // Selection bias: pick randomly but ensure a representative ratio (roughly matching our python tests: 15 success, 26 client error, 7 server errors, 4 timeouts)
    let strategy;
    const rng = Math.random();
    if (rng < 0.28) {
      // Success (200)
      strategy = fuzzStrategies.filter(s => s.code === 200)[Math.floor(Math.random() * 2)];
    } else if (rng < 0.78) {
      // Client Errors (422 / 400)
      strategy = fuzzStrategies.filter(s => [400, 422].includes(s.code))[Math.floor(Math.random() * 8)];
    } else if (rng < 0.92) {
      // Server Errors (500)
      strategy = fuzzStrategies.filter(s => s.code === 500)[Math.floor(Math.random() * 3)];
    } else {
      // Timeouts (408)
      strategy = fuzzStrategies.filter(s => s.code === 408)[Math.floor(Math.random() * 2)];
    }

    const latency = Math.floor(Math.random() * (strategy.latMax - strategy.latMin + 1)) + strategy.latMin;
    latencies.push(latency);
    
    if (strategy.code >= 400) {
      failedReqs++;
    }

    // Update Stats Display
    statTotal.textContent = totalReqs;
    statFailed.textContent = failedReqs;
    
    const failPct = ((failedReqs / totalReqs) * 100).toFixed(1);
    statFailPct.textContent = `${failPct}%`;
    
    // Running throughput
    reqsPerSec = Math.floor(Math.random() * 15) + Math.floor(concurrencySlider.value * 0.8);
    statRate.textContent = `${reqsPerSec} req/s`;

    // Latency averages
    const avgLatency = (latencies.reduce((a, b) => a + b, 0) / latencies.length).toFixed(1);
    statLatency.textContent = `${avgLatency} ms`;

    // Percentile 95th
    const sortedLats = [...latencies].sort((a, b) => a - b);
    const p95Idx = Math.min(Math.ceil(sortedLats.length * 0.95) - 1, sortedLats.length - 1);
    const p95Val = sortedLats[p95Idx];
    statLatencyP95.textContent = `${p95Val.toFixed(1)} ms`;

    // Progress Bar
    const progressPct = (totalReqs / maxSimulatedReqs) * 100;
    statProgressBar.style.width = `${progressPct}%`;

    // Add entries to activity table
    const timestamp = new Date().toLocaleTimeString();
    const endpoint = targetUrlInput.value;
    const method = requestMethodSelect.value;
    
    let codeBadgeClass = "text-green-500 bg-green-500/10 border border-green-500/20";
    if (strategy.code === 422) codeBadgeClass = "text-yellow-500 bg-yellow-500/10 border border-yellow-500/20";
    if (strategy.code === 400) codeBadgeClass = "text-orange-400 bg-orange-400/10 border border-orange-400/20";
    if (strategy.code >= 500) codeBadgeClass = "text-red-500 bg-red-500/10 border border-red-500/20";
    if (strategy.code === 408) codeBadgeClass = "text-red-400 bg-red-400/10 border border-red-400/20 animate-pulse";

    const tableRow = document.createElement("tr");
    tableRow.className = "hover:bg-zinc-900/30 transition-colors";
    tableRow.innerHTML = `
      <td class="px-6 py-3.5 text-zinc-500">${timestamp}</td>
      <td class="px-6 py-3.5 font-medium text-gray-300">${endpoint}</td>
      <td class="px-6 py-3.5 text-amber-500 font-bold">${method}</td>
      <td class="px-6 py-3.5"><span class="px-2 py-0.5 rounded text-[10px] font-bold ${codeBadgeClass}">${strategy.code}</span></td>
      <td class="px-6 py-3.5 text-zinc-400 flex items-center justify-between">
        <span>${strategy.strategy}</span>
        ${strategy.msg ? `<span class="text-[9px] font-semibold tracking-wider text-red-500 uppercase">${strategy.msg}</span>` : ''}
      </td>
    `;
    
    // Insert at top
    logsTableBody.insertBefore(tableRow, logsTableBody.firstChild);

    // Keep list length within 12 entries for premium performance
    if (logsTableBody.children.length > 12) {
      logsTableBody.removeChild(logsTableBody.lastChild);
    }

    // Update Chart
    // Labels is simply the request index
    latencyChart.data.labels.push(`#${totalReqs}`);
    latencyChart.data.datasets[0].data.push(latency);
    
    // Shift chart items to keep a rolling 20 points
    if (latencyChart.data.labels.length > 20) {
      latencyChart.data.labels.shift();
      latencyChart.data.datasets[0].data.shift();
    }
    
    latencyChart.update('none'); // Update without full redraw animations to maintain performance
  }

  function stopFuzzing(completed = false) {
    isFuzzing = false;
    clearInterval(timerId);
    
    // Reset trigger button styling
    btnStart.innerHTML = `<i data-lucide="play" class="w-4 h-4 fill-zinc-950"></i><span>START FUZZING TEST</span>`;
    btnStart.className = "w-full py-4 rounded-xl gold-gradient-bg text-zinc-950 font-bold text-sm tracking-wider flex items-center justify-center space-x-2 shadow-lg shadow-amber-500/15 hover:shadow-amber-500/25 transition-all duration-300 transform active:scale-[0.98]";
    lucide.createIcons();

    if (completed) {
      headerStatusText.textContent = "Engine Standby (Scan Completed)";
      headerStatusDot.className = "w-2 h-2 rounded-full bg-amber-500 shadow-amber-500/50 shadow-sm";
      statStatus.textContent = "COMPLETE";
      statStatus.className = "text-3xl font-bold font-title tracking-tight text-green-400";
    } else {
      headerStatusText.textContent = "Engine Standby";
      headerStatusDot.className = "w-2 h-2 rounded-full status-dot-idle";
      statStatus.textContent = "STANDBY";
      statStatus.className = "text-3xl font-bold font-title tracking-tight text-zinc-500 uppercase";
    }
  }

  // Bind Start Button click
  btnStart.addEventListener("click", () => {
    if (isFuzzing) {
      stopFuzzing(false);
    } else {
      startFuzzing();
    }
  });

  // Bind Clear table button
  btnClearLogs.addEventListener("click", () => {
    logsTableBody.innerHTML = `
      <tr id="table-empty-row">
        <td colspan="5" class="px-6 py-12 text-center text-zinc-600 font-sans font-medium">
          <i data-lucide="inbox" class="w-8 h-8 mx-auto mb-2 text-zinc-700"></i>
          No requests dispatched yet. Initiate fuzzing above.
        </td>
      </tr>
    `;
    lucide.createIcons();
  });

});
