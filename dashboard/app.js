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
    switchPage(navSettings, pageSettings, "Engine Config");
  });

  // Concurrency slider dynamic indicator
  const concurrencySlider = document.getElementById("concurrency-slider");
  const concurrencyDisplay = document.getElementById("concurrency-display");
  
  concurrencySlider.addEventListener("input", (e) => {
    concurrencyDisplay.textContent = `${e.target.value} threads`;
  });

  // Simulated Fuzz Strategies list (matching Python results)
  const fuzzStrategies = [
    // Malformed JSON (400)
    { strategy: "Malformed JSON: trailing comma", code: 400, latMin: 12, latMax: 25, cat: "malformed", payload: '{"username": "alice", "age": 30,}' },
    { strategy: "Malformed JSON: missing brace", code: 400, latMin: 10, latMax: 18, cat: "malformed", payload: '{"username": "alice", "age": 30' },
    { strategy: "Malformed JSON: missing separator", code: 400, latMin: 15, latMax: 22, cat: "malformed", payload: '{"username": "alice" "age": 30}' },
    { strategy: "Malformed JSON: extra junk bytes", code: 400, latMin: 18, latMax: 30, cat: "malformed", payload: '{"username": "alice", "age": 30}extra_junk' },
    
    // Standard baseline success (200)
    { strategy: "Baseline validation check", code: 200, latMin: 35, latMax: 50, cat: "success", payload: { username: "alice", age: 30, is_active: true } },
    { strategy: "Empty elements fallback validation", code: 200, latMin: 32, latMax: 45, cat: "success", payload: {} },
    
    // Type Fuzzing mismatch (422)
    { strategy: "Type swap: username -> integer", code: 422, latMin: 22, latMax: 40, cat: "types", payload: { username: 12345, age: 30, is_active: true } },
    { strategy: "Type swap: age -> boolean", code: 422, latMin: 20, latMax: 38, cat: "types", payload: { username: "alice", age: true, is_active: true } },
    { strategy: "Type swap: age -> list", code: 422, latMin: 25, latMax: 42, cat: "types", payload: { username: "alice", age: [], is_active: true } },
    { strategy: "Type swap: is_active -> string", code: 422, latMin: 21, latMax: 35, cat: "types", payload: { username: "alice", age: 30, is_active: "string_type_swap" } },
    
    // Boundary and internal overflows (500)
    { strategy: "Boundary overflow: username (>5000 chars)", code: 500, latMin: 90, latMax: 140, cat: "overflow", msg: "Internal Database Column Overflow", payload: { username: "A" * 6000, age: 30, is_active: true } },
    { strategy: "Arithmetic overflow: age (1.79e308)", code: 500, latMin: 85, latMax: 130, cat: "overflow", msg: "Arithmetic Error: Float limit exceeded", payload: { username: "alice", age: 1.79e308, is_active: true } },
    { strategy: "Directory traversal threat: ../../passwd", code: 500, latMin: 110, latMax: 180, cat: "overflow", msg: "Security Filter Failure Exception", payload: { username: "../../etc/passwd", age: 30, is_active: true } },
    
    // Latency exhaustion/timeouts (408)
    { strategy: "Boundary timeout check: age (-1)", code: 408, latMin: 5000, latMax: 5000, cat: "timeouts", msg: "Read Timeout Exceeded (5.0s limit)", payload: { username: "alice", age: -1, is_active: true } },
    { strategy: "Boundary timeout check: age (-2147483648)", code: 408, latMin: 5000, latMax: 5000, cat: "timeouts", msg: "Read Timeout Exceeded (5.0s limit)", payload: { username: "alice", age: -2147483648, is_active: true } }
  ];

  // In-memory persistent database of current session requests (for filtering/diffing/exporting)
  let fuzzedRequests = [];
  let lastSuccessfulPayload = { username: "alice", age: 30, is_active: true }; // Default baseline

  // State variables
  let isFuzzing = false;
  let timerId = null;
  let totalReqs = 0;
  let failedReqs = 0;
  let latencies = [];
  let reqsPerSec = 0;
  const maxSimulatedReqs = 52;

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
  
  // Data Intelligence, Summary, Export DOM triggers
  const filterLogType = document.getElementById("filter-log-type");
  const btnExportCsv = document.getElementById("btn-export-csv");
  
  const btnReportSummary = document.getElementById("btn-report-summary");
  const reportSummaryModal = document.getElementById("report-summary-modal");
  const btnCloseReport = document.getElementById("btn-close-report");
  const btnReportDownload = document.getElementById("btn-report-download");
  
  const reportTotalReqs = document.getElementById("report-total-reqs");
  const reportSuccessRate = document.getElementById("report-success-rate");
  const reportVulnCount = document.getElementById("report-vuln-count");
  
  const reportCatMalformed = document.getElementById("report-cat-malformed");
  const reportCatTypes = document.getElementById("report-cat-types");
  const reportCatOverflow = document.getElementById("report-cat-overflow");
  const reportCatTimeouts = document.getElementById("report-cat-timeouts");

  // Diff Panel DOM Elements
  const payloadDiffPanel = document.getElementById("payload-diff-panel");
  const btnCloseDiff = document.getElementById("btn-close-diff");
  const btnCloseDiffBottom = document.getElementById("btn-close-diff-bottom");
  
  const diffMetaMethod = document.getElementById("diff-meta-method");
  const diffMetaEndpoint = document.getElementById("diff-meta-endpoint");
  const diffMetaStrategy = document.getElementById("diff-meta-strategy");
  const diffMetaCode = document.getElementById("diff-meta-code");
  
  const diffBaselineJson = document.getElementById("diff-baseline-json");
  const diffFuzzedJson = document.getElementById("diff-fuzzed-json");

  // Performance-Optimized Chart.js Configuration (Bypasses rendering bottlenecks)
  const ctx = document.getElementById("latency-chart").getContext("2d");
  const chartGradient = ctx.createLinearGradient(0, 0, 0, 250);
  chartGradient.addColorStop(0, 'rgba(245, 158, 11, 0.2)');
  chartGradient.addColorStop(1, 'rgba(245, 158, 11, 0)');

  const latencyChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels: [],
      datasets: [{
        data: [],
        borderColor: '#f59e0b',
        borderWidth: 1.5,
        pointBackgroundColor: '#f59e0b',
        pointBorderColor: '#070709',
        pointRadius: 2,
        pointHoverRadius: 5,
        fill: true,
        backgroundColor: chartGradient,
        tension: 0.2, // Straighter tension curves speed up CPU calculations
        spanGaps: true
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: false,      // CRITICAL: Disables heavy animation redraw loops entirely
      parsing: false,        // CRITICAL: Bypasses inner data structures parsing
      normalized: true,      // CRITICAL: Assumes pre-sorted values on x-axis
      plugins: {
        legend: { display: false },
        tooltip: { enabled: true }
      },
      hover: {
        mode: 'nearest',
        intersect: true
      },
      scales: {
        x: {
          grid: { display: false }, // Avoid grid calculation reflows
          ticks: { color: '#4b5563', font: { size: 8, family: 'Plus Jakarta Sans' } }
        },
        y: {
          grid: { color: 'rgba(245, 158, 11, 0.02)' },
          ticks: { color: '#4b5563', font: { size: 8, family: 'Plus Jakarta Sans' } },
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
    fuzzedRequests = [];
    
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
    latencyChart.update('none'); // Update without redraw animations

    // Start interval
    const intervalMs = Math.max(50, Math.floor(2500 / concurrencySlider.value));
    
    timerId = setInterval(() => {
      if (totalReqs >= maxSimulatedReqs) {
        stopFuzzing(true);
        return;
      }
      simulateSingleRequest();
    }, intervalMs);
  }

  function simulateSingleRequest() {
    totalReqs++;
    
    // Pick request using representative ratios
    let strategy;
    const rng = Math.random();
    if (rng < 0.28) {
      strategy = fuzzStrategies.filter(s => s.code === 200)[Math.floor(Math.random() * 2)];
    } else if (rng < 0.78) {
      strategy = fuzzStrategies.filter(s => [400, 422].includes(s.code))[Math.floor(Math.random() * 8)];
    } else if (rng < 0.92) {
      strategy = fuzzStrategies.filter(s => s.code === 500)[Math.floor(Math.random() * 3)];
    } else {
      strategy = fuzzStrategies.filter(s => s.code === 408)[Math.floor(Math.random() * 2)];
    }

    const latency = Math.floor(Math.random() * (strategy.latMax - strategy.latMin + 1)) + strategy.latMin;
    latencies.push(latency);
    
    if (strategy.code >= 400) {
      failedReqs++;
    }

    // Keep track of the latest successful payload to serve as baseline
    if (strategy.code === 200 && Object.keys(strategy.payload).length > 0) {
      lastSuccessfulPayload = strategy.payload;
    }

    // Save record persistently in memory
    const requestRecord = {
      id: `PAYLOAD_IDX_${totalReqs}`,
      timestamp: new Date().toLocaleTimeString(),
      endpoint: targetUrlInput.value,
      method: requestMethodSelect.value,
      code: strategy.code,
      strategy: strategy.strategy,
      category: strategy.cat,
      latency: latency,
      msg: strategy.msg || "",
      payload: strategy.payload
    };
    fuzzedRequests.push(requestRecord);

    // Update Stats Display
    statTotal.textContent = totalReqs;
    statFailed.textContent = failedReqs;
    
    const failPct = ((failedReqs / totalReqs) * 100).toFixed(1);
    statFailPct.textContent = `${failPct}%`;
    
    reqsPerSec = Math.floor(Math.random() * 10) + Math.floor(concurrencySlider.value * 0.8);
    statRate.textContent = `${reqsPerSec} req/s`;

    const avgLatency = (latencies.reduce((a, b) => a + b, 0) / latencies.length).toFixed(1);
    statLatency.textContent = `${avgLatency} ms`;

    const sortedLats = [...latencies].sort((a, b) => a - b);
    const p95Idx = Math.min(Math.ceil(sortedLats.length * 0.95) - 1, sortedLats.length - 1);
    const p95Val = sortedLats[p95Idx];
    statLatencyP95.textContent = `${p95Val.toFixed(1)} ms`;

    const progressPct = (totalReqs / maxSimulatedReqs) * 100;
    statProgressBar.style.width = `${progressPct}%`;

    // Only render to DOM if log fits current view filter
    const activeFilter = filterLogType.value;
    const isInteresting = [400, 403, 408, 429, 500].includes(strategy.code);
    
    if (activeFilter === "all" || (activeFilter === "interesting" && isInteresting)) {
      renderRow(requestRecord);
    }

    // Update Chart dynamically
    latencyChart.data.labels.push(`#${totalReqs}`);
    latencyChart.data.datasets[0].data.push(latency);
    
    if (latencyChart.data.labels.length > 20) {
      latencyChart.data.labels.shift();
      latencyChart.data.datasets[0].data.shift();
    }
    
    // Performance optimization: updates chart instantly without animating grids
    latencyChart.update('none');
  }

  function renderRow(record) {
    let codeBadgeClass = "text-green-500 bg-green-500/10 border border-green-500/20";
    if (record.code === 422) codeBadgeClass = "text-yellow-500 bg-yellow-500/10 border border-yellow-500/20";
    if (record.code === 400) codeBadgeClass = "text-orange-400 bg-orange-400/10 border border-orange-400/20";
    if (record.code >= 500) codeBadgeClass = "text-red-500 bg-red-500/10 border border-red-500/20";
    if (record.code === 408) codeBadgeClass = "text-red-400 bg-red-400/10 border border-red-400/20 animate-pulse";

    const tableRow = document.createElement("tr");
    tableRow.className = "hover:bg-zinc-900/30 transition-colors duration-100";
    tableRow.setAttribute("data-request-id", record.id);
    
    tableRow.innerHTML = `
      <td class="px-6 py-3.5 text-zinc-500">${record.timestamp}</td>
      <td class="px-6 py-3.5 font-medium text-gray-300 font-mono text-[11px]">${record.endpoint}</td>
      <td class="px-6 py-3.5 text-amber-500 font-bold">${record.method}</td>
      <td class="px-6 py-3.5"><span class="px-2 py-0.5 rounded text-[10px] font-bold ${codeBadgeClass}">${record.code}</span></td>
      <td class="px-6 py-3.5 text-zinc-400 flex items-center justify-between">
        <span>${record.strategy}</span>
        ${record.msg ? `<span class="text-[9px] font-semibold tracking-wider text-red-500 uppercase">${record.msg}</span>` : ''}
      </td>
    `;
    
    // Bind click listener for diffing drawer directly to optimized row injection
    tableRow.addEventListener("click", () => openDiffDrawer(record));

    logsTableBody.insertBefore(tableRow, logsTableBody.firstChild);

    // Remove old rows to stay extremely high-performance (limit to latest 30)
    if (logsTableBody.children.length > 30) {
      logsTableBody.removeChild(logsTableBody.lastChild);
    }
  }

  // 5. Data Intelligence: Dropdown Filter rendering
  filterLogType.addEventListener("change", (e) => {
    const selected = e.target.value;
    logsTableBody.innerHTML = "";
    
    const filtered = fuzzedRequests.filter(record => {
      if (selected === "all") return true;
      return [400, 403, 408, 429, 500].includes(record.code);
    });

    if (filtered.length === 0) {
      logsTableBody.innerHTML = `
        <tr id="table-empty-row">
          <td colspan="5" class="px-6 py-12 text-center text-zinc-600 font-sans font-medium">
            <i data-lucide="inbox" class="w-8 h-8 mx-auto mb-2 text-zinc-700"></i>
            No records match the current view filter.
          </td>
        </tr>
      `;
      lucide.createIcons();
    } else {
      // Render latest 30 matching logs
      const itemsToRender = filtered.slice(-30).reverse();
      itemsToRender.forEach(record => renderRow(record));
    }
  });

  // 6. Payload Diffing Side-Panel Drawer
  function highlightDiff(baseline, fuzzed) {
    if (typeof fuzzed === "string") {
      // For malformed raw strings, just highlight the whole text
      return `<span class="bg-red-950/80 text-red-400 font-bold p-1 rounded border border-red-900/40">${fuzzed}</span>`;
    }
    
    // If it's a dict, construct highlighted diff string
    let resultLines = [];
    const keys = Object.keys(fuzzed);
    
    resultLines.push("{");
    keys.forEach((key, index) => {
      const val = fuzzed[key];
      const baselineVal = baseline[key];
      const isDiff = baselineVal === undefined || JSON.stringify(val) !== JSON.stringify(baselineVal);
      
      const lineStr = `  "${key}": ${JSON.stringify(val)}`;
      const comma = index < keys.length - 1 ? "," : "";
      
      if (isDiff) {
        // Highlight line
        resultLines.push(`<span class="bg-red-950/60 text-red-400 font-bold px-2 py-0.5 rounded border border-red-900/30 inline-block w-full">${lineStr}${comma}</span>`);
      } else {
        resultLines.push(`${lineStr}${comma}`);
      }
    });
    resultLines.push("}");
    return resultLines.join("\n");
  }

  function openDiffDrawer(record) {
    diffMetaMethod.textContent = record.method;
    diffMetaEndpoint.textContent = record.endpoint;
    diffMetaStrategy.textContent = record.strategy;
    diffMetaCode.textContent = record.code;
    
    // Dynamic badges class
    let badgeClass = "px-2 py-0.5 rounded text-[10px] font-bold border ";
    if (record.code === 200) badgeClass += "text-green-500 bg-green-500/10 border-green-500/20";
    else if (record.code === 422) badgeClass += "text-yellow-500 bg-yellow-500/10 border-yellow-500/20";
    else if (record.code === 400) badgeClass += "text-orange-400 bg-orange-400/10 border-orange-400/20";
    else badgeClass += "text-red-500 bg-red-500/10 border-red-500/20";
    diffMetaCode.className = badgeClass;

    // Render baseline
    diffBaselineJson.innerHTML = JSON.stringify(lastSuccessfulPayload, null, 2);
    
    // Highlight differences in the fuzzed payload
    diffFuzzedJson.innerHTML = highlightDiff(lastSuccessfulPayload, record.payload);

    // Slide panel in (Hardware-accelerated class swap)
    payloadDiffPanel.classList.add("drawer-open");
  }

  function closeDiffDrawer() {
    payloadDiffPanel.classList.remove("drawer-open");
  }

  btnCloseDiff.addEventListener("click", closeDiffDrawer);
  btnCloseDiffBottom.addEventListener("click", closeDiffDrawer);

  // 7. Interactive Stats Modal
  btnReportSummary.addEventListener("click", () => {
    // Fill stats fields
    reportTotalReqs.textContent = totalReqs;
    
    const rate = totalReqs ? (((totalReqs - failedReqs) / totalReqs) * 100).toFixed(1) : "0.0";
    reportSuccessRate.textContent = `${rate}%`;
    reportVulnCount.textContent = failedReqs;

    // Categorized quantities
    const malformed = fuzzedRequests.filter(r => r.category === "malformed").length;
    const types = fuzzedRequests.filter(r => r.category === "types").length;
    const overflow = fuzzedRequests.filter(r => r.category === "overflow").length;
    const timeouts = fuzzedRequests.filter(r => r.category === "timeouts").length;

    reportCatMalformed.textContent = malformed;
    reportCatTypes.textContent = types;
    reportCatOverflow.textContent = overflow;
    reportCatTimeouts.textContent = timeouts;

    // Show modal cleanly
    reportSummaryModal.classList.remove("hidden");
    setTimeout(() => {
      reportSummaryModal.classList.add("modal-show");
    }, 10);
  });

  function closeReportModal() {
    reportSummaryModal.classList.remove("modal-show");
    setTimeout(() => {
      reportSummaryModal.classList.add("hidden");
    }, 200);
  }

  btnCloseReport.addEventListener("click", closeReportModal);

  // Close modals when clicking overlay
  reportSummaryModal.addEventListener("click", (e) => {
    if (e.target === reportSummaryModal) closeReportModal();
  });

  // 8. Export Functionality using PapaParse
  function handleCsvExport(dataToExport) {
    if (dataToExport.length === 0) {
      alert("No logs available to export.");
      return;
    }

    // Map logs to simple structured format
    const formattedData = dataToExport.map(record => ({
      Timestamp: record.timestamp,
      Endpoint: record.endpoint,
      Method: record.method,
      ResponseCode: record.code,
      FuzzStrategy: record.strategy,
      Payload: typeof record.payload === "object" ? JSON.stringify(record.payload) : record.payload
    }));

    // PapaParse Unparse
    const csvContent = Papa.unparse(formattedData);
    
    // Trigger local browser download
    const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.setAttribute("href", url);
    
    const filterState = filterLogType.value === "all" ? "all" : "anomalies";
    link.setAttribute("download", `fuzzshield_report_${filterState}_${Date.now()}.csv`);
    link.style.visibility = "hidden";
    
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  }

  btnExportCsv.addEventListener("click", () => {
    const selected = filterLogType.value;
    const dataset = fuzzedRequests.filter(record => {
      if (selected === "all") return true;
      return [400, 403, 408, 429, 500].includes(record.code);
    });
    handleCsvExport(dataset);
  });

  btnReportDownload.addEventListener("click", () => {
    handleCsvExport(fuzzedRequests);
  });

  function stopFuzzing(completed = false) {
    isFuzzing = false;
    clearInterval(timerId);
    
    btnStart.innerHTML = `<i data-lucide="play" class="w-4 h-4 fill-zinc-950"></i><span>START FUZZING TEST</span>`;
    btnStart.className = "w-full py-4 rounded-xl gold-gradient-bg text-zinc-950 font-bold text-sm tracking-wider flex items-center justify-center space-x-2 shadow-lg shadow-amber-500/15 hover:shadow-amber-500/25 transition-all duration-300 transform active:scale-[0.98]";
    lucide.createIcons();

    if (completed) {
      headerStatusText.textContent = "Engine Standby (Scan Completed)";
      headerStatusDot.className = "w-2 h-2 rounded-full bg-amber-500 shadow-amber-500/50 shadow-sm";
      statStatus.textContent = "COMPLETE";
      statStatus.className = "text-3xl font-bold font-title tracking-tight text-green-400";
      
      // Auto trigger report summary modal on completion
      setTimeout(() => {
        btnReportSummary.click();
      }, 500);
    } else {
      headerStatusText.textContent = "Engine Standby";
      headerStatusDot.className = "w-2 h-2 rounded-full status-dot-idle";
      statStatus.textContent = "STANDBY";
      statStatus.className = "text-3xl font-bold font-title tracking-tight text-zinc-500 uppercase";
    }
  }

  btnStart.addEventListener("click", () => {
    if (isFuzzing) {
      stopFuzzing(false);
    } else {
      startFuzzing();
    }
  });

  btnClearLogs.addEventListener("click", () => {
    logsTableBody.innerHTML = `
      <tr id="table-empty-row">
        <td colspan="5" class="px-6 py-12 text-center text-zinc-600 font-sans font-medium">
          <i data-lucide="inbox" class="w-8 h-8 mx-auto mb-2 text-zinc-700"></i>
          No requests dispatched yet. Initiate fuzzing above.
        </td>
      </tr>
    `;
    fuzzedRequests = [];
    lucide.createIcons();
  });

});
