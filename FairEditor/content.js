/* FairEditor Content Script */
console.log("FairEditor Content Script Active");

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "analyzeText") {
    showFairEditorOverlay(request.text);
  } else if (request.action === "toggleSafeTalk") {
    const bubble = document.getElementById("fe-safetalk-bubble");
    if (bubble) bubble.style.display = request.enabled ? "flex" : "none";
  }
});

chrome.storage.onChanged.addListener((changes) => {
  if (changes.safetalkEnabled) {
    const bubble = document.getElementById("fe-safetalk-bubble");
    if (bubble) bubble.style.display = changes.safetalkEnabled.newValue ? "flex" : "none";
  }
});

// Initialize Features
initFairEditorSuite();

function initFairEditorSuite() {
  createSafeTalkBubble();
  checkToxicZone();
  setupSmartHide();
}

function createSafeTalkBubble() {
  if (document.getElementById("fe-safetalk-bubble")) return;
  const bubble = document.createElement("div");
  bubble.id = "fe-safetalk-bubble";
  bubble.innerHTML = `
    <div class="fe-bubble-inner">
      <img src="${chrome.runtime.getURL("icons/icon128.png")}" width="32">
      <div class="fe-bubble-hint">SafeTalk AI Hub</div>
    </div>
    <div id="fe-safetalk-menu" class="fe-bubble-menu" style="display:none;">
      <div class="fe-menu-item" id="fe-btn-chat"><i class="bi bi-chat-heart"></i> Trò chuyện AI</div>
      <div class="fe-menu-item" id="fe-btn-ss"><i class="bi bi-camera"></i> Chụp bằng chứng</div>
      <div class="fe-menu-item" id="fe-btn-report"><i class="bi bi-flag"></i> Báo cáo vi phạm</div>
      <div class="fe-menu-item" id="fe-btn-sos"><i class="bi bi-telephone-outbound"></i> Liên hệ khẩn cấp</div>
    </div>
  `;
  document.body.appendChild(bubble);
  
  bubble.onclick = (e) => {
    e.stopPropagation();
    const menu = document.getElementById("fe-safetalk-menu");
    menu.style.display = menu.style.display === "none" ? "flex" : "none";
  };

  document.addEventListener("click", () => {
    const menu = document.getElementById("fe-safetalk-menu");
    if (menu) menu.style.display = "none";
  });

  document.getElementById("fe-btn-chat").onclick = (e) => { e.stopPropagation(); showSafeTalkUI(); };
  document.getElementById("fe-btn-ss").onclick = (e) => { e.stopPropagation(); handleScreenshot(); };
  document.getElementById("fe-btn-report").onclick = (e) => { e.stopPropagation(); handleReport(); };
  document.getElementById("fe-btn-sos").onclick = (e) => { e.stopPropagation(); showEmergencyContacts(); };

  // Sync initial state
  chrome.storage.local.get(['safetalkEnabled'], (res) => {
    bubble.style.display = res.safetalkEnabled === false ? "none" : "flex";
  });
}

async function handleScreenshot() {
  chrome.runtime.sendMessage({ action: "captureScreen" }, (response) => {
    if (response && response.dataUrl) {
      const link = document.createElement('a');
      link.href = response.dataUrl;
      link.download = `ShieldCall_Evidence_${new Date().getTime()}.png`;
      link.click();
      alert("Đã chụp bằng chứng màn hình. Hãy lưu giữ để đối soát khi cần thiết.");
    }
  });
}

function handleReport() {
  const url = window.location.href;
  const reason = prompt("Lý do báo cáo vi phạm (ví dụ: bạo lực mạng, lừa đảo):");
  if (reason) {
    alert(`Đã gửi báo cáo cho ShieldCall VN về URL: ${url}\nLý do: ${reason}`);
    // Future: API call to /api/core/report/
  }
}

function showEmergencyContacts() {
  const contacts = [
    "📞 111 - Tổng đài Quốc gia Bảo vệ Trẻ em",
    "📞 19001567 - Tư vấn tâm lý & Phụ nữ",
    "📞 113 - Cảnh sát (Trường hợp khẩn cấp)",
    "🏳️‍🌈 CSAGA - Tổ chức hỗ trợ phụ nữ & LGBTQ+"
  ];
  alert("DANH BẠ KHẨN CẤP:\n\n" + contacts.join("\n"));
}

function checkToxicZone() {
  const isCS = window.location.hostname === "cs.fptoj.com";
  if (isCS) {
    // Placeholder logic for toxic zone detection
    // In production, this would call an API or check a blackboard
    const toxicAreas = ["comments", "forum", "chat"];
    if (toxicAreas.some(area => window.location.pathname.includes(area))) {
      showToxicAlert();
    }
  }
}

function showToxicAlert() {
  const alert = document.createElement("div");
  alert.className = "fe-toxic-alert";
  alert.innerHTML = `
    <i class="bi bi-shield-lock-fill"></i>
    <span>Khu vực này có dấu hiệu bạo lực mạng. Hãy cẩn trọng!</span>
    <button onclick="this.parentElement.remove()">Đã hiểu</button>
  `;
  document.body.appendChild(alert);
}

function setupSmartHide() {
  // Logic to blur toxic-looking comments automatically
  const selectors = [".comment-content", ".post-text", ".chat-msg"];
  const toxicKeywords = ["ngu", "chết", "xấu", "mập", "béo"]; // Mock list
  
  document.querySelectorAll(selectors.join(",")).forEach(el => {
    if (toxicKeywords.some(kw => el.innerText.toLowerCase().includes(kw))) {
      el.classList.add("fe-smart-hide");
      el.onclick = () => el.classList.remove("fe-smart-hide");
      const label = document.createElement("div");
      label.className = "fe-blur-label";
      label.innerText = "Bình luận nhạy cảm - Nhấn để xem";
      el.appendChild(label);
    }
  });
}

function showFairEditorOverlay(text) {
  // Remove existing overlay if any
  const old = document.getElementById("faireditor-overlay");
  if (old) old.remove();

  const overlay = document.createElement("div");
  overlay.id = "faireditor-overlay";
  overlay.innerHTML = `
    <div class="fe-header">
      <div class="fe-header-left">
        <img src="${chrome.runtime.getURL("icons/icon48.png")}" width="16">
        <span>FairEditor by ShieldCall</span>
      </div>
      <div class="fe-header-actions">
        <button id="fe-toggle-h" title="Ẩn/Hiện Highlight"><i class="bi bi-eye"></i></button>
        <button id="fe-close">×</button>
      </div>
    </div>
    <div class="fe-body">
      <div id="fe-loader" class="fe-loading">
        <div class="fe-spinner"></div>
        <span>Đang phân tích thấu cảm...</span>
      </div>
      <div id="fe-result" style="display:none;">
        <div class="fe-alert-box">
          <i class="bi bi-exclamation-triangle-fill"></i>
          <span id="fe-explanation"></span>
        </div>
        <div class="fe-label">Bản chỉnh sửa đề xuất:</div>
        <div id="fe-suggestion" class="fe-suggestion-box" contenteditable="true"></div>
        <div class="fe-footer">
          <button id="fe-ignore" class="fe-btn-secondary">Bỏ qua</button>
          <button id="fe-apply" class="fe-btn-primary">Áp dụng</button>
        </div>
      </div>
    </div>
  `;
  document.body.appendChild(overlay);

  document.getElementById("fe-close").onclick = () => {
    removeHighlights();
    overlay.remove();
  };
  
  document.getElementById("fe-ignore").onclick = () => {
    removeHighlights();
    overlay.remove();
  };

  // Call background for analysis
  chrome.runtime.sendMessage({ action: "getAnalysis", text: text }, (response) => {
    const loader = document.getElementById("fe-loader");
    const result = document.getElementById("fe-result");
    loader.style.display = "none";
    
    if (response.error) {
       result.style.display = "block";
       document.getElementById("fe-explanation").innerText = response.error;
       return;
    }

    if (!response.biasDetected) {
       result.style.display = "block";
       document.getElementById("fe-explanation").innerText = "Không phát hiện định kiến giới. Văn bản của bạn rất ổn!";
       document.getElementById("fe-suggestion").innerText = text;
       return;
    }

    result.style.display = "block";
    document.getElementById("fe-explanation").innerText = response.explanation || "Phát hiện ngôn từ cần cải thiện.";
    document.getElementById("fe-suggestion").innerText = response.suggestedText || response.suggestion;
    
    if (response.highlights && response.highlights.length > 0) {
      applyHighlights(text, response.highlights, response.suggestedText);
    }

    document.getElementById("fe-apply").onclick = () => {
      const newText = document.getElementById("fe-suggestion").innerText;
      applyTextToActiveElement(newText);
      removeHighlights();
      overlay.remove();
    };
    
    document.getElementById("fe-toggle-h").onclick = () => {
      const h = document.querySelectorAll(".fe-highlight-span");
      h.forEach(el => el.classList.toggle("fe-hidden"));
    };
  });
}

function applyHighlights(text, highlights, suggestion) {
  const selection = window.getSelection();
  if (!selection.rangeCount) return;
  const range = selection.getRangeAt(0);
  
  const fragment = document.createDocumentFragment();
  let lastIndex = 0;
  
  highlights.sort((a, b) => a.start - b.start);
  
  highlights.forEach(h => {
    fragment.appendChild(document.createTextNode(text.substring(lastIndex, h.start)));
    
    const span = document.createElement("span");
    span.className = "fe-highlight-span";
    span.innerText = text.substring(h.start, h.end);
    
    const tooltip = document.createElement("span");
    tooltip.className = "fe-tooltip";
    tooltip.innerHTML = `
      <div class="fe-tooltip-content">
        <div class="fe-tooltip-header">
          <strong>Lăng kính Công bằng</strong>
          <button class="fe-tooltip-close">×</button>
        </div>
        <p>Từ này mang định kiến giới hoặc chưa bao trùm. Bạn có muốn đổi không?</p>
        <div class="fe-tooltip-footer">
          <button class="fe-tooltip-fix-btn">Sửa nhanh</button>
        </div>
      </div>
    `;
    
    tooltip.querySelector(".fe-tooltip-close").onclick = (e) => {
      e.stopPropagation();
      span.classList.add("fe-hidden");
    };

    tooltip.querySelector(".fe-tooltip-fix-btn").onclick = (e) => {
      e.stopPropagation();
      replaceSelectionWithText(suggestion);
      removeHighlights();
      const overlay = document.getElementById("faireditor-overlay");
      if (overlay) overlay.remove();
    };
    
    span.appendChild(tooltip);
    fragment.appendChild(span);
    lastIndex = h.end;
  });
  
  fragment.appendChild(document.createTextNode(text.substring(lastIndex)));
  
  range.deleteContents();
  range.insertNode(fragment);
}

function removeHighlights() {
  const spans = document.querySelectorAll(".fe-highlight-span");
  spans.forEach(span => {
    const parent = span.parentNode;
    if (parent) {
      parent.replaceChild(document.createTextNode(span.innerText), span);
      parent.normalize();
    }
  });
}

function setupSmartHide() {
  const selectors = [".comment-content", ".post-text", ".chat-msg", ".comment-body", ".reply-text"];
  const toxicKeywords = ["ngu", "chết", "xấu", "mập", "béo", "đồ hèn", "vô dụng"];
  
  document.querySelectorAll(selectors.join(",")).forEach(el => {
    const text = el.innerText.toLowerCase();
    if (toxicKeywords.some(kw => text.includes(kw))) {
      el.classList.add("fe-smart-hide");
      if (!el.querySelector(".fe-blur-label")) {
        const label = document.createElement("div");
        label.className = "fe-blur-label";
        label.innerText = "Nội dung nhạy cảm - Nhấn để xem";
        el.appendChild(label);
        el.onclick = (e) => {
          e.stopPropagation();
          el.classList.remove("fe-smart-hide");
          label.remove();
        };
      }
    }
  });
}

function autoNeutralizeJobSites() {
  const jobSelectors = [".job-title", ".job-description", ".description", "h1", "h2"];
  const map = {
    "nam lập trình viên": "chuyên gia lập trình",
    "nữ văn phòng": "nhân viên văn phòng",
    "việc nhẹ cho nữ": "công việc văn phòng phù hợp",
    "bản lĩnh đàn ông": "sự chuyên nghiệp",
    "anh hùng": "người tiên phong"
  };
  
  document.querySelectorAll(jobSelectors.join(",")).forEach(el => {
    let html = el.innerHTML;
    let changed = false;
    for (const [key, val] of Object.entries(map)) {
      const reg = new RegExp(key, "gi");
      if (reg.test(html)) {
        html = html.replace(reg, `<span class="fe-neutralized" title="Đã trung hòa bởi FairEditor">${val}</span>`);
        changed = true;
      }
    }
    if (changed) el.innerHTML = html;
  });
}

function replaceSelectionWithText(text) {
  const sel = window.getSelection();
  if (sel.rangeCount) {
    const range = sel.getRangeAt(0);
    range.deleteContents();
    range.insertNode(document.createTextNode(text));
  }
}

function showSafeTalkUI() {
  const existing = document.getElementById("fe-chat-container");
  if (existing) {
    existing.style.display = "flex";
    return;
  }

  const container = document.createElement("div");
  container.id = "fe-chat-container";
  container.className = "fe-chat-window";
  container.innerHTML = `
    <div class="fe-chat-header">
      <div class="flex items-center gap-2">
        <div class="w-8 h-8 rounded-full bg-accent flex items-center justify-center">
          <i class="bi bi-chat-heart text-dark text-lg"></i>
        </div>
        <div>
          <div class="text-sm font-black italic">SAFETALK AI</div>
          <div class="text-[10px] text-accent/80 font-bold uppercase tracking-widest">Trợ lý thấu cảm</div>
        </div>
      </div>
      <button id="fe-chat-close" class="text-white/40 hover:text-white transition-colors">×</button>
    </div>
    <div id="fe-chat-messages" class="fe-chat-messages">
      <div class="fe-msg fe-msg-bot">Chào bạn, tôi là SafeTalk. Tôi ở đây để lắng nghe và hỗ trợ bạn trong các tình huống nhạy cảm hoặc độc hại trên không gian mạng. Bạn đang cần tôi giúp gì không?</div>
    </div>
    <div class="fe-chat-input-area">
      <input type="text" id="fe-chat-input" placeholder="Nhập tin nhắn..." autocomplete="off">
      <button id="fe-chat-send"><i class="bi bi-send-fill"></i></button>
    </div>
  `;
  document.body.appendChild(container);

  document.getElementById("fe-chat-close").onclick = () => {
    container.style.display = "none";
  };

  const input = document.getElementById("fe-chat-input");
  const sendBtn = document.getElementById("fe-chat-send");

  const sendMessage = () => {
    const text = input.value.trim();
    if (!text) return;

    appendMessage("user", text);
    input.value = "";
    
    // Call background to proxy to backend
    chrome.runtime.sendMessage({ action: "sendChat", text: text }, (response) => {
      if (response && response.reply) {
        appendMessage("bot", response.reply);
      } else {
        appendMessage("bot", "Xin lỗi, tôi gặp chút sự cố khi kết nối. Hãy thử lại sau nhé!");
      }
    });
  };

  sendBtn.onclick = sendMessage;
  input.onkeypress = (e) => { if (e.key === "Enter") sendMessage(); };
}

function appendMessage(role, text) {
  const chatMsgs = document.getElementById("fe-chat-messages");
  const msg = document.createElement("div");
  msg.className = `fe-msg fe-msg-${role}`;
  msg.innerText = text;
  chatMsgs.appendChild(msg);
  chatMsgs.scrollTop = chatMsgs.scrollHeight;
}

// Re-run setup on scroll or dynamic content
let timeout = null;
window.addEventListener("scroll", () => {
  clearTimeout(timeout);
  timeout = setTimeout(() => {
    setupSmartHide();
    autoNeutralizeJobSites();
  }, 500);
});
