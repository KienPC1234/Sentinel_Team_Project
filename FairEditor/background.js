// FairEditor Background Service Worker
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "checkBias",
    title: "Kiểm tra định kiến giới với FairEditor",
    contexts: ["selection"]
  });
  console.log("FairEditor by ShieldCall installed.");
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === "checkBias") {
    chrome.tabs.sendMessage(tab.id, { 
      action: "analyzeText", 
      text: info.selectionText 
    });
  }
});

// Listener for messages from popup or content script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "getAnalysis") {
    analyzeText(request.text).then(sendResponse);
    return true; 
  } else if (request.action === "captureScreen") {
    chrome.tabs.captureVisibleTab(null, { format: "png" }, (dataUrl) => {
      sendResponse({ dataUrl });
    });
    return true;
  } else if (request.action === "sendChat") {
    sendChatToAI(request.text).then(sendResponse);
    return true;
  }
});

async function sendChatToAI(text) {
  const token = await getToken();
  try {
    const response = await fetch("https://cs.fptoj.com/api/ai_chat/chat/", {
      method: "POST",
      headers: { 
        "Content-Type": "application/json",
        "Authorization": `Token ${token}`
      },
      body: JSON.stringify({ message: text })
    });
    return await response.json();
  } catch (e) {
    return { error: "Không thể kết nối với SafeTalk AI" };
  }
}

async function getToken() {
  return new Promise((resolve) => {
    chrome.storage.local.get(["token"], (res) => {
      if (res.token) {
        resolve(res.token);
      } else {
        // Fallback: Try to get token from domain cookies
        chrome.cookies.get({ url: "https://cs.fptoj.com", name: "sessionid" }, (cookie) => {
          if (cookie) {
            resolve(cookie.value);
          } else {
            resolve(null); // Force login
          }
        });
      }
    });
  });
}

async function analyzeText(text) {
  const token = await getToken();
  try {
    const response = await fetch("https://cs.fptoj.com/api/ai_chat/faireditor/analyze/", {
      method: "POST",
      headers: { 
        "Content-Type": "application/json",
        "Authorization": `Token ${token}`
      },
      body: JSON.stringify({ text })
    });
    if (response.status === 401) return { error: "Vui lòng đăng nhập ShieldCall VN để sử dụng FairEditor." };
    return await response.json();
  } catch (e) {
    return { error: "Không thể kết nối với hệ thống ShieldCall AI (cs.fptoj.com)" };
  }
}
