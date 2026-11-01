const assistantForm = document.getElementById("assistantForm");
const assistantPrompt = document.getElementById("assistantPrompt");
const assistantMessages = document.getElementById("assistantMessages");
const assistantError = document.getElementById("assistantError");
const csrfToken = document.querySelector('meta[name="csrf-token"]').content;

function appendMessage(role, text) {
  const message = document.createElement("article");
  message.className = `assistant-message assistant-message-${role}`;
  message.textContent = text;
  assistantMessages.append(message);
  assistantMessages.scrollTop = assistantMessages.scrollHeight;
}

assistantForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const message = assistantPrompt.value.trim();
  if (!message) return;

  assistantError.hidden = true;
  assistantError.textContent = "";
  const submitButton = assistantForm.querySelector('button[type="submit"]');
  submitButton.disabled = true;
  appendMessage("user", message);

  try {
    const response = await fetch("/api/assistant/chat", {
      method: "POST",
      credentials: "same-origin",
      headers: {
        "Content-Type": "application/json",
        "X-CSRFToken": csrfToken,
      },
      body: JSON.stringify({ message }),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || "The assistant request failed.");
    appendMessage("assistant", result.answer);
    assistantPrompt.value = "";
  } catch (error) {
    assistantError.textContent = error.message || "The assistant request failed.";
    assistantError.hidden = false;
  } finally {
    submitButton.disabled = false;
    assistantPrompt.focus();
  }
});
