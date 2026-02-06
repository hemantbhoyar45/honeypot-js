const express = require('express');
const fs = require('fs');
const path = require('path');
const axios = require('axios');
const crypto = require('crypto');

const app = express();
app.use(express.json());

// =========================================================
// ENV + CONSTANTS
// =========================================================
const CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult";
const SECRET_API_KEY = "team_top_250_secret" ;

const MIN_TURNS_BEFORE_FINAL = 6;
const JSON_FILE = path.join(__dirname, "honeypot_output.json");

const FINALIZED_SESSIONS = new Set();

// =========================================================
// JSON LOGGER (FILE + CONSOLE)
// =========================================================
function log_json(data) {
	console.log(JSON.stringify(data, null, 2));
	try {
		if (!fs.existsSync(JSON_FILE)) {
			fs.writeFileSync(JSON_FILE, JSON.stringify([]), 'utf-8');
		}
		const existing = JSON.parse(fs.readFileSync(JSON_FILE, 'utf-8'));
		existing.push(data);
		fs.writeFileSync(JSON_FILE, JSON.stringify(existing, null, 2), 'utf-8');
	} catch (e) {
		console.error("JSON LOG ERROR:", e.toString());
	}
}

// =========================================================
// SANITIZATION
// =========================================================
function sanitize(text) {
	if (!text) return "";
	return text
		.normalize("NFKD")
		.replace(/[\x00-\x1F\x7F]/g, "")
		.trim();
}

// =========================================================
// HONEYPOT AGENT DATA
// =========================================================
const ZOMBIE_INTROS = [
	"Hello sir,", "Excuse me,", "One second please,", "Listen,", "I am confused,"
];

const ZOMBIE_REPLIES = {
	bank: [
		"Why will my account be blocked?",
		"Which bank are you talking about?",
		"I just received pension yesterday."
	],
	upi: [
		"I don't know my UPI ID.",
		"Can I send 1 rupee to check?",
		"Do I share this with anyone?"
	],
	link: [
		"The link is not opening.",
		"Chrome says unsafe website.",
		"Is this government site?"
	],
	otp: [
		"My son told me not to share OTP.",
		"The message disappeared.",
		"Is OTP required?"
	],
	threat: [
		"Please don't block my account.",
		"Will police really come?",
		"I am very scared."
	],
	generic: [
		"What should I do now?",
		"Please explain slowly.",
		"I don't understand technology."
	]
};

const ZOMBIE_CLOSERS = [
	"Please reply.", "Are you there?", "Waiting for response."
];

// =========================================================
// RESPONSE ENGINE
// =========================================================
function agent_reply(text) {
	const t = text.toLowerCase();
	let cat = "generic";

	if (["bank", "account", "ifsc"].some(x => t.includes(x))) cat = "bank";
	else if (["upi", "gpay", "paytm", "phonepe"].some(x => t.includes(x))) cat = "upi";
	else if (["http", "link", "apk", "url"].some(x => t.includes(x))) cat = "link";
	else if (["otp", "pin", "code"].some(x => t.includes(x))) cat = "otp";
	else if (["block", "police", "suspend"].some(x => t.includes(x))) cat = "threat";

	const pick = arr => arr[Math.floor(Math.random() * arr.length)];

	return sanitize(
		`${pick(ZOMBIE_INTROS)} ${pick(ZOMBIE_REPLIES[cat])} ${pick(ZOMBIE_CLOSERS)}`
	);
}

// =========================================================
// INTELLIGENCE EXTRACTION
// =========================================================
function extract_intelligence(messages) {
	const blob = sanitize(messages.join(" "));
	return {
		bankAccounts: [...new Set(blob.match(/\b\d{12}\b/g) || [])],
		upiIds: [...new Set(blob.match(/[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}/g) || [])],
		phishingLinks: [...new Set(blob.match(/https?:\/\/\S+|www\.\S+/g) || [])],
		phoneNumbers: [...new Set(blob.match(/(?:\+91[\-\s]?)?[6-9]\d{9}/g) || [])],
		suspiciousKeywords: [...new Set(blob.match(/\b(urgent|verify|blocked|suspend|kyc|police|otp)\b/gi) || [])]
	};
}

// =========================================================
// HEALTH CHECK
// =========================================================
app.get('/', (req, res) => {
	const response = {
		status: "Agentic Honeypot Running",
		platform: "Render",
		endpoint: "/honey-pote"
	};
	log_json({ event: "health_check", response });
	res.json(response);
});

// =========================================================
// HONEYPOT API
// =========================================================
app.post('/honey-pote', (req, res) => {
	const payload = req.body;

	const session_id = sanitize(payload.sessionId);
	const incoming = sanitize(payload.message?.text || "");

	const history = (payload.conversationHistory || [])
		.map(m => sanitize(m.text));
	history.push(incoming);

	const intel = extract_intelligence(history);

	const scam_detected = Boolean(
		intel.upiIds.length ||
		intel.phishingLinks.length ||
		intel.phoneNumbers.length ||
		intel.suspiciousKeywords.length
	);

	const reply = agent_reply(incoming);

	log_json({
		event: "incoming_message",
		sessionId: session_id,
		message: incoming,
		turns: history.length
	});

	if (
		scam_detected &&
		history.length >= MIN_TURNS_BEFORE_FINAL &&
		!FINALIZED_SESSIONS.has(session_id)
	) {
		const final_payload = {
			sessionId: session_id,
			scamDetected: true,
			totalMessagesExchanged: history.length,
			extractedIntelligence: intel,
			agentNotes: "Scammer used urgency, OTP request and account blocking threats."
		};

		log_json({ event: "FINAL_RESULT", data: final_payload });
		send_final_callback(final_payload);
		FINALIZED_SESSIONS.add(session_id);
	}

	res.json({
		status: "success",
		reply
	});
});

// =========================================================
// FINAL CALLBACK
// =========================================================
function send_final_callback(payload) {
	axios.post(CALLBACK_URL, payload, {
		headers: {
			'Content-Type': 'application/json',
			'x-api-key': SECRET_API_KEY
		},
		timeout: 5000
	})
	.then(() => log_json({ event: "final_callback_sent", sessionId: payload.sessionId }))
	.catch(e => log_json({ event: "callback_error", error: e.toString() }));
}

// =========================================================
// SERVER START
// =========================================================
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
	console.log(`🔥 Agentic Scam Honeypot running on port ${PORT}`);
});
