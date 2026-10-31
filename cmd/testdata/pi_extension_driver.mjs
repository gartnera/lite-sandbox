// Drives the rendered pi extension (path in argv[2]) against a stand-in for
// pi's ExtensionAPI, for TestPiExtension. It reads the calls to make as JSON
// from argv[3] and prints what the extension did as JSON.
//
// Each call is {toolName, input, hasUI, confirm}; its result is the value the
// tool_call handler returned (null when it let the call run), or {error} when
// it threw, which pi treats as a blocked call.
const { default: extension } = await import(process.argv[2]);
const calls = JSON.parse(process.argv[3]);

const handlers = {};
const servers = {};
const pi = {
	registerMcpServer(name, config) {
		servers[name] = config;
	},
	on(event, handler) {
		handlers[event] = handler;
	},
};
extension(pi);

const results = [];
const confirms = [];
for (const call of calls) {
	const ctx = {
		cwd: process.cwd(),
		hasUI: call.hasUI,
		signal: undefined,
		ui: {
			confirm: async (title, message) => {
				confirms.push({ title, message });
				return call.confirm;
			},
		},
	};
	try {
		const result = await handlers.tool_call({ type: "tool_call", toolCallId: "c1", toolName: call.toolName, input: call.input }, ctx);
		results.push(result ?? null);
	} catch (err) {
		results.push({ error: String(err?.message ?? err) });
	}
}

const promptEvent = { systemPromptOptions: { sections: {} } };
if (handlers.before_agent_start) await handlers.before_agent_start(promptEvent, {});

console.log(JSON.stringify({ servers, results, confirms, sections: promptEvent.systemPromptOptions.sections, events: Object.keys(handlers) }));
