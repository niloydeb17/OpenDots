import type { AnyTextAdapter } from '@tanstack/ai';

// Some Responses-compatible gateways omit function calls from the terminal
// response.output, even though their complete call lifecycle was streamed.
// The adapter then reports stop and TanStack never executes those calls.
export function restoreResponseToolFinish<T extends AnyTextAdapter>(
  adapter: T,
): T {
  const stream = adapter.chatStream.bind(adapter);
  adapter.chatStream = async function* (options) {
    const calls = new Map<string, { args: string; complete: boolean }>();
    const serverTools = new Set(
      options.tools?.filter((tool) => tool.execute).map((tool) => tool.name),
    );
    let failed = false;
    for await (const chunk of stream(options)) {
      if (chunk.type === 'RUN_ERROR') failed = true;
      if (chunk.type === 'TOOL_CALL_START' && serverTools.has(chunk.toolName))
        calls.set(chunk.toolCallId, { args: '', complete: false });
      const call =
        'toolCallId' in chunk && chunk.toolCallId
          ? calls.get(chunk.toolCallId)
          : undefined;
      if (call && chunk.type === 'TOOL_CALL_ARGS') call.args += chunk.delta;
      if (call && chunk.type === 'TOOL_CALL_END') {
        try {
          JSON.parse(call.args);
          call.complete = true;
        } catch {
          // Leave incomplete/invalid calls to the existing error handling.
        }
      }
      if (chunk.type === 'TOOL_CALL_RESULT') calls.delete(chunk.toolCallId);
      if (
        chunk.type === 'RUN_FINISHED' &&
        chunk.finishReason === 'stop' &&
        !failed &&
        calls.size > 0 &&
        [...calls.values()].every((call) => call.complete)
      ) {
        yield { ...chunk, finishReason: 'tool_calls' };
      } else yield chunk;
    }
  };
  return adapter;
}
