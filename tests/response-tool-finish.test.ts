import { afterEach, expect, it, vi } from 'vitest';
import { chat, toolDefinition, type AdapterYieldChunk } from '@tanstack/ai';
import { openaiCompatibleText } from '@tanstack/ai-openai/compatible';
import { z } from 'zod';
import { restoreResponseToolFinish } from '../src/server/response-tool-finish.js';

afterEach(() => vi.restoreAllMocks());

it.each([
  'length',
  'content_filter',
  'error',
  'incomplete',
  'invalid',
  'result',
  'text',
])('does not promote a %s stream to tool execution', async (kind) => {
  const adapter = openaiCompatibleText('fixture', {
    apiKey: 'fixture',
    baseURL: 'https://unused.invalid/v1',
    api: 'responses',
  });
  const events: Record<string, unknown>[] =
    kind === 'text'
      ? []
      : [
          { type: 'TOOL_CALL_START', toolCallId: 'call', toolName: 'read' },
          {
            type: 'TOOL_CALL_ARGS',
            toolCallId: 'call',
            delta: kind === 'invalid' ? '{' : '{}',
          },
          ...(kind === 'incomplete'
            ? []
            : [{ type: 'TOOL_CALL_END', toolCallId: 'call' }]),
          ...(kind === 'error'
            ? [{ type: 'RUN_ERROR', message: 'failed' }]
            : []),
          ...(kind === 'result'
            ? [{ type: 'TOOL_CALL_RESULT', toolCallId: 'call', content: '{}' }]
            : []),
        ];
  const reason = ['length', 'content_filter'].includes(kind) ? kind : 'stop';
  events.push({ type: 'RUN_FINISHED', finishReason: reason });
  adapter.chatStream = async function* () {
    yield* events as unknown as AdapterYieldChunk[];
  };
  restoreResponseToolFinish(adapter);
  const execute = vi.fn();
  const chunks = [];
  // This fake stream does not consume the engine's internal logger.
  const options = {
    model: 'fixture',
    messages: [],
    tools: [
      { name: 'read', description: 'Read', inputSchema: z.object({}), execute },
    ],
  } as unknown as Parameters<typeof adapter.chatStream>[0];
  for await (const chunk of adapter.chatStream(options)) chunks.push(chunk);
  expect(chunks.at(-1)).toMatchObject({ finishReason: reason });
  expect(execute).not.toHaveBeenCalled();
});

function response(events: Record<string, unknown>[]) {
  return new Response(
    events
      .map(
        (event) => `event: ${event.type}\ndata: ${JSON.stringify(event)}\n\n`,
      )
      .join(''),
    { headers: { 'Content-Type': 'text/event-stream' } },
  );
}

function toolResponse() {
  const item = {
    type: 'function_call',
    id: 'fc_test',
    call_id: 'call_test',
    name: 'computer_read',
    arguments: '{}',
  };
  return response([
    {
      type: 'response.created',
      response: { id: 'response_test', model: 'fixture' },
    },
    {
      type: 'response.output_item.added',
      output_index: 0,
      item: { ...item, arguments: '' },
    },
    {
      type: 'response.function_call_arguments.delta',
      item_id: item.id,
      delta: '{}',
    },
    {
      type: 'response.function_call_arguments.done',
      item_id: item.id,
      arguments: '{}',
    },
    { type: 'response.output_item.done', output_index: 0, item },
    // The subscription gateway streams the call, but omits it here.
    {
      type: 'response.completed',
      response: { id: 'response_test', model: 'fixture', output: [] },
    },
  ]);
}

it('executes a fully streamed server call even when terminal response.output omits it', async () => {
  vi.spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(toolResponse())
    .mockResolvedValueOnce(
      response([
        {
          type: 'response.created',
          response: { id: 'response_final', model: 'fixture' },
        },
        {
          type: 'response.completed',
          response: { id: 'response_final', model: 'fixture', output: [] },
        },
      ]),
    );
  const execute = vi.fn(() => ({ title: 'Nike' }));
  const adapter = restoreResponseToolFinish(
    openaiCompatibleText('fixture', {
      apiKey: 'fixture',
      baseURL: 'https://unused.invalid/v1',
      api: 'responses',
    }),
  );
  const tools = [
    toolDefinition({
      name: 'computer_read',
      description: 'Read page',
      inputSchema: z.object({}).strict(),
    }).server(execute),
  ];
  const events = [];
  for await (const event of chat({
    adapter,
    tools,
    messages: [{ role: 'user', content: 'Read page' }],
  }))
    events.push(event);
  expect(execute).toHaveBeenCalledTimes(1);
  expect(events).toEqual(
    expect.arrayContaining([
      expect.objectContaining({
        type: 'TOOL_CALL_RESULT',
        toolCallId: 'call_test',
      }),
    ]),
  );
});
