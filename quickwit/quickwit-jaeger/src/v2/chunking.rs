// Copyright 2021-Present Datadog, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Splits the OTLP `TracesData` messages served by the Jaeger v2 API into chunks that fit
//! within the maximum gRPC message size.

use std::mem;

use prost::Message;
use quickwit_proto::opentelemetry::proto::trace::v1::{ResourceSpans, ScopeSpans, TracesData};

/// Maximum number of spans in a single chunk.
const MAX_CHUNK_NUM_SPANS: usize = 1_000;

/// 4 MiB, the default maximum size of gRPC messages, minus some headroom.
///
/// The headroom absorbs the two places where we knowingly under-account:
/// - the length delimiter of a resource or scope envelope grows as spans are appended to it,
///   whereas [`embedded_len`] measures it once, while the envelope is still empty;
/// - when a chunk is flushed on the first span of a new scope, the resource envelope was left
///   out of the size check because it was still open in the chunk we just sent, so the new
///   chunk may exceed the limit by the size of that envelope.
///
/// Both slacks are a handful of bytes per envelope, which holds as long as a resource carries
/// less than a few kilobytes of attributes.
const MAX_CHUNK_NUM_BYTES: usize = 4 * 1024 * 1024 - 10 * 1024;

/// Splits `traces_data` into chunks small enough to be sent over gRPC.
///
/// The Jaeger v2 `TraceReader` API mandates that:
/// - a single chunk MUST NOT carry spans from more than one trace,
/// - a large trace MAY be split across multiple *consecutive* chunks,
/// - a chunk MUST NOT be empty.
///
/// The first requirement is a hidden contract of this function: the caller is responsible for
/// passing spans that all belong to the same trace. The last two are guaranteed here.
///
/// Resource and scope envelopes are repeated in every chunk carrying one of their spans, which
/// is how OTLP expresses a batch spread over several messages.
///
/// A span that does not fit in a chunk on its own is still emitted alone, in an oversized chunk:
/// letting the transport report the failure is better than silently truncating a trace.
pub(super) fn split_traces_data(traces_data: TracesData) -> Vec<TracesData> {
    let mut chunks: Vec<TracesData> = Vec::new();
    let mut chunk_resource_spans: Vec<ResourceSpans> = Vec::new();
    let mut chunk_num_spans: usize = 0;
    let mut chunk_num_bytes: usize = 0;

    for resource_spans in traces_data.resource_spans {
        let resource = resource_spans.resource;
        let resource_schema_url = resource_spans.schema_url;
        let resource_envelope_num_bytes = embedded_len(&ResourceSpans {
            resource: resource.clone(),
            scope_spans: Vec::new(),
            schema_url: resource_schema_url.clone(),
        });
        // Whether the chunk being built already carries this resource's envelope.
        let mut is_resource_open = false;

        for scope_spans in resource_spans.scope_spans {
            let scope = scope_spans.scope;
            let scope_schema_url = scope_spans.schema_url;
            let scope_envelope_num_bytes = embedded_len(&ScopeSpans {
                scope: scope.clone(),
                spans: Vec::new(),
                schema_url: scope_schema_url.clone(),
            });
            // Whether the chunk being built already carries this scope's envelope.
            let mut is_scope_open = false;

            for span in scope_spans.spans {
                let span_num_bytes = embedded_len(&span);
                let mut envelope_num_bytes = 0;

                if !is_resource_open {
                    envelope_num_bytes += resource_envelope_num_bytes;
                }
                if !is_scope_open {
                    envelope_num_bytes += scope_envelope_num_bytes;
                }
                let is_chunk_full = chunk_num_spans >= MAX_CHUNK_NUM_SPANS
                    || chunk_num_bytes + envelope_num_bytes + span_num_bytes > MAX_CHUNK_NUM_BYTES;

                if is_chunk_full && chunk_num_spans > 0 {
                    chunks.push(TracesData {
                        resource_spans: mem::take(&mut chunk_resource_spans),
                    });
                    chunk_num_spans = 0;
                    chunk_num_bytes = 0;
                    is_resource_open = false;
                    is_scope_open = false;
                }
                if !is_resource_open {
                    chunk_resource_spans.push(ResourceSpans {
                        resource: resource.clone(),
                        scope_spans: Vec::new(),
                        schema_url: resource_schema_url.clone(),
                    });
                    chunk_num_bytes += resource_envelope_num_bytes;
                    is_resource_open = true;
                }
                let open_resource_spans = chunk_resource_spans
                    .last_mut()
                    .expect("the resource envelope should be open");

                if !is_scope_open {
                    open_resource_spans.scope_spans.push(ScopeSpans {
                        scope: scope.clone(),
                        spans: Vec::new(),
                        schema_url: scope_schema_url.clone(),
                    });
                    chunk_num_bytes += scope_envelope_num_bytes;
                    is_scope_open = true;
                }
                open_resource_spans
                    .scope_spans
                    .last_mut()
                    .expect("the scope envelope should be open")
                    .spans
                    .push(span);
                chunk_num_bytes += span_num_bytes;
                chunk_num_spans += 1;
            }
        }
    }
    if chunk_num_spans > 0 {
        chunks.push(TracesData {
            resource_spans: chunk_resource_spans,
        });
    }
    chunks
}

/// Returns the number of spans carried by `traces_data`.
pub(super) fn num_spans(traces_data: &TracesData) -> usize {
    traces_data
        .resource_spans
        .iter()
        .flat_map(|resource_spans| &resource_spans.scope_spans)
        .map(|scope_spans| scope_spans.spans.len())
        .sum()
}

/// Returns the number of bytes a message takes once embedded in its parent: the field tag, the
/// length delimiter, and the message itself.
///
/// All the messages nested here are identified by a field number small enough to fit its tag on
/// a single byte.
fn embedded_len(message: &impl Message) -> usize {
    let num_bytes = message.encoded_len();
    1 + prost::length_delimiter_len(num_bytes) + num_bytes
}

#[cfg(test)]
mod tests {
    use quickwit_proto::opentelemetry::proto::common::v1::any_value::Value as OtelValue;
    use quickwit_proto::opentelemetry::proto::common::v1::{
        AnyValue as OtelAnyValue, InstrumentationScope, KeyValue as OtelKeyValue,
    };
    use quickwit_proto::opentelemetry::proto::resource::v1::Resource as OtelResource;
    use quickwit_proto::opentelemetry::proto::trace::v1::Span as OtelSpan;

    use super::*;

    fn span_for_test(span_id: u8, num_padding_bytes: usize) -> OtelSpan {
        OtelSpan {
            trace_id: vec![1; 16],
            span_id: vec![span_id; 8],
            name: "span".to_string(),
            attributes: vec![OtelKeyValue {
                key: "padding".to_string(),
                value: Some(OtelAnyValue {
                    value: Some(OtelValue::StringValue("x".repeat(num_padding_bytes))),
                }),
            }],
            ..Default::default()
        }
    }

    fn resource_spans_for_test(service_name: &str, spans: Vec<OtelSpan>) -> ResourceSpans {
        ResourceSpans {
            resource: Some(OtelResource {
                attributes: vec![OtelKeyValue {
                    key: "service.name".to_string(),
                    value: Some(OtelAnyValue {
                        value: Some(OtelValue::StringValue(service_name.to_string())),
                    }),
                }],
                dropped_attributes_count: 0,
            }),
            scope_spans: vec![ScopeSpans {
                scope: Some(InstrumentationScope {
                    name: "scope".to_string(),
                    ..Default::default()
                }),
                spans,
                schema_url: String::new(),
            }],
            schema_url: String::new(),
        }
    }

    fn collect_span_ids(chunks: &[TracesData]) -> Vec<Vec<u8>> {
        chunks
            .iter()
            .flat_map(|chunk| &chunk.resource_spans)
            .flat_map(|resource_spans| &resource_spans.scope_spans)
            .flat_map(|scope_spans| &scope_spans.spans)
            .map(|span| span.span_id.clone())
            .collect()
    }

    #[test]
    fn test_split_traces_data_empty() {
        assert!(split_traces_data(TracesData::default()).is_empty());
    }

    #[test]
    fn test_split_traces_data_never_yields_an_empty_chunk() {
        // A resource carrying no span at all must not produce a chunk.
        let traces_data = TracesData {
            resource_spans: vec![resource_spans_for_test("quickwit", Vec::new())],
        };
        assert!(split_traces_data(traces_data).is_empty());
    }

    #[test]
    fn test_split_traces_data_single_chunk() {
        let traces_data = TracesData {
            resource_spans: vec![resource_spans_for_test(
                "quickwit",
                vec![span_for_test(1, 0), span_for_test(2, 0)],
            )],
        };
        let chunks = split_traces_data(traces_data);
        assert_eq!(chunks.len(), 1);
        assert_eq!(num_spans(&chunks[0]), 2);
        assert_eq!(collect_span_ids(&chunks), vec![vec![1; 8], vec![2; 8]]);
    }

    #[test]
    fn test_split_traces_data_splits_on_num_spans() {
        let spans = (0..MAX_CHUNK_NUM_SPANS + 1)
            .map(|idx| span_for_test(idx as u8, 0))
            .collect();
        let traces_data = TracesData {
            resource_spans: vec![resource_spans_for_test("quickwit", spans)],
        };
        let chunks = split_traces_data(traces_data);

        assert_eq!(chunks.len(), 2);
        assert_eq!(num_spans(&chunks[0]), MAX_CHUNK_NUM_SPANS);
        assert_eq!(num_spans(&chunks[1]), 1);
    }

    #[test]
    fn test_split_traces_data_splits_on_num_bytes() {
        // Six spans of ~1 MiB each: they cannot fit in a single 4 MiB chunk.
        let num_padding_bytes = 1024 * 1024;
        let spans = (1..=6)
            .map(|span_id| span_for_test(span_id, num_padding_bytes))
            .collect();
        let traces_data = TracesData {
            resource_spans: vec![resource_spans_for_test("quickwit", spans)],
        };
        let chunks = split_traces_data(traces_data);

        assert!(chunks.len() > 1);

        for chunk in &chunks {
            assert!(num_spans(chunk) > 0);
            assert!(chunk.encoded_len() <= MAX_CHUNK_NUM_BYTES);
        }
        // No span is lost nor reordered.
        let expected_span_ids: Vec<Vec<u8>> = (1..=6).map(|span_id| vec![span_id; 8]).collect();
        assert_eq!(collect_span_ids(&chunks), expected_span_ids);
    }

    #[test]
    fn test_split_traces_data_repeats_envelopes_across_chunks() {
        let spans = (0..MAX_CHUNK_NUM_SPANS + 1)
            .map(|idx| span_for_test(idx as u8, 0))
            .collect();
        let traces_data = TracesData {
            resource_spans: vec![resource_spans_for_test("quickwit", spans)],
        };
        let chunks = split_traces_data(traces_data);

        for chunk in &chunks {
            assert_eq!(chunk.resource_spans.len(), 1);
            let resource_spans = &chunk.resource_spans[0];
            assert_eq!(resource_spans.scope_spans.len(), 1);
            assert_eq!(
                resource_spans.resource.as_ref().unwrap().attributes[0].key,
                "service.name"
            );
            assert_eq!(
                resource_spans.scope_spans[0].scope.as_ref().unwrap().name,
                "scope"
            );
        }
    }

    #[test]
    fn test_split_traces_data_preserves_multiple_resources_in_one_chunk() {
        let traces_data = TracesData {
            resource_spans: vec![
                resource_spans_for_test("quickwit-search", vec![span_for_test(1, 0)]),
                resource_spans_for_test("quickwit-indexing", vec![span_for_test(2, 0)]),
            ],
        };
        let chunks = split_traces_data(traces_data);

        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].resource_spans.len(), 2);
        assert_eq!(num_spans(&chunks[0]), 2);
    }

    #[test]
    fn test_split_traces_data_emits_oversized_span_alone() {
        let num_padding_bytes = MAX_CHUNK_NUM_BYTES + 1;
        let traces_data = TracesData {
            resource_spans: vec![resource_spans_for_test(
                "quickwit",
                vec![span_for_test(1, 0), span_for_test(2, num_padding_bytes)],
            )],
        };
        let chunks = split_traces_data(traces_data);

        assert_eq!(chunks.len(), 2);
        assert_eq!(num_spans(&chunks[0]), 1);
        assert_eq!(num_spans(&chunks[1]), 1);
        assert!(chunks[1].encoded_len() > MAX_CHUNK_NUM_BYTES);
        assert_eq!(collect_span_ids(&chunks), vec![vec![1; 8], vec![2; 8]]);
    }
}
