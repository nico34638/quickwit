---
title: Distributed Tracing with Quickwit
sidebar_label: Overview
sidebar_position: 1
---

Distributed Tracing is a process that tracks your application requests flowing through your different services: frontend, backend, databases and more. It's a powerful tool to understand how your application works and to debug performance issues.

Quickwit is a cloud-native engine to index and search unstructured data which makes it a perfect fit for a traces backend.

Moreover, Quickwit supports natively the [OpenTelemetry gRPC and HTTP (protobuf only) protocol](https://opentelemetry.io/docs/reference/specification/protocol/otlp/) and the [Jaeger gRPC APIs](https://www.jaegertracing.io/) (both v1 SpanReaderPlugin and v2 TraceReader). **This means that you can use Quickwit to store your traces and to query them with Jaeger UI**.

![Quickwit Distributed Tracing](../assets/images/distributed-tracing-overview-light.png#gh-light-mode-only)![Quickwit Distributed Tracing](../assets/images/distributed-tracing-overview-dark.png#gh-dark-mode-only)

## Plug Quickwit to Jaeger

Quickwit implements gRPC services compatible with Jaeger UI. All you need is to configure Jaeger with a (span) storage type `grpc`[^1] and you will be able to visualize your traces in Jaeger that are stored in any Quickwit's indexes matching the pattern `otel-traces-v0_*`.

### Jaeger API Versions

Quickwit provides both Jaeger v1 and v2 APIs on the same gRPC endpoint (port 7281 by default):

- **Jaeger v1 (SpanReaderPlugin)**: Legacy API that returns traces in Jaeger's native format
- **Jaeger v2 (TraceReader)**: Modern API that returns traces in OpenTelemetry format

**Important**: The Jaeger v1 API (SpanReaderPlugin) has been **deprecated and removed from Jaeger since version 2.6**. If you're using Jaeger 2.6 or later, you must use the v2 API. Quickwit supports both versions to maintain compatibility with older Jaeger deployments.

The main differences between the two APIs:
- **Response format**: v1 uses Jaeger's native span format, v2 uses OpenTelemetry TracesData format
- **Compatibility**: v1 works with Jaeger < 2.6, v2 is required for Jaeger >= 2.6
- **Future support**: v2 is the recommended API going forward

We made a tutorial on [how to plug Quickwit to Jaeger UI](plug-quickwit-to-jaeger.md) that will guide you through the process.

[^1]: It was `grpc-plugin` until the version 1.58 of Jaeger.

## Send traces to Quickwit

- [Using OTEL collector](send-traces/using-otel-collector.md)
- [Using python OTEL SDK](send-traces/using-otel-sdk-python.md)

