# Python Logging Library Choice

Contents:

- [Python Logging Library Choice](#python-logging-library-choice)
  - [Summary](#summary)
    - [Issue](#issue)
    - [Decision](#decision)
    - [Status](#status)
  - [Details](#details)
    - [Assumptions](#assumptions)
    - [Constraints](#constraints)
    - [Positions](#positions)
    - [Argument](#argument)
    - [Implications](#implications)
  - [Related](#related)
    - [Related decisions](#related-decisions)
    - [Related requirements](#related-requirements)
    - [Related artifacts](#related-artifacts)
    - [Related principles](#related-principles)
  - [Notes](#notes)
  - [References](#references)

## Summary

### Issue

We need to select a Python-based logging library for our applications that balances ease of configuration, structured logging support, performance, and long-term maintainability.

### Decision

We are choosing **Loguru** as the primary logging library for Python applications due to its user-friendly API, built-in support for structured and colorized output, and powerful `add()` configuration model ([BetterStack][1]).

### Status

Decided. We will proceed with Loguru for new and existing projects, while remaining open to re-evaluation as new libraries mature.

## Details

### Assumptions

* Applications require structured log output (JSON or equivalent) for downstream processing and aggregation.
* Developers prefer minimal boilerplate to start logging.
* Performance should be on-par with or better than the standard library for most use cases.
* Log rotation, retention, and compression are desirable built-in features.
* Integration with external monitoring/log management tools (e.g., centralized dashboards) is a requirement.

### Constraints

* Must be open-source and permissively licensed.
* Should not force large changes to existing logging calls in legacy codebases.
* Dependencies should be lightweight to avoid bloating our deployment packages.
* Must work seamlessly in multi-threaded and multi-process environments.

### Positions

We considered the following options:

* **Standard library `logging`**
* **Loguru**
* **Structlog**
* **Eliot**
* **Logbook**
* **Picologging**

### Argument

* **Standard `logging`**:
  Built into Python, highly extensible, and well-supported, but requires verbose setup of handlers, formatters, and filters to achieve structured output and advanced features ([BetterStack][1]).

* **Loguru**:
  Pre-configured logger with colored, semi-structured output by default; exposes a single `add()` function to manage handlers, levels, serialization, rotation, and retention. Defaults to `DEBUG` level and supports contextual binding via `bind()`. Its ease of use and rich feature set make it our top choice ([BetterStack][1], [BetterStack][1]).

* **Structlog**:
  Designed for functional, structured logging with customizable processors and rendering pipelines. Highly flexible but requires more boilerplate to configure formatters and processors compared to Loguru ([BetterStack][1]).

* **Eliot**:
  Provides action-oriented JSON logs with a decorator-based API. Lacks native log-level semantics, which may complicate integration with tools expecting standard levels like INFO or ERROR ([BetterStack][1]).

* **Logbook**:
  Offers an alternative handler model and adds a NOTICE level, but does not support structured logging out of the box, necessitating custom handlers for JSON output ([BetterStack][1]).

* **Picologging**:
  Drop-in replacement for `logging` offering significant performance improvements in early-alpha, but its immature state makes it unsuitable for production at this time ([BetterStack][1]).

### Implications

* Developers will adopt Loguru’s API (e.g., `logger.info`, `logger.add`) and may require a short ramp-up period.
* Logging configuration (rotation, retention, formatting) will be centralized via Loguru’s `add()` calls in application bootstrap code.
* Existing code using the standard `logging` module can be migrated gradually by replacing imports and adjusting configuration.
* Downstream systems (e.g., log aggregators) will receive consistent, structured JSON by default, simplifying parsing and analysis.
* We gain built-in file rotation, compression, and contextual binding without additional dependencies.

## Related

### Related decisions

* **Centralized log aggregation**: choice of log management platform (e.g., ELK, Better Stack)
* **Application monitoring**: integration of log-based metrics into monitoring dashboards

### Related requirements

* Support for JSON-serialized logs
* Multi-process and multi-thread safety
* Configurable retention and compression policies

### Related artifacts

* Loguru configuration snippet (e.g., `logger.add("app.log", rotation="10 MB", retention="7 days", serialize=True)`)
* Migration guide from `logging` to Loguru

### Related principles

* **Simplicity:** minimize boilerplate and cognitive load for developers
* **Observability:** favor libraries that output structured logs by default
* **Performance:** ensure logging overhead remains low even under high throughput

## Notes

* Monitor Loguru’s roadmap for enhancements (e.g., additional sinks, integrations).
* Periodically review emerging libraries as they mature.
* Ensure all teams standardize on a common bootstrap module for logger configuration.

## References

1. https://betterstack.com/community/guides/logging/best-python-logging-libraries/ "Logging in Python: A Comparison of the Top 6 Libraries | Better Stack Community"
